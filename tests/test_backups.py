import json
import hashlib
import os
import stat
import tarfile
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import call, patch
from zipfile import ZipFile

from werkzeug.security import generate_password_hash
import tomlkit

import backups
import backend as b
from routing import DEFAULT_ROUTING


class BackupsTest(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        root = Path(stack.enter_context(TemporaryDirectory()))
        self.state, self.config = root / "state", root / "config"
        for path in (self.state, self.config, self.state / "geo"):
            path.mkdir()
        stack.enter_context(patch.multiple(b, STATE=self.state, CONFIG=self.config,
                                            VPN=self.config / "vpn.toml", HOSTS=self.config / "hosts.toml",
                                            LAUNCH=self.state / "endpoint.json", ROUTING=self.state / "routing.json",
                                            GEO=self.state / "geo"))

    def test_selected_components_snapshot_and_verify(self):
        (self.state / "panel.json").write_bytes(b'{"secret":"panel-secret"}')
        b.VPN.write_text('credentials_file = "access.toml"\nrules_file = "filters.toml"\n', encoding="utf-8")
        (self.config / "access.toml").write_bytes(b"credential")
        (self.config / "filters.toml").write_bytes(b"filter")
        (b.GEO / "geosite.dat").write_bytes(b"geodata")
        name = backups.create(["clients", "geo"], "0.1.0")
        backups.verify(name)
        path = backups.archive_path(name)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with ZipFile(path) as archive:
            self.assertEqual(set(archive.namelist()), {"config/access.toml", "state/geo/geosite.dat", "manifest.json"})
            self.assertEqual(archive.read("config/access.toml"), b"credential")
        history = backups.history()
        self.assertEqual(history[0][0], name)
        self.assertEqual(history[0][1]["components"], ["clients", "geo"])

    def test_backup_and_restore_custom_geofile(self):
        geo = b.GEO / "custom-sites.dat"
        geo.write_bytes(b"original geodata")
        archive = backups.create(["geo"], "0.1.0")
        with ZipFile(backups.archive_path(archive)) as snapshot:
            self.assertEqual(snapshot.read("state/geo/custom-sites.dat"), b"original geodata")
        geo.write_bytes(b"modified geodata")
        with patch.object(b, "service_state", return_value="inactive"):
            backups.restore(archive, {})
        self.assertEqual(geo.read_bytes(), b"original geodata")

    def test_endpoint_backup_contains_certbot_configuration(self):
        b.VPN.write_text('listen_address = "127.0.0.1:443"\n', encoding="utf-8")
        directory = self.state / "acme" / "config" / "renewal"
        directory.mkdir(parents=True)
        (directory / "vpn.example.conf").write_text("renewal configuration", encoding="utf-8")
        name = backups.create(["endpoint"], "0.1.0")
        backups.verify(name)
        with ZipFile(backups.archive_path(name)) as archive:
            manifest = json.loads(archive.read(backups.MANIFEST))
            self.assertTrue(manifest["certbot_manual_restore"])
            with tarfile.open(fileobj=BytesIO(archive.read("state/certbot-config.tar.gz")), mode="r:gz") as config:
                self.assertEqual(config.extractfile("config/renewal/vpn.example.conf").read(), b"renewal configuration")
        with backups.archive_path(name).open("rb") as source:
            imported = backups.import_archive(source)
        backups.verify(imported)
        self.assertTrue(dict(backups.history())[imported]["certbot_manual_restore"])

    def test_panel_only_backup_does_not_include_certbot_secrets(self):
        (self.state / "panel.json").write_text("{}", encoding="utf-8")
        directory = self.state / "acme" / "config"
        directory.mkdir(parents=True)
        (directory / "secret").write_text("private", encoding="utf-8")
        name = backups.create(["panel"], "0.1.0")
        with ZipFile(backups.archive_path(name)) as archive:
            self.assertNotIn("state/certbot-config.tar.gz", archive.namelist())
            self.assertNotIn("certbot_manual_restore", json.loads(archive.read(backups.MANIFEST)))

    def test_certbot_restore_and_rollback(self):
        config = self.state / "acme" / "config"
        config.mkdir(parents=True)
        (config / "old").write_text("old", encoding="utf-8")
        source = self.state / "source"
        source.mkdir()
        (source / "new").write_text("new", encoding="utf-8")
        archive = self.state / "certbot.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            output.add(source, arcname="config")
        with self.assertRaisesRegex(RuntimeError, "failed"):
            with backups.restore_certbot(archive):
                self.assertEqual((config / "new").read_text(encoding="utf-8"), "new")
                raise RuntimeError("failed")
        self.assertEqual((config / "old").read_text(encoding="utf-8"), "old")
        with backups.restore_certbot(archive):
            self.assertEqual((config / "new").read_text(encoding="utf-8"), "new")
        self.assertFalse((config / "old").exists())

    def test_failed_certbot_rollback_keeps_previous_configuration_and_reports_its_path(self):
        config = self.state / "acme" / "config"
        config.mkdir(parents=True)
        (config / "old").write_text("old", encoding="utf-8")
        source = self.state / "source"
        source.mkdir()
        (source / "new").write_text("new", encoding="utf-8")
        archive = self.state / "certbot.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            output.add(source, arcname="config")
        original_rename = Path.rename

        def fail_recovery(path, target):
            if path.name == "previous":
                raise PermissionError("rename denied")
            return original_rename(path, target)

        with patch.object(Path, "rename", fail_recovery):
            with self.assertRaisesRegex(RuntimeError, "Certbot recovery failed.*rename denied") as failure:
                with backups.restore_certbot(archive) as rollback:
                    with self.assertRaises(PermissionError):
                        rollback()
                    raise RuntimeError("service failed")
        previous = next((self.state / "acme").glob(".restore-*/previous"))
        self.assertIn(str(previous), str(failure.exception))
        self.assertEqual((previous / "old").read_text(encoding="utf-8"), "old")

    def test_certbot_files_are_not_reported_as_missing_external_files(self):
        b.VPN.write_text('listen_address = "127.0.0.1:443"\n', encoding="utf-8")
        directory = self.state / "acme" / "config" / "archive" / "vpn.example"
        directory.mkdir(parents=True)
        cert, key = directory / "cert.pem", directory / "key.pem"
        cert.write_text("certificate", encoding="utf-8")
        key.write_text("key", encoding="utf-8")
        external = self.state.parent / "other.pem"
        external.write_text("external", encoding="utf-8")
        b.HOSTS.write_text(tomlkit.dumps({"main_hosts": [{"hostname": "vpn.example",
                           "cert_chain_path": str(cert), "private_key_path": str(key)}],
                           "ping_hosts": [{"hostname": "ping.example", "cert_chain_path": str(external)}]}),
                           encoding="utf-8")
        name = backups.create(["endpoint"], "0.1.0")
        with ZipFile(backups.archive_path(name)) as archive:
            manifest = json.loads(archive.read(backups.MANIFEST))
        self.assertTrue(manifest["certbot_manual_restore"])
        self.assertEqual(manifest["external_tls_files"], [str(external.resolve())])

    def test_failed_certbot_snapshot_keeps_previous_backup(self):
        b.VPN.write_text('listen_address = "127.0.0.1:443"\n', encoding="utf-8")
        previous = backups.create(["endpoint"], "0.1.0")
        directory = self.state / "acme" / "config"
        directory.mkdir(parents=True)
        (directory / "large-file").write_bytes(b"x" * 2048)
        with patch.object(backups, "MAX_BYTES", 1024):
            with self.assertRaisesRegex(ValueError, "Certbot configuration exceeds"):
                backups.create(["endpoint"], "0.1.0")
        self.assertEqual([path.name for path in backups.location().iterdir()], [previous])
        backups.verify(previous)

    def test_certbot_walk_failure_does_not_publish_backup(self):
        b.VPN.write_text('listen_address = "127.0.0.1:443"\n', encoding="utf-8")
        (self.state / "acme" / "config").mkdir(parents=True)

        def fail_walk(path, *, followlinks, onerror):
            onerror(PermissionError("unreadable directory"))
            return iter(())

        with patch.object(backups.os, "walk", side_effect=fail_walk):
            with self.assertRaisesRegex(PermissionError, "unreadable directory"):
                backups.create(["endpoint"], "0.1.0")
        self.assertEqual(list(backups.location().iterdir()), [])

    def test_certbot_configuration_must_be_directory(self):
        b.VPN.write_text('listen_address = "127.0.0.1:443"\n', encoding="utf-8")
        (self.state / "acme").mkdir()
        (self.state / "acme" / "config").write_text("invalid", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "local directory"):
            backups.create(["endpoint"], "0.1.0")
        self.assertEqual(list(backups.location().iterdir()), [])

    def test_import_rejects_modified_certbot_payload(self):
        b.VPN.write_text('listen_address = "127.0.0.1:443"\n', encoding="utf-8")
        directory = self.state / "acme" / "config"
        directory.mkdir(parents=True)
        (directory / "renewal.conf").write_text("original", encoding="utf-8")
        original = backups.archive_path(backups.create(["endpoint"], "0.1.0"))
        modified = BytesIO()
        with ZipFile(original) as source, ZipFile(modified, "w") as target:
            for name in source.namelist():
                payload = source.read(name)
                if name == "state/certbot-config.tar.gz":
                    payload += b"tampered"
                target.writestr(name, payload)
        modified.seek(0)
        with self.assertRaisesRegex(ValueError, "checksums"):
            backups.import_archive(modified)

    def test_certbot_archive_rejects_escaping_link(self):
        path = self.state / "malicious.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            entry = tarfile.TarInfo("config/live/cert.pem")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "../../../outside"
            archive.addfile(entry)
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            backups.validate_certbot_archive(path)

    def test_certbot_archive_rejects_indirect_link_escape_and_cycles(self):
        path = self.state / "links.tar.gz"
        for links in ((('config/x/a', '../z'), ('config/x/b', 'a/../../outside')),
                      (('config/a', 'b'), ('config/b', 'a'))):
            with self.subTest(links=links), tarfile.open(path, "w:gz") as archive:
                root = tarfile.TarInfo("config")
                root.type = tarfile.DIRTYPE
                archive.addfile(root)
                for name, target in links:
                    link = tarfile.TarInfo(name)
                    link.type = tarfile.SYMTYPE
                    link.linkname = target
                    archive.addfile(link)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                backups.validate_certbot_archive(path)

    def test_import_rejects_certbot_link_even_with_matching_checksum(self):
        nested = BytesIO()
        with tarfile.open(fileobj=nested, mode="w:gz") as archive:
            entry = tarfile.TarInfo("config/live/cert.pem")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "../../../outside"
            archive.addfile(entry)
        payload = nested.getvalue()
        member = "state/certbot-config.tar.gz"
        manifest = {"format": 1, "version": "0.1.0", "created": "", "components": ["endpoint"],
                    "files": {member: {"size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}},
                    "certbot_manual_restore": True}
        source = BytesIO()
        with ZipFile(source, "w") as archive:
            archive.writestr(backups.MANIFEST, json.dumps(manifest))
            archive.writestr(member, payload)
        source.seek(0)
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            backups.import_archive(source)
        self.assertEqual(list(backups.location().iterdir()), [])

    def test_certbot_archive_accepts_relative_certificate_link(self):
        path = self.state / "certbot.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            root = tarfile.TarInfo("config")
            root.type = tarfile.DIRTYPE
            archive.addfile(root)
            entry = tarfile.TarInfo("config/live/vpn.example/cert.pem")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "../../archive/vpn.example/cert1.pem"
            archive.addfile(entry)
        backups.validate_certbot_archive(path)

    def test_certbot_archive_rejects_duplicate_entries(self):
        path = self.state / "duplicate.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for _ in range(2):
                archive.addfile(tarfile.TarInfo("config/renewal/example.conf"))
        with self.assertRaisesRegex(ValueError, "Invalid Certbot archive entry"):
            backups.validate_certbot_archive(path)

    def test_certbot_archive_requires_directory_root(self):
        path = self.state / "root-file.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            archive.addfile(tarfile.TarInfo("config"))
        with self.assertRaisesRegex(ValueError, "Invalid Certbot archive entry"):
            backups.validate_certbot_archive(path)

    def test_certbot_archive_rejects_files_beneath_links(self):
        path = self.state / "nested.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            child = tarfile.TarInfo("config/live/link/file")
            archive.addfile(child)
            link = tarfile.TarInfo("config/live/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "../archive"
            archive.addfile(link)
        with self.assertRaisesRegex(ValueError, "nested under symbolic links"):
            backups.validate_certbot_archive(path)

    def test_certbot_archive_rejects_truncated_data(self):
        path = self.state / "truncated.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            archive.addfile(tarfile.TarInfo("config/renewal/example.conf"))
        data = path.read_bytes()
        path.write_bytes(data[:len(data) // 2])
        with self.assertRaisesRegex(ValueError, "damaged"):
            backups.validate_certbot_archive(path)

    def test_certbot_archive_rejects_expanded_data_over_limit(self):
        path = self.state / "oversized.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            root = tarfile.TarInfo("config")
            root.type = tarfile.DIRTYPE
            archive.addfile(root)
            entry = tarfile.TarInfo("config/large")
            entry.size = 1025
            archive.addfile(entry, BytesIO(b"x" * 1025))
        with patch.object(backups, "MAX_BYTES", 1024):
            with self.assertRaisesRegex(ValueError, "exceeds the supported size"):
                backups.validate_certbot_archive(path)

    @unittest.skipUnless(os.name == "posix", "Symbolic links require POSIX")
    def test_certbot_snapshot_preserves_internal_links_and_rejects_external_links(self):
        b.VPN.write_text('listen_address = "127.0.0.1:443"\n', encoding="utf-8")
        root = self.state / "acme" / "config"
        archive = root / "archive" / "vpn.example"
        live = root / "live" / "vpn.example"
        archive.mkdir(parents=True)
        live.mkdir(parents=True)
        (archive / "cert1.pem").write_text("certificate", encoding="utf-8")
        (live / "cert.pem").symlink_to("../../archive/vpn.example/cert1.pem")
        name = backups.create(["endpoint"], "0.1.0")
        with ZipFile(backups.archive_path(name)) as snapshot:
            with tarfile.open(fileobj=BytesIO(snapshot.read("state/certbot-config.tar.gz")), mode="r:gz") as config:
                link = config.getmember("config/live/vpn.example/cert.pem")
                self.assertTrue(link.issym())
                self.assertEqual(link.linkname, "../../archive/vpn.example/cert1.pem")
        (live / "outside").symlink_to("../../../../../outside")
        with self.assertRaisesRegex(ValueError, "outside its directory"):
            backups.create(["endpoint"], "0.1.0")

    def test_endpoint_snapshot_includes_only_managed_tls_files(self):
        cert, external = self.config / "tls-chain.pem", self.state.parent / "outside.pem"
        cert.write_bytes(b"certificate")
        external.write_bytes(b"external key")
        b.VPN.write_text('listen_address = "127.0.0.1:443"\n', encoding="utf-8")
        b.HOSTS.write_text('[[main_hosts]]\nhostname = "vpn.example"\ncert_chain_path = "tls-chain.pem"\n'
                           f'private_key_path = "{external.as_posix()}"\n', encoding="utf-8")
        name = backups.create(["endpoint"], "0.1.0")
        backups.verify(name)
        with ZipFile(backups.archive_path(name)) as archive:
            self.assertEqual(set(archive.namelist()), {"config/vpn.toml", "config/hosts.toml", "config/tls-chain.pem",
                                                        backups.MANIFEST})
            manifest = json.loads(archive.read(backups.MANIFEST))
            self.assertEqual(manifest["external_tls_files"], [str(external.resolve())])

    def test_reject_tampered_archive_without_leaving_generated_copy(self):
        (self.state / "panel.json").write_bytes(b"{}")
        name = backups.create(["panel"], "0.1.0")
        path = backups.archive_path(name)
        with ZipFile(path) as archive:
            manifest = json.loads(archive.read(backups.MANIFEST))
        with ZipFile(path, "w") as archive:
            archive.writestr(backups.MANIFEST, json.dumps(manifest))
            archive.writestr("state/panel.json", "[]")
        with self.assertRaisesRegex(ValueError, "checksums"):
            backups.verify(name)
        with self.assertRaisesRegex(ValueError, "name"):
            backups.archive_path("../" + name)
        with patch.object(backups, "MAX_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "size"):
                backups.create(["panel"], "0.1.0")
        self.assertEqual(list(path.parent.iterdir()), [path])

    def test_import_restore_settings_preserves_signing_key_and_revokes_sessions(self):
        panel = self.state / "panel.json"
        captured = {"path": "/archived", "username": "admin", "address": "", "secure_cookie": False,
                    "secret": "old", "password_hash": generate_password_hash("original", method="pbkdf2:sha256:1000")}
        b.write_json(panel, captured)
        archive = backups.archive_path(backups.create(["panel"], "0.1.0"))
        with archive.open("rb") as source:
            imported = backups.import_archive(source)
        current = {**captured, "path": "/current", "secret": "current-key"}
        b.write_json(panel, current)
        self.assertEqual(backups.restore(imported, current), "/archived")
        restored = json.loads(b.read(panel))
        self.assertEqual(restored["secret"], "current-key")
        self.assertEqual(restored["password_hash"], captured["password_hash"])
        self.assertTrue(restored["session_epoch"])

    def test_restore_endpoint_rolls_back_files_and_restarts_original_service(self):
        credentials = self.config / "credentials.toml"
        captured = '[[client]]\nusername = "first"\npassword = "original"\n'
        current = captured.replace('"original"', '"current"')
        b.VPN.write_text('listen_address = "127.0.0.1:443"\ncredentials_file = "credentials.toml"\n', encoding="utf-8")
        b.HOSTS.write_text('[[main_hosts]]\nhostname = "test.example"\n', encoding="utf-8")
        credentials.write_text(captured, encoding="utf-8")
        archive = backups.create(["endpoint", "clients"], "0.1.0")
        credentials.write_text(current, encoding="utf-8")
        readies = []

        def readiness():
            readies.append(b.read(credentials))
            if len(readies) == 1:
                raise RuntimeError("Startup failed")

        with patch.object(b, "service_state", side_effect=lambda unit: "active" if unit == b.ENDPOINT_UNIT else "inactive"), \
                patch.object(b, "active_endpoint", side_effect=readiness), patch.object(b, "service") as service:
            with self.assertRaisesRegex(RuntimeError, "Startup failed"):
                backups.restore(archive, {})
        self.assertEqual(service.call_args_list, [call("restart", b.ENDPOINT_UNIT)] * 2)
        self.assertEqual(readies, [captured, current])
        self.assertEqual(b.read(credentials), current)
        self.assertFalse((self.state / "clients.json").exists())

    def test_restore_endpoint_restores_certbot_before_validation_and_rolls_back_before_restart(self):
        config = self.state / "acme" / "config"
        config.mkdir(parents=True)
        cert, key = config / "cert.pem", config / "key.pem"
        cert.write_text("archived certificate", encoding="utf-8")
        key.write_text("archived key", encoding="utf-8")
        b.VPN.write_text('listen_address = "127.0.0.1:443"\ncredentials_file = "credentials.toml"\n', encoding="utf-8")
        (self.config / "credentials.toml").write_text('', encoding="utf-8")
        b.HOSTS.write_text(tomlkit.dumps({"main_hosts": [{"hostname": "test.example",
                           "cert_chain_path": str(cert), "private_key_path": str(key)}]}), encoding="utf-8")
        archive = backups.create(["endpoint", "clients"], "0.1.0")
        cert.write_text("current certificate", encoding="utf-8")
        key.write_text("current key", encoding="utf-8")
        restarts = []

        def validate(certificate, private_key, host):
            self.assertEqual(host, "test.example")
            self.assertEqual(certificate.read_text(encoding="utf-8"), "archived certificate")
            self.assertEqual(private_key.read_text(encoding="utf-8"), "archived key")

        def ready():
            restarts.append(cert.read_text(encoding="utf-8"))
            if len(restarts) == 1:
                raise RuntimeError("Startup failed")

        with patch.object(backups.tls, "validate", side_effect=validate), \
                patch.object(b, "service_state", side_effect=lambda unit: "active" if unit == b.ENDPOINT_UNIT else "inactive"), \
                patch.object(b, "service"), patch.object(b, "active_endpoint", side_effect=ready):
            with self.assertRaisesRegex(RuntimeError, "Startup failed"):
                backups.restore(archive, {})
        self.assertEqual(restarts, ["archived certificate", "current certificate"])
        self.assertEqual(key.read_text(encoding="utf-8"), "current key")
        with patch.object(backups.tls, "validate", side_effect=validate), \
                patch.object(b, "service_state", return_value="inactive"), \
                patch.object(b, "service"), patch.object(b, "active_endpoint"):
            backups.restore(archive, {})
        self.assertEqual(cert.read_text(encoding="utf-8"), "archived certificate")
        self.assertEqual(key.read_text(encoding="utf-8"), "archived key")

    @unittest.skipUnless(os.name == "posix", "Certificate symlinks require POSIX")
    def test_restore_certbot_preserves_certificate_symlinks(self):
        config = self.state / "acme" / "config"
        archive_dir = config / "archive" / "test.example"
        live = config / "live" / "test.example"
        archive_dir.mkdir(parents=True)
        live.mkdir(parents=True)
        (archive_dir / "fullchain1.pem").write_text("certificate", encoding="utf-8")
        (live / "fullchain.pem").symlink_to("../../archive/test.example/fullchain1.pem")
        b.VPN.write_text('listen_address = "127.0.0.1:443"\n', encoding="utf-8")
        name = backups.create(["endpoint"], "0.1.0")
        (archive_dir / "fullchain1.pem").write_text("changed", encoding="utf-8")
        with TemporaryDirectory() as directory:
            _, staged = backups.verify_file(backups.archive_path(name), Path(directory))
            with backups.restore_certbot(staged["state/certbot-config.tar.gz"]):
                self.assertTrue((live / "fullchain.pem").is_symlink())
                self.assertEqual((live / "fullchain.pem").read_text(encoding="utf-8"), "certificate")

    def test_rejects_archive_paths_outside_configuration(self):
        source = BytesIO()
        name = "state/../panel.json"
        data = {"format": 1, "version": "0.1.0", "created": "", "components": ["panel"], "files": {name: {}}}
        with ZipFile(source, "w") as archive:
            archive.writestr(backups.MANIFEST, json.dumps(data))
            archive.writestr(name, b"{}")
        source.seek(0)
        with self.assertRaisesRegex(ValueError, "invalid file path"):
            backups.import_archive(source)
        self.assertEqual(list(backups.location().iterdir()), [])

    def test_rejects_invalid_external_tls_metadata(self):
        source = BytesIO()
        manifest = {"format": 1, "version": "0.1.0", "created": "", "components": ["panel"],
                    "files": {}, "external_tls_files": {"path": "invalid"}}
        with ZipFile(source, "w") as archive:
            archive.writestr(backups.MANIFEST, json.dumps(manifest))
        source.seek(0)
        with self.assertRaisesRegex(ValueError, "TLS metadata"):
            backups.import_archive(source)
        self.assertEqual(list(backups.location().iterdir()), [])

    def test_rejects_certbot_archive_without_endpoint_metadata(self):
        source = BytesIO()
        member = "state/certbot-config.tar.gz"
        manifest = {"format": 1, "version": "0.1.0", "created": "", "components": ["panel"],
                    "files": {member: {}}, "certbot_manual_restore": True}
        with ZipFile(source, "w") as archive:
            archive.writestr(backups.MANIFEST, json.dumps(manifest))
            archive.writestr(member, b"invalid")
        source.seek(0)
        with self.assertRaisesRegex(ValueError, "Certbot metadata"):
            backups.import_archive(source)

    def test_failed_xray_validation_preserves_old_geodata_without_restarting(self):
        b.VPN.write_text(tomlkit.dumps({"listen_address": "127.0.0.1:443", "forward_protocol": b.ROUTER_FORWARD}),
                         encoding="utf-8")
        b.write_json(b.ROUTING, {**DEFAULT_ROUTING, "enabled": True})
        geo = b.GEO / "geosite.dat"
        geo.write_bytes(b"captured geodata")
        archive = backups.create(["geo"], "0.1.0")
        geo.write_bytes(b"working geodata")

        def invalid_config(_):
            self.assertEqual(geo.read_bytes(), b"captured geodata")
            raise RuntimeError("Xray rejected geodata")

        with patch.object(b, "service_state", return_value="active"), patch.object(b, "service") as service, \
                patch.object(b, "validate_xray", side_effect=invalid_config):
            with self.assertRaisesRegex(RuntimeError, "Xray rejected geodata"):
                backups.restore(archive, {})
        service.assert_not_called()
        self.assertEqual(geo.read_bytes(), b"working geodata")

    def test_schedule_keeps_manual_and_imported_archives(self):
        (self.state / "panel.json").write_bytes(b"{}")
        manual = backups.create(["panel"], "0.1.0")
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        backups.schedule("daily", ["panel"], now)
        backups.run_scheduled("0.1.0", now)
        self.assertEqual(len(backups.history()), 1)
        backups.run_scheduled("0.1.0", now + timedelta(days=1))
        scheduled = backups.load_schedule()["last"]
        with backups.archive_path(scheduled).open("rb") as source:
            imported = backups.import_archive(source)
        with patch.object(backups, "SCHEDULED_RETENTION", 1):
            backups.run_scheduled("0.1.0", now + timedelta(days=2))
        history = dict(backups.history())
        self.assertEqual(len(history), 3)
        self.assertIn(manual, history)
        self.assertIn(imported, history)
        self.assertEqual(sum(name.endswith("-auto.zip") for name in history), 1)
