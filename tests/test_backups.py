import json
import os
import stat
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
