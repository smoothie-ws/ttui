import json
import os
import stat
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from zipfile import ZipFile

import backups
import backend as b


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
