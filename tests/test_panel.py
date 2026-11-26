import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import generate_password_hash

import app as panel
from routing import DEFAULT_ROUTING, compile_routing
from auth import LIMIT, reserve_attempt


class PanelTest(unittest.TestCase):
    def setUp(self):
        state = tempfile.TemporaryDirectory()
        self.addCleanup(state.cleanup)
        self.state = Path(state.name)
        patcher = patch.object(panel.b, "STATE", self.state)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_sign_in_limit_survives_reopening_database_and_is_per_address(self):
        database = self.state / "sign-in.sqlite3"
        for _ in range(LIMIT):
            self.assertEqual(reserve_attempt(database, "192.0.2.1", 100), 0)
        self.assertEqual(reserve_attempt(database, "192.0.2.1", 101), 59)
        self.assertEqual(reserve_attempt(database, "192.0.2.2", 101), 0)
        self.assertEqual(reserve_attempt(database, "192.0.2.1", 160), 0)

    def test_revocation_invalidates_other_signed_sessions(self):
        settings_path = self.state / "panel.json"
        config = {"path": "/ttui", "secret": "test-secret", "username": "admin", "secure_cookie": False,
                  "password_hash": generate_password_hash("correct-password", method="pbkdf2:sha256:1000")}
        panel.b.write_json(settings_path, config)
        with patch.object(panel, "SETTINGS", settings_path), patch.dict(panel.app.config, SECRET_KEY=config["secret"]):
            first, second = panel.app.test_client(), panel.app.test_client()
            for client in (first, second):
                page = client.get("/ttui/login")
                token = re.search(rb'name="csrf" value="([^"]+)"', page.data)[1].decode()
                self.assertEqual(client.post("/ttui/login", data={
                    "csrf": token, "username": "admin", "password": "correct-password",
                }).status_code, 302)
            page = first.get("/ttui/settings")
            token = re.search(rb'name="csrf" value="([^"]+)"', page.data)[1].decode()
            self.assertEqual(first.post("/ttui/sessions/revoke", data={
                "csrf": token, "current_password": "correct-password",
            }).status_code, 302)
            self.assertTrue(second.get("/ttui/settings").location.endswith("/ttui/login"))

    def test_login_and_version_at_configured_path(self):
        config = {
            "path": "/private/panel",
            "secret": "test-secret",
            "username": "admin",
            "password_hash": generate_password_hash("correct-password", method="pbkdf2:sha256:1000"),
            "secure_cookie": False,
        }
        with patch.object(panel, "settings", return_value=config) as load_settings, patch.dict(
            panel.app.config, SECRET_KEY=config["secret"]
        ):
            client = panel.app.test_client()
            self.assertEqual(client.get("/ttui/").status_code, 404)
            settings = "/private/panel/settings"
            login = "/private/panel/login"
            self.assertTrue(client.get(settings).location.endswith(login))
            data = {"username": "admin", "password": "correct-password"}
            self.assertEqual(client.post(login, data=data).status_code, 403)
            response = client.get(login)
            data["csrf"] = re.search(rb'name="csrf" value="([^"]+)"', response.data)[1].decode()
            self.assertEqual(client.post(login, data=data).status_code, 302)
            version = (panel.Path(panel.__file__).parent / "VERSION").read_bytes().strip()
            load_settings.reset_mock()
            self.assertIn(b"ttui " + version, client.get(settings).data)
            load_settings.assert_called_once()

    def test_public_https_forces_secure_cookie(self):
        config = {"path": "/ttui", "secure_cookie": False}
        with patch.object(panel, "PUBLIC_HTTPS", True), patch.object(panel, "settings", return_value=config), patch.dict(
            panel.app.config, SECRET_KEY="test-secret"
        ):
            response = panel.app.test_client().get("/ttui/login", base_url="https://panel.example")
            self.assertIn("; Secure;", response.headers["Set-Cookie"])

    def test_dashboard_shows_unconfigured_endpoint_and_recent_activity(self):
        config = {"path": "/ttui", "secret": "test-secret", "username": "admin", "secure_cookie": False,
                  "password_hash": generate_password_hash("correct-password", method="pbkdf2:sha256:1000")}
        with patch.object(panel, "settings", return_value=config), patch.dict(
            panel.app.config, SECRET_KEY=config["secret"]
        ), patch.object(panel.b, "VPN", self.state / "vpn.toml"), patch.object(
            panel.b, "HOSTS", self.state / "hosts.toml"
        ), patch.object(panel, "history", return_value=[]):
            client = panel.app.test_client()
            page = client.get("/ttui/login")
            token = re.search(rb'name="csrf" value="([^"]+)"', page.data)[1].decode()
            self.assertEqual(client.post("/ttui/login", data={
                "csrf": token, "username": "admin", "password": "correct-password",
            }).status_code, 302)
            page = client.get("/ttui/")
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"Not configured", page.data)
            self.assertIn(b"Administrator sign-in", page.data)
            self.assertIn(b"Completed", page.data)

    def test_dashboard_warns_about_certificates_expiring_soon(self):
        vpn = self.state / "vpn.toml"
        hosts = self.state / "hosts.toml"
        vpn.write_text("", encoding="utf-8")
        hosts.write_text('[[main_hosts]]\nhostname = "vpn.example"\n'
                         'cert_chain_path = "cert.pem"\nprivate_key_path = "key.pem"\n', encoding="utf-8")
        config = {"path": "/ttui", "secret": "test-secret", "username": "admin", "secure_cookie": False,
                  "password_hash": generate_password_hash("correct-password", method="pbkdf2:sha256:1000")}
        status = {"expires": "2026-12-01T00:00+00:00", "days": 5, "fingerprint": "AA:BB"}
        with patch.object(panel, "settings", return_value=config), patch.dict(
            panel.app.config, SECRET_KEY=config["secret"]
        ), patch.object(panel.b, "VPN", vpn), patch.object(panel.b, "HOSTS", hosts), patch.object(
            panel, "history", return_value=[]
        ), patch.object(panel.tls, "certificate_status", return_value=status):
            client = panel.app.test_client()
            page = client.get("/ttui/login")
            token = re.search(rb'name="csrf" value="([^"]+)"', page.data)[1].decode()
            client.post("/ttui/login", data={"csrf": token, "username": "admin", "password": "correct-password"})
            page = client.get("/ttui/")
            self.assertIn(b"vpn.example", page.data)
            self.assertIn(b"Expires in 5 days", page.data)
            self.assertIn(b"1 needs attention", page.data)

    def test_routing_preserves_priority_and_default(self):
        rules = [{"domain": [r"regexp:^test\.example$"], "outboundTag": "direct"},
                 {"ip": ["geoip:private"], "outboundTag": "block"}]
        config, _ = compile_routing({**DEFAULT_ROUTING, "default": "block", "rules": rules})
        self.assertEqual(config["outbounds"][0]["tag"], "block")
        self.assertEqual([rule["outboundTag"] for rule in config["routing"]["rules"]], ["direct", "block"])
