import re
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
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
            self.assertIn(b"Node readiness", page.data)
            self.assertIn(b"Needs attention", page.data)

    def test_dashboard_marks_a_node_ready_when_required_checks_pass(self):
        vpn = self.state / "vpn.toml"
        hosts = self.state / "hosts.toml"
        clients = self.state / "clients.toml"
        vpn.write_text('listen_address = "0.0.0.0:8443"\ncredentials_file = "clients.toml"\n', encoding="utf-8")
        hosts.write_text('[[main_hosts]]\nhostname = "vpn.example"\n'
                         'cert_chain_path = "cert.pem"\nprivate_key_path = "key.pem"\n', encoding="utf-8")
        clients.write_text('[[client]]\nusername = "demo"\npassword = "secret"\n', encoding="utf-8")
        config = {"path": "/ttui", "secret": "test-secret", "username": "admin", "secure_cookie": False,
                  "password_hash": generate_password_hash("correct-password", method="pbkdf2:sha256:1000")}
        status = {"expires": "2027-12-01T00:00+00:00", "days": 300, "fingerprint": "AA:BB"}
        stats = {"demo": {"sessions": 1, "inbound": 10, "outbound": 20, "ip": "192.0.2.1"}}
        with patch.object(panel, "settings", return_value=config), patch.dict(
            panel.app.config, SECRET_KEY=config["secret"]
        ), patch.object(panel.b, "CONFIG", self.state), patch.object(panel.b, "VPN", vpn), patch.object(
            panel.b, "HOSTS", hosts), patch.object(panel, "history", return_value=[]
        ), patch.object(panel.b, "service_states", side_effect=lambda units: {unit: "active" for unit in units}), \
                patch.object(panel, "client_statistics", return_value=stats), patch.object(
                    panel.tls, "certificate_status", return_value=status):
            client = panel.app.test_client()
            page = client.get("/ttui/login")
            token = re.search(rb'name="csrf" value="([^"]+)"', page.data)[1].decode()
            client.post("/ttui/login", data={"csrf": token, "username": "admin", "password": "correct-password"})
            page = client.get("/ttui/")
            self.assertIn(b'class="status online">Ready', page.data)
            self.assertIn(b"Connected client accounts", page.data)

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

    def test_quick_setup_form_uses_the_open_panel_hostname(self):
        config = {"path": "/ttui", "secret": "test-secret", "username": "admin", "secure_cookie": False,
                  "password_hash": generate_password_hash("correct-password", method="pbkdf2:sha256:1000")}
        with patch.object(panel, "settings", return_value=config), patch.dict(
            panel.app.config, SECRET_KEY=config["secret"]
        ), patch.object(panel.b, "VPN", self.state / "vpn.toml"), patch.object(
            panel.b, "HOSTS", self.state / "hosts.toml"
        ):
            client = panel.app.test_client()
            page = client.get("/ttui/login", base_url="http://panel.example.com")
            token = re.search(rb'name="csrf" value="([^"]+)"', page.data)[1].decode()
            client.post("/ttui/login", base_url="http://panel.example.com", data={
                "csrf": token, "username": "admin", "password": "correct-password",
            })
            page = client.get("/ttui/endpoint", base_url="http://panel.example.com")
            self.assertIn(b"Create node for panel.example.com:443", page.data)
            self.assertIn(b"Start TrustTunnel", page.data)
            other = panel.app.test_client()
            login = other.get("/ttui/login", base_url="http://203.0.113.5:8080")
            token = re.search(rb'name="csrf" value="([^"]+)"', login.data)[1].decode()
            other.post("/ttui/login", base_url="http://203.0.113.5:8080", data={
                "csrf": token, "username": "admin", "password": "correct-password",
            })
            page = other.get("/ttui/endpoint", base_url="http://203.0.113.5:8080")
            self.assertIn(b"Create node for 203.0.113.5:443", page.data)
            self.assertIn(b'name="public_address" value="203.0.113.5:443"', page.data)

    def test_quick_setup_works_with_dns_and_ip(self):
        with panel.app.test_request_context("/", base_url="http://panel.example.com"):
            self.assertEqual(panel.quick_setup(),
                             {"hostname": "panel.example.com", "address": "", "target": "panel.example.com:443"})
        with panel.app.test_request_context("/", base_url="http://203.0.113.5:8080"):
            self.assertEqual(panel.quick_setup(),
                             {"hostname": "vpn.local", "address": "203.0.113.5:443", "target": "203.0.113.5:443"})
        with panel.app.test_request_context("/", base_url="http://localhost"):
            self.assertIsNone(panel.quick_setup())

    def test_settings_cache_reloads_after_a_write(self):
        path = self.state / "panel.json"
        config = {"path": "/ttui", "secret": "test-secret", "username": "admin", "secure_cookie": False}
        panel.b.write_json(path, config)
        with patch.object(panel, "SETTINGS", path):
            first = panel.settings()
            self.assertIs(panel.settings(), first)
            config["username"] = "operator"
            time.sleep(0.003)
            panel.b.write_json(path, config)
            self.assertEqual(panel.settings()["username"], "operator")

    def test_static_assets_are_cacheable_but_pages_are_not(self):
        config = {"path": "/ttui", "secret": "test-secret", "username": "admin", "secure_cookie": False,
                  "password_hash": generate_password_hash("correct-password", method="pbkdf2:sha256:1000")}
        with patch.object(panel, "settings", return_value=config), patch.dict(
            panel.app.config, SECRET_KEY=config["secret"]
        ):
            client = panel.app.test_client()
            page = client.get("/ttui/login")
            asset = client.get("/ttui/static/style.css")
            self.assertEqual(page.headers["Cache-Control"], "no-store")
            self.assertEqual(asset.headers["Cache-Control"], "public, max-age=300")
            page.close()
            asset.close()

    def test_service_states_uses_one_systemctl_call(self):
        result = SimpleNamespace(stdout="active\ninactive\n", returncode=3)
        with patch.object(panel.b.subprocess, "run", return_value=result) as run:
            self.assertEqual(panel.b.service_states(["one.service", "two.service"]),
                             {"one.service": "active", "two.service": "inactive"})
            run.assert_called_once()

    def test_certificate_status_is_cached_by_file_version(self):
        certificate = self.state / "cert.pem"
        certificate.write_text("pem", encoding="utf-8")
        status = {"expires": "2026-12-01T00:00+00:00", "days": 5, "fingerprint": "AA:BB"}
        with patch.object(panel.tls, "path", return_value=certificate), patch.object(
            panel.tls, "inspect", return_value=status
        ) as inspect:
            panel.tls._status_cache.clear()
            self.assertEqual(panel.tls.certificate_status("cert.pem"), status)
            self.assertEqual(panel.tls.certificate_status("cert.pem"), status)
            self.assertEqual(inspect.call_count, 1)

    def test_routing_preserves_priority_and_default(self):
        rules = [{"domain": [r"regexp:^test\.example$"], "outboundTag": "direct"},
                 {"ip": ["geoip:private"], "outboundTag": "block"}]
        config, _ = compile_routing({**DEFAULT_ROUTING, "default": "block", "rules": rules})
        self.assertEqual(config["outbounds"][0]["tag"], "block")
        self.assertEqual([rule["outboundTag"] for rule in config["routing"]["rules"]], ["direct", "block"])
