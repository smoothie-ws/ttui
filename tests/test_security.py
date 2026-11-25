import base64
import re
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from werkzeug.security import generate_password_hash

import app as panel
import auth
import backups


def field(page, name):
    return re.search(rb'name="' + name.encode() + rb'" value="([^"]+)"', page.data)[1].decode()


class SecurityTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        self.settings = self.state / "panel.json"
        self.config = {"path": "/ttui", "username": "admin", "address": "", "secret": "test-secret",
                       "secure_cookie": False, "password_hash": generate_password_hash("correct", method="pbkdf2:sha256:1000")}
        panel.b.write_json(self.settings, self.config)
        for patcher in (patch.object(panel.b, "STATE", self.state), patch.object(panel, "SETTINGS", self.settings),
                        patch.dict(panel.app.config, SECRET_KEY=self.config["secret"])):
            patcher.start()
            self.addCleanup(patcher.stop)

    def login(self, client, code="", address="192.0.2.1"):
        environ = {"REMOTE_ADDR": address}
        page = client.get("/ttui/login", environ_overrides=environ)
        fields = {"csrf": field(page, "csrf"), "username": "admin", "password": "correct", "code": code}
        return client.post("/ttui/login", data=fields, environ_overrides=environ)

    def test_totp_matches_rfc_vector_and_accepts_a_counter_only_once(self):
        key = b"12345678901234567890"
        self.assertEqual(auth.totp_code(key, 59 // 30, digits=8), "94287082")
        secret = base64.b32encode(key).decode()
        path = self.state / "replay.sqlite3"
        code = auth.totp_code(key, 100)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: auth.use_totp(path, secret, code, now=3000), range(8)))
        self.assertEqual(sum(results), 1)
        self.assertFalse(auth.use_totp(path, secret, code, now=3030))
        self.assertTrue(auth.use_totp(path, secret, auth.totp_code(key, 101), now=3030))

    def test_enrollment_is_session_bound_and_revokes_other_sessions(self):
        first, second = panel.app.test_client(), panel.app.test_client()
        self.assertEqual(self.login(first).status_code, 302)
        self.assertEqual(self.login(second).status_code, 302)
        path = "/ttui/mfa"
        token = field(first.get("/ttui/settings"), "csrf")
        with self.assertLogs(panel.app.logger, level="INFO") as log:
            enroll = first.post(path, data={"csrf": token, "operation": "begin", "current_password": "correct"})
            setup = field(enroll, "enrollment")
            key = base64.b32decode(re.search(rb"<code>([A-Z2-7]{32})</code>", enroll.data)[1])
            self.assertIn(b"<svg", enroll.data)
            code = auth.totp_code(key, 100)
            fields = {"operation": "enable", "enrollment": setup, "code": code}
            other = field(second.get("/ttui/settings"), "csrf")
            with patch.object(auth, "time", SimpleNamespace(time=lambda: 3000)):
                rejected = second.post(path, data={**fields, "csrf": other}, follow_redirects=True)
                self.assertIn(b"Start authenticator setup in this session", rejected.data)
                enabled = first.post(path, data={**fields, "csrf": token}, follow_redirects=True)
                self.assertIn(b"Two-factor authentication is enabled", enabled.data)
        self.assertIn("Audit: mfa rejected", "\n".join(log.output))
        self.assertIn("Audit: authenticator enabled", "\n".join(log.output))
        self.assertNotIn(setup, "\n".join(log.output))
        self.assertTrue(second.get("/ttui/settings").location.endswith("/ttui/login"))
        client = panel.app.test_client()
        with patch.object(auth, "time", SimpleNamespace(time=lambda: 3030)):
            self.assertEqual(self.login(client).status_code, 401)
            next_code = auth.totp_code(key, 101)
            self.assertEqual(self.login(client, next_code).status_code, 302)
            self.assertEqual(self.login(panel.app.test_client(), next_code).status_code, 401)

    def test_allowlist_checks_the_peer_and_prevents_excluding_current_address(self):
        client = panel.app.test_client()
        address = {"REMOTE_ADDR": "192.0.2.1"}
        self.login(client)
        token = field(client.get("/ttui/settings", environ_overrides=address), "csrf")
        data = {"csrf": token, "current_password": "correct", "path": "/ttui", "username": "admin"}
        denied = client.post("/ttui/settings", data={**data, "ip_allowlist": "203.0.113.0/24"},
                             environ_overrides=address, follow_redirects=True)
        self.assertIn(b"Include your current IP address", denied.data)
        client.post("/ttui/settings", data={**data, "ip_allowlist": "192.0.2.1, 2001:db8::/64"}, environ_overrides=address)
        self.assertEqual(panel.settings()["ip_allowlist"], ["192.0.2.1/32", "2001:db8::/64"])
        forged = {"X-Forwarded-For": "192.0.2.1"}
        outside = {"REMOTE_ADDR": "203.0.113.3"}
        self.assertEqual(client.get("/ttui/login", headers=forged, environ_overrides=outside).status_code, 403)
        self.assertEqual(client.get("/ttui/login", environ_overrides={"REMOTE_ADDR": "2001:db8::5"}).status_code, 200)
        probe = {"X-Ttui-Health": panel.health_token(self.config)}
        self.assertEqual(client.get("/ttui/login", headers=probe, environ_overrides=outside).status_code, 200)
        self.assertEqual(client.post("/ttui/login", headers=probe, environ_overrides=outside).status_code, 403)
        self.assertEqual(client.get("/ttui/settings", headers=probe, environ_overrides=outside).status_code, 403)

    def test_restoring_panel_security_preserves_credentials_and_checks_source_address(self):
        archived = {**self.config, "totp_secret": auth.new_totp_secret(), "ip_allowlist": ["198.51.100.0/24"]}
        panel.b.write_json(self.settings, archived)
        archive = backups.create(["panel"], "0.1.0")
        panel.b.write_json(self.settings, self.config)
        with self.assertRaisesRegex(ValueError, "archived allowlist excludes"):
            backups.restore(archive, self.config, "192.0.2.1")
        self.assertEqual(panel.settings(), self.config)
        self.assertEqual(backups.restore(archive, self.config, "198.51.100.2"), "/ttui")
        restored = panel.settings()
        self.assertEqual(restored["totp_secret"], archived["totp_secret"])
        self.assertEqual(restored["ip_allowlist"], archived["ip_allowlist"])

    def test_action_rechecks_allowlist_after_config_lock(self):
        client = panel.app.test_client()
        self.login(client)
        address = {"REMOTE_ADDR": "192.0.2.1"}
        page = client.get("/ttui/settings", environ_overrides=address)
        changed = {**self.config, "ip_allowlist": ["198.51.100.3/32"]}
        with patch.object(panel, "settings", side_effect=[self.config, changed]):
            response = client.post("/ttui/sessions/revoke", environ_overrides=address,
                                   data={"current_password": "correct", "csrf": field(page, "csrf")})
        self.assertEqual(response.status_code, 403)
