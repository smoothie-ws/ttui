import re
import unittest
from unittest.mock import patch

from werkzeug.security import generate_password_hash

import app as panel
from routing import DEFAULT_ROUTING, compile_routing


class PanelTest(unittest.TestCase):
    def test_login_and_version_at_configured_path(self):
        config = {
            "path": "/private/panel",
            "secret": "test-secret",
            "username": "admin",
            "password_hash": generate_password_hash("correct-password", method="pbkdf2:sha256:1000"),
            "secure_cookie": False,
        }
        with patch.object(panel, "settings", return_value=config), patch.dict(
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
            self.assertIn(b"ttui " + version, client.get(settings).data)

    def test_routing_preserves_priority_and_default(self):
        rules = [{"domain": [r"regexp:^test\.example$"], "outboundTag": "direct"},
                 {"ip": ["geoip:private"], "outboundTag": "block"}]
        config, _ = compile_routing({**DEFAULT_ROUTING, "default": "block", "rules": rules})
        self.assertEqual(config["outbounds"][0]["tag"], "block")
        self.assertEqual([rule["outboundTag"] for rule in config["routing"]["rules"]], ["direct", "block"])
