import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import generate_password_hash

import app as panel
import updates


def release(tag="v0.2.0"):
    return {"tag_name": tag, "draft": False, "prerelease": False, "body": "Release notes",
            "assets": [{"name": name, "state": "uploaded"} for name in updates.ASSETS]}


class UpdatesTest(unittest.TestCase):
    def test_only_newer_compatible_stable_release_is_offered(self):
        info = {"version": "0.2.0", "format": 1, "minimum_python": [3, 9], "systems": ["debian"],
                "architectures": ["x86_64"], "components": {key: "v1.2.3" for key in updates.COMPONENTS}}
        with patch.object(updates, "fetch", side_effect=[release(), info]) as fetch, \
                patch.object(updates, "compatibility", return_value=None):
            checked = updates.latest("0.1.0")
        self.assertTrue(checked["compatible"])
        self.assertEqual(checked["components"], info["components"])
        self.assertEqual(fetch.call_args.args[0], updates.REPOSITORY + "/releases/download/v0.2.0/release-info.json")

        with patch.object(updates, "fetch", return_value=release()) as fetch:
            self.assertFalse(updates.latest("0.2.1")["compatible"])
            fetch.assert_called_once()
        with patch.object(updates, "fetch", return_value={**release(), "assets": []}):
            self.assertIn("missing", updates.latest("0.1.0")["problem"])
        with patch.object(updates, "fetch", return_value={**release(), "prerelease": True}):
            with self.assertRaisesRegex(ValueError, "stable"):
                updates.latest("0.1.0")

    def test_queue_runs_only_fixed_command_and_restores_failed_request(self):
        idle = {"tag": "v0.1.0", "available": True, "busy": False}
        with tempfile.TemporaryDirectory() as directory, patch.object(updates.b, "STATE", Path(directory)), \
                patch.object(updates, "status", return_value=idle), \
                patch.object(updates.b, "command", side_effect=RuntimeError("sudo failed")) as command:
            with self.assertRaisesRegex(ValueError, "Invalid update"):
                updates.queue("v0.2.0 --source /tmp")
            command.assert_not_called()
            with self.assertRaisesRegex(RuntimeError, "sudo failed"):
                updates.queue("v0.2.0")
            self.assertEqual(updates.request_file().read_text(encoding="utf-8"), "v0.1.0\n")
            command.assert_called_once_with(["/usr/bin/sudo", "-n", updates.b.SYSTEMCTL, "start", "--no-block",
                                             updates.UNIT], timeout=5)

    def test_updates_requires_authentication_csrf_password_and_reviewed_tag(self):
        config = {"path": "/ttui", "secret": "test-secret", "username": "admin", "secure_cookie": False,
                  "password_hash": generate_password_hash("correct", method="pbkdf2:sha256:1000")}
        latest = {"tag": "v0.2.0", "compatible": True, "url": updates.REPOSITORY, "components": {},
                  "problem": None, "notes": "<script>release note</script>"}
        status = {"available": True, "busy": False, "tag": "", "failed": False}
        with tempfile.TemporaryDirectory() as directory, patch.object(updates.b, "STATE", Path(directory)), \
                patch.object(panel, "settings", return_value=config), patch.dict(panel.app.config, SECRET_KEY=config["secret"]), \
                patch.object(updates, "latest", return_value=latest) as check, patch.object(updates, "queue") as queue, \
                patch.object(updates, "status", return_value=status):
            client = panel.app.test_client()
            self.assertTrue(client.get("/ttui/updates").location.endswith("/ttui/login"))
            response = client.get("/ttui/login")
            token = re.search(rb'name="csrf" value="([^\"]+)"', response.data)[1].decode()
            client.post("/ttui/login", data={"csrf": token, "username": "admin", "password": "correct"})
            response = client.get("/ttui/updates")
            token = re.search(rb'name="csrf" value="([^\"]+)"', response.data)[1].decode()
            self.assertEqual(client.post("/ttui/updates", data={"operation": "check"}).status_code, 403)
            response = client.post("/ttui/updates", data={"csrf": token, "operation": "check"})
            self.assertIn(b"&lt;script&gt;release note", response.data)
            data = {"csrf": token, "operation": "install", "tag": "v0.2.0", "current_password": "wrong"}
            client.post("/ttui/updates", data=data)
            check.assert_called_once()
            client.post("/ttui/updates", data={**data, "tag": "v0.1.9", "current_password": "correct"})
            queue.assert_not_called()
            client.post("/ttui/updates", data={**data, "current_password": "correct"})
            queue.assert_called_once_with("v0.2.0")
