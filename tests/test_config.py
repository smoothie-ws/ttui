from io import BytesIO
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

import tomlkit

import app as panel
import backend as b
import endpoint_settings
from routing import DEFAULT_ROUTING, ROUTER_ADDRESS


class ConfigTest(unittest.TestCase):
    def test_endpoint_form_preserves_native_settings_outside_form(self):
        vpn = tomlkit.parse('listen_address = "0.0.0.0:443"\n[listen_protocols.http2]\nmax_frame_size = 20000\n[metrics]\naddress = "127.0.0.1:1987"\n')
        fields = {"bind": "::", "port": "8443", "http2": "on", "quic": "on"}
        fields.update({key: str(default) for key, _, default in endpoint_settings.FIELDS["Timeouts (seconds)"]})
        endpoint_settings.update(vpn, fields)
        self.assertEqual(vpn["listen_address"], "[::]:8443")
        self.assertEqual(vpn["listen_protocols"]["http2"]["max_frame_size"], 20000)
        self.assertEqual(vpn["metrics"]["address"], "127.0.0.1:1987")
        self.assertIn("quic", vpn["listen_protocols"])

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        for key, path in {
            "CONFIG": self.directory,
            "STATE": self.directory,
            "VPN": self.directory / "vpn.toml",
            "HOSTS": self.directory / "hosts.toml",
            "ROUTING": self.directory / "routing.json",
            "GEO": self.directory / "geo",
            "LAUNCH": self.directory / "endpoint.json",
        }.items():
            self.start_patch(patch.object(b, key, path))
        self.service = self.start_patch(patch.object(b, "service"))
        self.status = self.start_patch(patch.object(b, "service_state", return_value="inactive"))
        self.real_active_endpoint = b.active_endpoint
        self.active = self.start_patch(patch.object(b, "active_endpoint"))
        self.validate = self.start_patch(patch.object(b, "validate_xray"))

    def start_patch(self, patcher):
        self.addCleanup(patcher.stop)
        return patcher.start()

    def write_vpn(self):
        text = 'listen_address = "127.0.0.1:443"\n[forward_protocol.direct]\n'
        b.VPN.write_text(text, encoding="utf-8")
        return text

    def test_save_disabled_routing_without_endpoint(self):
        spec = {**DEFAULT_ROUTING, "default": "block"}
        b.apply_routing(spec)
        self.assertEqual(b.load_routing(), spec)
        self.assertFalse(b.VPN.exists())
        self.service.assert_not_called()

    def test_initial_setup_writes_config_and_preserves_it_on_retry(self):
        def certificate(args):
            for option in ("-out", "-keyout"):
                Path(args[args.index(option) + 1]).write_bytes(b"generated PEM")

        fields = {"hostname": "vpn.example.com", "bind": "::", "port": "443", "username": "first", "quic": "on"}
        with patch.dict(panel.app.config, SECRET_KEY="secret"), patch.object(b, "command", side_effect=certificate):
            for _ in range(2):
                with panel.app.test_request_context("/setup", method="POST", data=fields):
                    self.assertEqual(panel.setup_endpoint().status_code, 302)
        vpn = tomlkit.parse(b.read(b.VPN))
        self.assertEqual(vpn["listen_address"], "[::]:443")
        self.assertEqual(set(vpn["listen_protocols"]), {"http2", "quic"})
        self.assertEqual(b.configured_clients(vpn)[0]["username"], "first")
        self.assertEqual((self.directory / "endpoint-key.pem").read_bytes(), b"generated PEM")
        self.service.assert_called_once_with("restart", b.ENDPOINT_UNIT)

    def test_routing_does_not_start_stopped_services(self):
        self.write_vpn()
        b.apply_routing({**DEFAULT_ROUTING, "enabled": True})
        self.assertEqual(tomlkit.parse(b.read(b.VPN))["forward_protocol"]["socks5"]["address"], ROUTER_ADDRESS)
        self.assertTrue(b.load_routing()["enabled"])
        b.apply_routing(DEFAULT_ROUTING)
        self.assertIn("direct", tomlkit.parse(b.read(b.VPN))["forward_protocol"])
        self.service.assert_not_called()

    def test_detached_credentials_are_ignored_in_loopback_mode(self):
        self.write_vpn()
        (b.CONFIG / "credentials.toml").write_text("invalid = [", encoding="utf-8")
        b.apply_routing({**DEFAULT_ROUTING, "enabled": True})
        self.assertEqual(b.configured_clients({}, "invalid = ["), [])
        self.assertTrue(b.load_routing()["enabled"])

    def test_live_routing_failure_restores_files_and_services(self):
        original = self.write_vpn()
        self.status.side_effect = lambda unit: "active" if unit == b.ENDPOINT_UNIT else "inactive"
        self.active.side_effect = [RuntimeError("startup"), None]
        with self.assertRaisesRegex(RuntimeError, "startup"):
            b.apply_routing({**DEFAULT_ROUTING, "enabled": True})
        self.assertEqual(b.read(b.VPN), original)
        self.assertFalse(b.ROUTING.exists())
        self.assertEqual(self.service.call_args_list, [
            call("restart", b.ROUTER_UNIT), call("restart", b.ENDPOINT_UNIT),
            call("restart", b.ENDPOINT_UNIT), call("stop", b.ROUTER_UNIT),
        ])

    def test_changing_rule_does_not_restart_live_endpoint(self):
        self.write_vpn()
        b.apply_routing({**DEFAULT_ROUTING, "enabled": True})
        original = b.read(b.VPN).replace("extended_auth = false", "extended_auth=false")
        b.VPN.write_text(original, encoding="utf-8")
        self.status.return_value = "active"
        b.apply_routing({**DEFAULT_ROUTING, "enabled": True, "default": "block"})
        self.assertEqual(b.read(b.VPN), original)
        self.service.assert_called_once_with("restart", b.ROUTER_UNIT)

    def test_invalid_geofile_does_not_restart_running_router(self):
        b.write_json(b.ROUTING, {**DEFAULT_ROUTING, "enabled": True})
        b.GEO.mkdir()
        data = b.GEO / "geoip.dat"
        data.write_bytes(b"old")
        self.status.return_value = "active"
        self.validate.side_effect = RuntimeError("invalid")
        with self.assertRaisesRegex(RuntimeError, "invalid"):
            b.replace_geofile(data.name, BytesIO(b"new"))
        self.assertEqual(data.read_bytes(), b"old")
        self.service.assert_not_called()

    def test_readiness_rejects_restarting_endpoint(self):
        running = "ActiveState=active\nMainPID=123\n"
        with patch.object(b.time, "sleep"), \
                patch.object(b, "command", side_effect=[running, running.replace("123", "456")]) as command:
            with self.assertRaisesRegex(RuntimeError, "TrustTunnel"):
                self.real_active_endpoint()
        self.assertEqual(command.call_count, 2)

    def test_write_failure_rolls_back_without_touching_services(self):
        self.write_vpn()
        old = b.VPN.read_bytes()
        real_atomic = b.atomic

        def fail_second(path, data):
            if path == b.HOSTS:
                raise OSError("write failed")
            real_atomic(path, data)

        with patch.object(b, "atomic", side_effect=fail_second):
            with self.assertRaisesRegex(OSError, "write failed"):
                b.change_files({b.VPN: b"new", b.HOSTS: b""}, self.service, self.active)
        self.assertEqual(b.VPN.read_bytes(), old)
        self.service.assert_not_called()
        self.active.assert_not_called()

    def test_rebinding_existing_file_preserves_target(self):
        vpn = 'listen_address = "0.0.0.0:443"\ncredentials_file = "old.toml"\n'
        b.VPN.write_text(vpn, encoding="utf-8")
        old = '[[client]]\nusername = "old"\npassword = "secret"\n'
        new = old.replace('"old"', '"new"')
        (b.CONFIG / "old.toml").write_text(old, encoding="utf-8")
        (b.CONFIG / "new.toml").write_text(new, encoding="utf-8")
        config = {"path": "/ttui", "secret": "secret", "password_hash": "test", "secure_cookie": False}
        with patch.object(panel, "settings", return_value=config), patch.dict(panel.app.config, SECRET_KEY="secret"):
            client = panel.app.test_client()
            with client.session_transaction() as session:
                session["auth"] = panel.session_id(config)
                session["csrf"] = "token"
            data = {**panel.server_sources()[2], "csrf": "token"}
            data["revision"] = panel.revision(panel.server_sources()[2])
            data["vpn"] = vpn.replace("old.toml", "new.toml")
            edited = {**data, "credentials": old.replace("secret", "changed")}
            self.assertEqual(client.post("/ttui/server", data=edited).status_code, 400)
            data["credentials"] = old.replace("\n", "\r\n")
            self.assertEqual(client.post("/ttui/server", data=data).status_code, 302)
        self.assertEqual((b.CONFIG / "new.toml").read_text(encoding="utf-8"), new)
        self.assertIn("new.toml", b.read(b.VPN))

    def test_broken_credentials_can_be_replaced_by_rebinding(self):
        vpn = 'listen_address = "0.0.0.0:443"\ncredentials_file = "old.toml"\n'
        b.VPN.write_text(vpn, encoding="utf-8")
        (b.CONFIG / "old.toml").write_text("invalid = [", encoding="utf-8")
        new = '[[client]]\nusername = "new"\npassword = "secret"\n'
        (b.CONFIG / "new.toml").write_text(new, encoding="utf-8")
        source = panel.server_sources()[2]
        with patch.dict(panel.app.config, SECRET_KEY="secret"), panel.app.test_request_context("/server", method="POST", data={
            **source, "vpn": vpn.replace("old.toml", "new.toml"), "revision": panel.revision(source),
        }):
            self.assertEqual(panel.save_server().status_code, 302)
        self.assertIn("new.toml", b.read(b.VPN))
        self.assertEqual((b.CONFIG / "new.toml").read_text(encoding="utf-8"), new)
