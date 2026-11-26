from io import BytesIO
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

import tomlkit
from werkzeug.security import generate_password_hash
from werkzeug.datastructures import MultiDict

import app as panel
import acme
import backend as b
import certificates as tls
import endpoint_settings
from client_manager import ClientManager, client_statistics
from routing import DEFAULT_ROUTING, FIRST_CASCADE_PORT, ROUTER_ADDRESS, compile_routing


class ConfigTest(unittest.TestCase):
    def test_large_routing_ruleset_preserves_order_and_outbounds(self):
        rules = [{"outboundTag": "block" if index % 2 else "direct", "domain": [f"full:host{index}.example"]}
                 for index in range(5000)]
        config, _ = compile_routing({**DEFAULT_ROUTING, "enabled": True, "rules": rules})
        compiled = config["routing"]["rules"]
        self.assertEqual(len(compiled), len(rules))
        self.assertEqual([(row["outboundTag"], row["domain"]) for row in compiled],
                         [(row["outboundTag"], row["domain"]) for row in rules])

    def test_routing_keeps_rule_priority_and_blocking_fallback(self):
        rules = [{"outboundTag": "direct", "domain": [r"regexp:^vpn\.example$"]},
                 {"outboundTag": "direct", "ip": ["geoip:private", "ext:custom.dat:local"]}]
        spec = {**DEFAULT_ROUTING, "enabled": True, "default": "block", "rules": rules}
        config, _ = compile_routing(spec)
        self.assertEqual(config["outbounds"][0]["tag"], "block")
        self.assertEqual(config["routing"]["rules"], [{**rule, "type": "field"} for rule in rules])

    def test_structured_cascade_compiles_to_native_client_and_socks_outbound(self):
        remote = {"hostname": "vpn.example.com", "addresses": ["vpn.example.com:443"],
                  "username": "client", "password": "secret", "upstream_protocol": "http3"}
        spec = {**DEFAULT_ROUTING, "outbounds": [{"tag": "vpn", "protocol": "trusttunnel", "endpoint": remote}]}
        xray, cascades = compile_routing(spec)
        client = tomlkit.parse(cascades[FIRST_CASCADE_PORT])
        self.assertEqual(client["endpoint"], {**remote, "tls_profile": "chrome"})
        self.assertEqual(client["listener"]["socks"]["address"], f"127.0.0.1:{FIRST_CASCADE_PORT}")
        self.assertEqual(xray["outbounds"][-1]["settings"]["servers"][0]["port"], FIRST_CASCADE_PORT)
        remote["addresses"] = "not-an-array"
        with self.assertRaisesRegex(ValueError, "provide hostname"):
            compile_routing(spec)

    def test_acme_challenges_are_available_without_panel_login(self):
        directory = acme.webroot() / ".well-known" / "acme-challenge"
        directory.mkdir(parents=True)
        (directory / "Example_token-1").write_text("known-authorization", encoding="ascii")
        with patch.dict("os.environ", TTUI_ACME="1"), patch.object(
            panel, "settings", return_value={"path": "/private", "secure_cookie": True,
                                             "secret": "test", "password_hash": "test"},
        ):
            client = panel.app.test_client()
            response = client.get(acme.CHALLENGE_PREFIX + "Example_token-1")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data, b"known-authorization")
            self.assertEqual(client.get(acme.CHALLENGE_PREFIX + "unknown").status_code, 404)
            self.assertEqual(client.get(acme.CHALLENGE_PREFIX + "../panel.json").status_code, 404)
            self.assertEqual(client.get("/private/").status_code, 302)
        with patch.dict("os.environ", TTUI_ACME="0"):
            self.assertIsNone(acme.challenge("Example_token-1"))

    def test_renewal_reloads_only_validated_changes_and_remembers_them(self):
        host = "vpn.example.com"
        b.HOSTS.write_text(tomlkit.dumps({"main_hosts": [{"hostname": host, **acme.live_pair(host)}]}),
                           encoding="utf-8")
        acme.webroot().mkdir(parents=True)
        self.status.return_value = "active"
        with patch.dict("os.environ", TTUI_ACME="1"), patch.object(acme, "certbot") as certbot, patch.object(
            tls, "existing_pair", return_value={"fingerprint": "version-1"},
        ) as verify:
            acme.renew()
            certbot.assert_called_once_with("renew", "--cert-name", host, timeout=180)
            verify.assert_called_once_with(*acme.live_pair(host).values(), host)
            self.service.assert_called_once_with("reload", b.ENDPOINT_UNIT)
            acme.renew()
            self.service.assert_called_once()
            verify.side_effect = ValueError("invalid certificate")
            with self.assertRaisesRegex(ValueError, "invalid certificate"):
                acme.renew()
            self.service.assert_called_once()

    def test_acme_issue_validates_certbot_output_before_returning_paths(self):
        host = "vpn.example.com"
        with patch.dict("os.environ", TTUI_ACME="1"), patch.object(acme, "certbot") as certbot, patch.object(
            tls, "existing_pair", return_value={"fingerprint": "validated"},
        ) as verify:
            pair, details = acme.issue(host, "admin@example.com")
            self.assertEqual(pair, acme.live_pair(host))
            self.assertEqual(details["fingerprint"], "validated")
            self.assertTrue(acme.webroot().is_dir())
            self.assertIn("--keep-until-expiring", certbot.call_args.args)
            verify.assert_called_once_with(*pair.values(), host)

    def test_tls_hostname_must_be_unique_across_groups_before_issuing_certificate(self):
        b.HOSTS.write_text('[[main_hosts]]\nhostname = "vpn.example.com"\n', encoding="utf-8")
        fields = {"revision": panel.revision(b.read(b.HOSTS)), "operation": "create", "group": "ping_hosts",
                  "hostname": "VPN.EXAMPLE.COM", "acme_email": "admin@example.com", "acme_terms": "on"}
        with patch.dict(panel.app.config, SECRET_KEY="secret"), patch.object(panel.acme, "issue") as issue:
            with panel.app.test_request_context("/tls", method="POST", data=fields):
                self.assertEqual(panel.update_tls_host().status_code, 302)
                self.assertIn("already exists", panel.session["_flashes"][0][1])
            issue.assert_not_called()
        self.assertNotIn("ping_hosts", tomlkit.parse(b.read(b.HOSTS)))
        self.service.assert_not_called()

    def test_moving_last_main_host_is_rejected_before_issuing_certificate(self):
        b.HOSTS.write_text('[[main_hosts]]\nhostname = "vpn.example.com"\n', encoding="utf-8")
        fields = {"revision": panel.revision(b.read(b.HOSTS)), "operation": "edit", "source": "main_hosts",
                  "index": "0", "group": "ping_hosts", "hostname": "ping.example.com",
                  "acme_email": "admin@example.com", "acme_terms": "on"}
        with patch.dict(panel.app.config, SECRET_KEY="secret"), patch.object(panel.acme, "issue") as issue:
            with panel.app.test_request_context("/tls", method="POST", data=fields):
                self.assertEqual(panel.update_tls_host().status_code, 302)
                self.assertIn("at least one VPN TLS host", panel.session["_flashes"][0][1])
            issue.assert_not_called()
        self.service.assert_not_called()

    def test_subscription_host_cannot_be_renamed_or_deleted_before_updating_subscription(self):
        b.VPN.write_text('[subscription]\nenabled = false\nhostname = "vpn.example.com"\n'
                         'address = "vpn.example.com:443"\n', encoding="utf-8")
        original = ('[[main_hosts]]\nhostname = "vpn.example.com"\n'
                    '[[main_hosts]]\nhostname = "other.example.com"\n')
        b.HOSTS.write_text(original, encoding="utf-8")
        common = {"revision": panel.revision(original), "source": "main_hosts", "index": "0"}
        cases = ({"operation": "delete"},
                 {"operation": "edit", "group": "main_hosts", "hostname": "new.example.com",
                  "acme_email": "admin@example.com", "acme_terms": "on"},
                 {"operation": "edit", "group": "ping_hosts", "hostname": "vpn.example.com"})
        with patch.dict(panel.app.config, SECRET_KEY="secret"), patch.object(panel.acme, "issue") as issue:
            for fields in cases:
                with self.subTest(operation=fields), panel.app.test_request_context(
                        "/tls", method="POST", data={**common, **fields}):
                    self.assertEqual(panel.update_tls_host().status_code, 302)
                    self.assertIn("Update the subscription hostname", panel.session["_flashes"][0][1])
            issue.assert_not_called()
        self.assertEqual(b.read(b.HOSTS), original)
        self.service.assert_not_called()

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required for TLS certificate tests")
    def test_uploaded_tls_pair_is_validated_and_rolled_back_on_restart_failure(self):
        self.write_vpn()
        original = '[[main_hosts]]\nhostname = "first.example"\nallowed_sni = ["alias.example"]\n'
        b.HOSTS.write_text(original, encoding="utf-8")
        cert, key = self.directory / "cert.pem", self.directory / "key.pem"
        b.command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
                   "-subj", "/CN=second.example", "-addext", "subjectAltName=DNS:second.example",
                   "-out", str(cert), "-keyout", str(key)])
        self.assertGreaterEqual(tls.validate(cert, key, "second.example")["days"], 2)
        with self.assertRaises(RuntimeError):
            tls.validate(cert, key, "wrong.example")
        other_key = self.directory / "other.pem"
        b.command(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
                   "ec_paramgen_curve:prime256v1", "-out", str(other_key)])
        with self.assertRaisesRegex(ValueError, "do not match"):
            tls.validate(cert, other_key, "second.example")

        def edit():
            data = {
                "revision": panel.revision(b.read(b.HOSTS)), "operation": "edit",
                "source": "main_hosts", "group": "main_hosts", "index": "0", "hostname": "second.example",
                "certificate": (BytesIO(cert.read_bytes()), "cert.pem"),
                "private_key": (BytesIO(key.read_bytes()), "key.pem"),
            }
            with patch.dict(panel.app.config, SECRET_KEY="test-secret"), panel.app.test_request_context(
                "/tls", method="POST", data=data,
            ):
                self.assertEqual(panel.update_tls_host().status_code, 302)

        self.active.side_effect = RuntimeError("startup failed")
        edit()
        self.assertEqual(b.read(b.HOSTS), original)
        self.assertEqual(list(self.directory.glob("tls-*-*.pem")), [])
        self.active.side_effect = None
        edit()
        updated = tomlkit.parse(b.read(b.HOSTS))["main_hosts"][0]
        self.assertEqual(updated["hostname"], "second.example")
        self.assertEqual(updated["allowed_sni"], ["alias.example"])
        self.assertTrue((self.directory / updated["private_key_path"]).is_file())
        self.assertTrue((self.directory / "tls-history.json").is_file())

    def test_client_lifecycle_keeps_disabled_credentials_off_endpoint(self):
        vpn = tomlkit.parse('listen_address = "0.0.0.0:443"\ncredentials_file = "clients.toml"\n')
        credentials, _ = b.related(vpn)
        credentials.write_text('[[client]]\nusername = "keeper"\npassword = "present"\n'
                               '[[client]]\nusername = "laptop"\npassword = "old-secret"\n', encoding="utf-8")

        def apply(operations):
            manager = ClientManager(vpn)
            before = tomlkit.dumps(manager.document)
            for name, action, fields in operations:
                manager.change(name, action, fields)
            manager.save(before)

        apply([("laptop", "disable", {})])
        self.assertNotIn("old-secret", b.read(credentials))
        self.assertEqual(self.service.call_count, 1)
        apply([("laptop", "edit", {"new_username": "tablet", "group": "Office"}),
               ("tablet", "rotate", {"password": "new-secret"})])
        self.assertEqual(self.service.call_count, 1)
        self.assertNotIn("new-secret", b.read(credentials))
        row, = ClientManager(vpn).visible("office", "disabled")
        self.assertEqual(row["username"], "tablet")
        self.assertNotIn("new-secret", str(row))
        self.assertEqual([event["action"] for event in row["history"]], ["rotate", "edit", "disable"])
        apply([("tablet", "enable", {})])
        self.assertEqual([entry["username"] for entry in b.configured_clients(vpn)], ["keeper", "tablet"])
        self.assertIn("new-secret", b.read(credentials))
        self.assertEqual(self.service.call_count, 2)
        original = b.read(credentials)
        with self.assertRaisesRegex(ValueError, "at least one client"):
            apply([("keeper", "disable", {}), ("tablet", "disable", {})])
        self.assertEqual(b.read(credentials), original)
        self.assertFalse(ClientManager(vpn).visible(status="disabled"))

    def test_bulk_client_changes_preserve_order_comments_and_disabled_data(self):
        vpn = tomlkit.parse('listen_address = "127.0.0.1:443"\ncredentials_file = "clients.toml"\n')
        credentials, _ = b.related(vpn)
        credentials.write_text('# Credentials\n[[client]]\nusername = "first"\npassword = "one"\n'
                               '[[client]]\nusername = "second"\npassword = "two"\n'
                               '[[client]]\nusername = "third"\npassword = "three"\n', encoding="utf-8")
        manager = ClientManager(vpn)
        before = tomlkit.dumps(manager.document)
        manager.change_many(["third", "first"], "disable", {})
        manager.save(before)
        self.assertTrue(b.read(credentials).startswith("# Credentials\n"))
        self.assertEqual([entry["username"] for entry in b.configured_clients(vpn)], ["second"])
        manager = ClientManager(vpn)
        self.assertEqual({row["username"] for row in manager.visible(status="disabled")}, {"first", "third"})
        manager.change_many(["first", "third"], "enable", {})
        self.assertEqual([entry["username"] for entry in manager.entries], ["second", "first", "third"])
        self.assertEqual([entry["password"] for entry in manager.entries], ["two", "one", "three"])

    def test_failed_bulk_change_does_not_write_partial_results(self):
        vpn = tomlkit.parse('listen_address = "127.0.0.1:443"\ncredentials_file = "clients.toml"\n')
        credentials, _ = b.related(vpn)
        original = '[[client]]\nusername = "first"\npassword = "secret"\n'
        credentials.write_text(original, encoding="utf-8")
        manager = ClientManager(vpn)
        with self.assertRaisesRegex(ValueError, "Client not found"):
            manager.change_many(["first", "missing"], "disable", {})
        self.assertEqual(b.read(credentials), original)
        self.assertFalse(manager.path.exists())

    def test_client_limits_survive_disabling_and_can_inherit_defaults(self):
        vpn = tomlkit.parse('listen_address = "127.0.0.1:443"\ncredentials_file = "clients.toml"\n')
        manager = ClientManager(vpn)
        manager.change("laptop", "create", {"max_http2_conns": "24", "max_http3_conns": "2"})
        manager.change("laptop", "disable", {})
        rows = manager.visible()
        manager.display_limits(rows)
        self.assertEqual(rows[0]["max_http2_conns"], 24)
        manager.change("laptop", "edit", {"new_username": "laptop", "max_http2_conns": ""})
        manager.change("laptop", "enable", {})
        self.assertNotIn("max_http2_conns", manager.entries[0])
        self.assertEqual(manager.entries[0]["max_http3_conns"], 2)

    def test_statistics_use_loopback_and_ignore_malformed_counters(self):
        metrics = {"per_client_metrics": True, "address": "192.0.2.1:1987"}
        vpn = {"metrics": metrics, "listen_protocols": {"http1": {}}}
        with patch("client_manager.HTTPConnection") as connect:
            self.assertIsNone(client_statistics(vpn))
            connect.assert_not_called()
            metrics["address"] = "[::1]:1987"
            response = connect.return_value.getresponse.return_value.__enter__.return_value
            response.status = 200
            entry = {"username": "laptop", "sessions": 0, "inbound": 1024, "outbound": 0, "ip": "2001:db8::1"}
            response.read.return_value = json.dumps([entry]).encode()
            self.assertEqual(client_statistics(vpn), {"laptop": {"sessions": 0, "inbound": 1024, "outbound": 0,
                                                                "ip": "2001:db8::1"}})
            connect.assert_called_once_with("::1", 1987, timeout=0.75)
            response.read.return_value = json.dumps([entry, {**entry, "sessions": True}]).encode()
            self.assertIsNone(client_statistics(vpn))
            response.read.return_value = json.dumps([entry, entry]).encode()
            self.assertIsNone(client_statistics(vpn))

    def test_client_list_paginates_filtered_matches(self):
        b.VPN.write_text('listen_address = "127.0.0.1:443"\ncredentials_file = "clients.toml"\n', encoding="utf-8")
        b.HOSTS.write_text('[[main_hosts]]\nhostname = "vpn.example.com"\n', encoding="utf-8")
        (b.CONFIG / "clients.toml").write_text(tomlkit.dumps({"client": [
            {"username": f"client-{n:02}", "password": "secret"} for n in range(55)
        ]}), encoding="utf-8")
        config = {"path": "/ttui", "secret": "secret", "password_hash": "test", "secure_cookie": False}
        with patch.object(panel, "settings", return_value=config), patch.dict(panel.app.config, SECRET_KEY="secret"):
            client = panel.app.test_client()
            with client.session_transaction() as state:
                state["auth"] = panel.session_id(config)
            page = client.get("/ttui/clients?page=2&q=client&status=enabled")
        self.assertIn(b"Page 2 of 2", page.data)
        self.assertIn(b">client-50</span>", page.data)
        self.assertNotIn(b">client-49</span>", page.data)

    def test_dashboard_only_counts_connected_configured_accounts(self):
        b.VPN.write_text('listen_address = "127.0.0.1:443"\ncredentials_file = "clients.toml"\n', encoding="utf-8")
        b.HOSTS.touch()
        (b.CONFIG / "clients.toml").write_text(tomlkit.dumps({"client": [
            {"username": "first", "password": "secret"}, {"username": "other", "password": "secret"}
        ]}), encoding="utf-8")
        stats = {"first": {"sessions": 2}, "other": {"sessions": 0}, "removed": {"sessions": 1}}
        with patch.dict(panel.app.config, SECRET_KEY="secret"), panel.app.test_request_context("/"), \
                patch.object(panel, "client_statistics", return_value=stats):
            self.assertIn("<dt>Connected client accounts</dt><dd>1</dd>", panel.dashboard())

    def test_endpoint_form_preserves_native_settings_outside_form(self):
        vpn = tomlkit.parse('listen_address = "0.0.0.0:443"\n[listen_protocols.http2]\nmax_frame_size = 20000\n[metrics]\naddress = "127.0.0.1:1987"\n')
        fields = {"bind": "::", "port": "8443", "http2": "on", "quic": "on"}
        fields.update({key: str(default) for key, _, default in endpoint_settings.FIELDS["Timeouts (seconds)"]})
        endpoint_settings.update(vpn, fields)
        self.assertEqual(vpn["listen_address"], "[::]:8443")
        self.assertEqual(vpn["listen_protocols"]["http2"]["max_frame_size"], 20000)
        self.assertEqual(vpn["metrics"]["address"], "127.0.0.1:1987")
        self.assertIn("quic", vpn["listen_protocols"])

    def test_endpoint_preview_updates_native_tables_and_creates_a_backup(self):
        b.VPN.write_text('listen_address = "127.0.0.1:443"\n[listen_protocols.http2]\n', encoding="utf-8")
        b.HOSTS.write_text('[[main_hosts]]\nhostname = "vpn.example.com"\n', encoding="utf-8")
        config = {"path": "/ttui", "secret": "secret", "username": "admin", "secure_cookie": False,
                  "password_hash": generate_password_hash("example", method="pbkdf2:sha256:1000")}
        fields = {"csrf": "token", "bind": "127.0.0.1", "port": "443", "http1": "on", "http2": "on",
                  "http2.max_frame_size": "32768", "metrics": "on", "metrics.address": "[::1]:1987",
                  "metrics.per_client_metrics": "on", "subscription": "on", "subscription.hostname": "vpn.example.com",
                  "subscription.address": "vpn.example.com:443", "subscription.path": "/clients",
                  "subscription.dns_upstreams": "tls://1.1.1.1\ntls://8.8.8.8", "default_max_http3_conns_per_client": "4"}
        fields.update({key: str(default) for key, _, default in endpoint_settings.FIELDS["Timeouts (seconds)"]})
        with patch.object(panel, "settings", return_value=config), patch.dict(panel.app.config, SECRET_KEY="secret"):
            client = panel.app.test_client()
            login = client.get("/ttui/login")
            csrf = re.compile(rb'name="csrf" value="([^"]+)"')
            self.assertEqual(client.post("/ttui/login", data={"csrf": csrf.search(login.data)[1].decode(),
                                                              "username": "admin", "password": "example"}).status_code, 302)
            page = client.get("/ttui/endpoint")
            fields["csrf"] = csrf.search(page.data)[1].decode()
            self.assertIn(b'name="http2.max_frame_size"', page.data)
            fields["revision"] = re.search(rb'name="revision" value="([^"]+)"', page.data)[1].decode()
            invalid = client.post("/ttui/endpoint", data={**fields, "operation": "preview", "subscription.path": "/ping/vpn"},
                                  follow_redirects=True)
            self.assertIn(b"must not overlap", invalid.data)
            invalid = client.post("/ttui/endpoint", data={**fields, "operation": "preview", "http1": ""},
                                  follow_redirects=True)
            self.assertIn(b"Enable HTTP/1.1", invalid.data)
            preview = client.post("/ttui/endpoint", data={**fields, "operation": "preview"})
            self.assertIn(b'max_frame_size = 32768', preview.data)
            fields["candidate"] = re.search(rb'name="candidate" value="([^"]+)"', preview.data)[1].decode()
            self.service.assert_not_called()
            accepted = client.post("/ttui/endpoint", data={**fields, "operation": "apply"}, follow_redirects=True)
            self.assertIn(b"Previous configuration saved", accepted.data)
        archives = panel.snapshots.history()
        self.assertEqual(archives[0][1]["reason"], "pre-config")
        saved = tomlkit.parse(b.read(b.VPN))
        self.assertEqual(saved["listen_protocols"]["http2"]["max_frame_size"], 32768)
        self.assertTrue(saved["metrics"]["per_client_metrics"])
        self.assertEqual(saved["default_max_http3_conns_per_client"], 4)
        self.assertEqual(saved["subscription"]["dns_upstreams"], ["tls://1.1.1.1", "tls://8.8.8.8"])
        self.service.assert_called_once_with("restart", b.ENDPOINT_UNIT)

    def test_endpoint_preserves_quic_aliases_and_managed_outbound(self):
        vpn = tomlkit.parse('listen_address = "127.0.0.1:443"\n[listen_protocols.quic]\nmax_streams_bidi = 500\n')
        vpn["forward_protocol"] = b.ROUTER_FORWARD
        fields = {"bind": "127.0.0.1", "port": "443", "quic": "on", "quic.initial_max_streams_bidi": "700", "forward": "direct"}
        fields.update({key: str(default) for key, _, default in endpoint_settings.FIELDS["Timeouts (seconds)"]})
        self.assertEqual(endpoint_settings.values(vpn)["quic.initial_max_streams_bidi"], 500)
        endpoint_settings.update(vpn, fields, routed=True)
        self.assertEqual(vpn["listen_protocols"]["quic"], {"max_streams_bidi": 700})
        self.assertEqual(vpn["forward_protocol"], b.ROUTER_FORWARD)

    def test_filter_rows_keep_order_and_preserve_native_fields(self):
        document = tomlkit.parse('[[rule]]\naction = "deny"\ncidr = "192.0.2.0/24"\nextra = true\n'
                                 '[[rule]]\naction = "allow"\n')
        values = MultiDict({"rule_index": ["1", "0", ""], "cidr": ["", "192.0.2.9/24", "2001:db8::/64"],
                            "action": ["allow", "deny", "deny"], "client_random_prefix": ["", "", "aabb/ff00"],
                            "client_random_auth_key": ["", "", ""]})
        rows = endpoint_settings.update_filters(document, values)
        self.assertEqual([index for index, _ in rows], ["1", "0", ""])
        rules = tomlkit.parse(tomlkit.dumps(document))["rule"]
        self.assertEqual([rule["action"] for rule in rules], ["allow", "deny", "deny"])
        self.assertTrue(rules[1]["extra"])
        self.assertEqual(rules[1]["cidr"], "192.0.2.0/24")
        self.assertEqual(rules[2]["client_random_prefix"], "aabb/ff00")
        values.setlist("client_random_auth_key", ["", "", "abcd"])
        with self.assertRaisesRegex(ValueError, "optional mask"):
            endpoint_settings.update_filters(document, values)

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

    def test_routing_requires_an_explicit_apply_operation(self):
        spec = {**DEFAULT_ROUTING, "default": "block"}
        with patch.dict(panel.app.config, SECRET_KEY="secret"), patch.object(b, "apply_routing") as apply:
            for operation in ("", "unexpected"):
                fields = {"revision": panel.revision(b.load_routing()), "spec": json.dumps(spec),
                          "operation": operation}
                with panel.app.test_request_context("/routing", method="POST", data=fields):
                    body, status = panel.save_routing()
                    self.assertEqual(status, 400)
                    self.assertIn("Choose whether to validate or apply routing", body)
            apply.assert_not_called()

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

    def test_setup_checks_existing_credentials_before_requesting_certificate(self):
        credentials = self.directory / "credentials.toml"
        credentials.write_text("existing credentials", encoding="utf-8")
        fields = {"hostname": "vpn.example.com", "bind": "0.0.0.0", "port": "8443",
                  "username": "first", "acme_email": "admin@example.com", "acme_terms": "on"}
        with patch.dict(panel.app.config, SECRET_KEY="secret"), patch.object(panel.acme, "issue") as issue:
            with panel.app.test_request_context("/setup", method="POST", data=fields):
                response = panel.setup_endpoint()
                self.assertEqual(response.status_code, 302)
                self.assertIn("cannot overwrite", panel.session["_flashes"][0][1])
        issue.assert_not_called()
        self.assertEqual(credentials.read_text(encoding="utf-8"), "existing credentials")
        self.assertFalse(b.VPN.exists())
        self.service.assert_not_called()

    def test_setup_error_preserves_fields_until_the_form_is_shown(self):
        config = {"path": "/ttui", "secret": "secret", "username": "admin", "secure_cookie": False,
                  "password_hash": generate_password_hash("example", method="pbkdf2:sha256:1000")}
        with patch.object(panel, "settings", return_value=config), patch.dict(panel.app.config, SECRET_KEY="secret"), \
                patch.dict("os.environ", TTUI_ACME="1"):
            client = panel.app.test_client()
            login = client.get("/ttui/login")
            token = re.search(rb'name="csrf" value="([^"]+)"', login.data)[1].decode()
            client.post("/ttui/login", data={"csrf": token, "username": "admin", "password": "example"})
            token = re.search(rb'name="csrf" value="([^"]+)"', client.get("/ttui/server").data)[1].decode()
            response = client.post("/ttui/setup", data={"csrf": token, "hostname": "vpn.example.com",
                                   "bind": "127.0.0.1", "port": "65536", "username": "laptop",
                                   "quic": "on", "acme_email": "admin@example.com", "acme_terms": "on"},
                                   follow_redirects=True)
            self.assertIn(b"Enter a port from 1 to 65535", response.data)
            self.assertIn(b'name="hostname" required placeholder="vpn.example.com" value="vpn.example.com"', response.data)
            self.assertIn(b'name="username" maxlength="64" required placeholder="laptop" value="laptop"', response.data)
            self.assertIn(b'name="acme_email" type="email" maxlength="254" value="admin@example.com"', response.data)
            self.assertIn(b'name="quic" checked', response.data)
            self.assertIn(b'name="acme_terms" type="checkbox" checked', response.data)
            self.assertNotIn(b'value="vpn.example.com"', client.get("/ttui/server").data)

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

    def test_geofile_checksum_can_be_checked_without_changing_the_file(self):
        b.GEO.mkdir()
        path = b.GEO / "custom.dat"
        path.write_bytes(b"geodata")
        with patch.dict(panel.app.config, SECRET_KEY="secret"):
            for fields, message in (({"name": "custom.dat"}, "SHA-256"),
                                    ({"name": "custom.dat", "sha256": "0" * 64}, "does not match"),
                                    ({"name": "../custom.dat"}, "valid geodata")):
                with self.subTest(fields=fields), panel.app.test_request_context("/geofiles/verify", method="POST", data=fields):
                    self.assertEqual(panel.verify_geo().status_code, 302)
                    self.assertIn(message, panel.session["_flashes"][0][1])
        self.assertEqual(path.read_bytes(), b"geodata")
        self.service.assert_not_called()

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
