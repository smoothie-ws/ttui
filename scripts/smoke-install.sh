#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -e /opt/ttui || -e /etc/trusttunnel/vpn.toml ]] || systemctl cat trusttunnel.service >/dev/null 2>&1; then
    echo "Run the installation smoke test on a fresh VM or CI runner." >&2
    exit 1
fi
umask 077
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/source"
(cd dist && sha256sum --check --strict ttui.tar.gz.sha256)
tar -xzf dist/ttui.tar.gz -C "$work/source"
install_panel() {
    local command
    printf -v command '%q ' sudo bash "$work/source/install.sh" --source "$work/source" "$@"
    # Exercise an interactive terminal while keeping credentials out of the CI log.
    if ! script -eqc "$command" /dev/null </dev/null 2>&1 | tr -d '\r' >"$work/install.log"; then
        sed '/^ttui .* | .* | /d' "$work/install.log" >&2
        return 1
    fi
}
smoke() {
    curl --fail --silent --show-error --retry 5 --retry-connrefused \
        http://127.0.0.1:8080/ttui/login | grep 'ttui' >/dev/null
}
snapshot() {
    sudo sha256sum /var/lib/ttui/panel.json /var/lib/ttui/routing.json \
        /var/lib/ttui/geo/geosite.dat /etc/trusttunnel/{vpn,hosts,credentials}.toml \
        /etc/systemd/system/ttui.service
}
install_panel --local
grep -q '^Default sign-in URL: http://127.0.0.1:8080/ttui/$' "$work/install.log"
grep -q '^Administrator username: admin$' "$work/install.log"
grep -Eq '^ttui /ttui \| admin \| [A-Za-z0-9_-]+$' "$work/install.log"
grep -Fq 'Sign in and open Server > Set up TrustTunnel' "$work/install.log"
smoke
for config in vpn hosts credentials; do
    sudo test ! -e "/etc/trusttunnel/$config.toml"
done
if systemctl is-active --quiet trusttunnel.service; then
    echo "TrustTunnel started before web setup." >&2
    exit 1
fi
systemctl is-active --quiet ttui-metrics.timer
systemctl is-active --quiet ttui-backups.timer
sudo systemctl start ttui-metrics.service
sudo -u ttui sudo -n /usr/bin/journalctl --no-pager --output=json --lines=500 --unit=ttui.service >/dev/null
sudo -u ttui mkdir -p /var/lib/ttui/acme/config/{archive,live}/smoke.example
printf 'archived certificate\n' | sudo -u ttui tee /var/lib/ttui/acme/config/archive/smoke.example/fullchain1.pem >/dev/null
sudo -u ttui ln -s ../../archive/smoke.example/fullchain1.pem /var/lib/ttui/acme/config/live/smoke.example/fullchain.pem
python3 - "$work/install.log" <<'PY'
import base64
import hashlib
import html
import hmac
import http.server
import json
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener, urlopen

password = re.search(r"^ttui /ttui \| admin \| (\S+)$", Path(sys.argv[1]).read_text(), re.M)[1]
cookies = CookieJar()
client = build_opener(HTTPCookieProcessor(cookies))
base = "http://127.0.0.1:8080/ttui"

def get(path):
    return client.open(base + path, timeout=15).read().decode()

def submit(route, page, **fields):
    fields["csrf"] = re.search(r'name="csrf" value="([^"]+)"', page)[1]
    return client.open(base + route, urlencode(fields, doseq=True).encode(), timeout=45).read().decode()

def new_archive(before, after):
    pattern = r'name="name" value="(ttui-[^"]+\.zip)"'
    created = set(re.findall(pattern, after)) - set(re.findall(pattern, before))
    assert len(created) == 1, "Expected exactly one new backup"
    return created.pop()

submit("/login", get("/login"), username="admin", password=password)
assert "Not configured" in get("/")
assert "TrustTunnel Endpoint" in get("/updates")
assert "The systemd updater is unavailable" not in get("/updates")
assert 'data-chart="usage"' in get("/monitoring")
assert "The service journal is unavailable" not in get("/logs")
assert "Accepting connections on 127.0.0.1:8080." in submit("/diagnostics", get("/diagnostics"))
server = get("/server")
assert "Set up TrustTunnel" in server
page = submit("/setup", server, hostname="smoke.example", bind="127.0.0.1", port="17443", username="smoke")
assert "TrustTunnel is running." in page, "Panel setup failed"
cookie_header = "; ".join(f"{cookie.name}={cookie.value}" for cookie in cookies)

def concurrent_read(item):
    path, expected = item
    with urlopen(Request(base + path, headers={"Cookie": cookie_header}), timeout=30) as response:
        return response.status == 200 and expected in response.read().decode()

with ThreadPoolExecutor(max_workers=8) as pool:
    results = list(pool.map(concurrent_read, [("/", "Dashboard"), ("/clients", "smoke"),
                                             ("/routing", "Routing")] * 20))
assert all(results), "The panel failed concurrent authenticated reads"
assert "tt://?" in submit("/export", page, username="smoke", address="127.0.0.1:17443", format="deeplink")
exported = submit("/export", page, username="smoke", address="127.0.0.1:17443", format="toml")
config_text = html.unescape(re.search(r'<textarea id="export-value"[^>]*>(.*?)</textarea>', exported, re.S)[1])
endpoint = tomllib.loads(config_text)
assert endpoint["hostname"] == "smoke.example"
assert endpoint["username"] == "smoke" and endpoint["password"]
assert endpoint.get("skip_verification", False) is False
assert "-----BEGIN CERTIFICATE-----" in endpoint["certificate"]
assert "Set up TrustTunnel" not in get("/server")
assert "Not configured" not in get("/")
routing_page = get("/routing")
csrf = re.search(r'name="csrf" value="([^\"]+)"', routing_page)[1]
geo_data = b"ttui custom geodata smoke test"
boundary = "ttui-smoke-boundary"
parts = [f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode()
         for key, value in (("csrf", csrf), ("sha256", hashlib.sha256(geo_data).hexdigest()))]
parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="data"; filename="smoke.dat"\r\n'
             'Content-Type: application/octet-stream\r\n\r\n'.encode() + geo_data + b"\r\n")
parts.append(f"--{boundary}--\r\n".encode())
upload = Request(base + "/geofiles", b"".join(parts),
                 {"Content-Type": f"multipart/form-data; boundary={boundary}"})
assert "Geodata file saved." in client.open(upload, timeout=30).read().decode()
checked = submit("/geofiles/verify", get("/routing"), name="smoke.dat", sha256=hashlib.sha256(geo_data).hexdigest())
assert "(verified)." in checked
assert "checksum does not match" in submit("/geofiles/verify", checked, name="smoke.dat", sha256="0" * 64)
before_backup = get("/backups")
geo_backup = submit("/backups", before_backup, operation="create", component="geo")
assert "Backup created." in geo_backup
geo_archive = new_archive(before_backup, geo_backup)
geo_path = "/var/lib/ttui/geo/smoke.dat"
subprocess.run(["sudo", "-u", "ttui", "tee", geo_path], input=b"changed", stdout=subprocess.DEVNULL, check=True)
assert "Backup restored." in submit("/backups", geo_backup, operation="restore", name=geo_archive,
                                   current_password=password)
assert subprocess.check_output(["sudo", "-u", "ttui", "cat", geo_path]) == geo_data
before_backup = get("/backups")
backup = submit("/backups", before_backup, operation="create", component=["endpoint", "clients"])
assert "Backup created." in backup
cert = "/var/lib/ttui/acme/config/live/smoke.example/fullchain.pem"
subprocess.run(["sudo", "-u", "ttui", "tee", cert], input=b"changed certificate\n", stdout=subprocess.DEVNULL, check=True)
archive = new_archive(before_backup, backup)
assert "Backup integrity verified." in submit("/backups", backup, operation="verify", name=archive)
with client.open(f"{base}/backups/{archive}", timeout=15) as download:
    assert download.read(2) == b"PK"
    assert "attachment" in download.headers["Content-Disposition"]
new_password = "smoke-client-rotated"
updated = submit("/clients", backup, operation="rotate", username="smoke", password=new_password)
assert "Clients updated." in updated
assert new_password in submit("/export", updated, username="smoke", address="127.0.0.1:17443", format="toml")
page = submit("/backups", get("/backups"), operation="restore", name=archive, current_password="incorrect")
assert "Enter your current administrator password." in page
page = submit("/backups", page, operation="restore", name=archive, current_password=password)
assert "Backup restored." in page
assert subprocess.check_output(["sudo", "-u", "ttui", "cat", cert]) == b"archived certificate\n"
subprocess.run(["sudo", "-u", "ttui", "test", "-L", cert], check=True)
assert new_password not in submit("/export", page, username="smoke", address="127.0.0.1:17443", format="toml")
assert "tt://?" in submit("/export", page, username="smoke", address="127.0.0.1:17443", format="deeplink")
endpoint = get("/endpoint")
fields = {"bind": "127.0.0.1", "port": "17443", "http1": "on", "http2": "on", "ipv6_available": "on",
          "allow_private_network_connections": "on",
          "tls_handshake_timeout_secs": "10", "client_listener_timeout_secs": "600",
          "connection_establishment_timeout_secs": "30", "tcp_connections_timeout_secs": "604800",
          "udp_connections_timeout_secs": "300", "http2.max_frame_size": "32768", "metrics": "on",
          "metrics.address": "127.0.0.1:11987", "metrics.per_client_metrics": "on",
          "subscription": "on", "subscription.hostname": "smoke.example",
          "subscription.address": "smoke.example:17443", "subscription.path": "/vpn-config"}
fields["revision"] = re.search(r'name="revision" value="([^"]+)"', endpoint)[1]
preview = submit("/endpoint", endpoint, operation="preview", **fields)
assert "max_frame_size = 32768" in preview
fields["candidate"] = re.search(r'name="candidate" value="([^"]+)"', preview)[1]
applied = submit("/endpoint", preview, operation="apply", **fields)
assert "Previous configuration saved" in applied
assert "Before configuration change" in get("/backups")
routing_page = get("/routing")
routing_revision = re.search(r'name="revision" value="([^\"]+)"', routing_page)[1]
routing_spec = {"enabled": True, "domainStrategy": "IPIfNonMatch", "default": "block", "outbounds": [],
                "rules": [{"outboundTag": "direct", "domain": ["regexp:^smoke\\.example$"]},
                          {"outboundTag": "direct", "ip": ["geoip:private"]}]}
assert "Routing settings saved." in submit("/routing", routing_page, operation="apply", revision=routing_revision,
                                           spec=json.dumps(routing_spec))
subprocess.run(["systemctl", "is-active", "--quiet", "ttui-router.service"], check=True)

class TestOrigin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"trusttunnel-smoke-ok")

    def log_message(self, *args):
        pass

with socket.socket() as reservation:
    reservation.bind(("127.0.0.1", 0))
    socks_port = reservation.getsockname()[1]
config_file = Path(sys.argv[1]).with_name("smoke-client.toml")
config_file.write_text(f'vpn_mode = "general"\n[listener.socks]\naddress = "127.0.0.1:{socks_port}"\n'
                       f'[endpoint]\n{config_text}', encoding="utf-8")
def wait_listener(port, process):
    deadline = time.monotonic() + 20
    while True:
        if process.poll() is not None:
            raise AssertionError("TrustTunnel process exited before its listener was ready")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            if time.monotonic() >= deadline:
                raise AssertionError("TrustTunnel listener did not start")
            time.sleep(0.2)

def stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()

def exercise_vpn():
    with http.server.HTTPServer(("127.0.0.1", 0), TestOrigin) as origin:
        thread = threading.Thread(target=origin.serve_forever, daemon=True)
        thread.start()
        process = subprocess.Popen(["/opt/ttui/trusttunnel_client", "--config", str(config_file)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_listener(socks_port, process)
            body = subprocess.check_output(["curl", "--fail", "--silent", "--show-error", "--max-time", "15",
                                            "--noproxy", "", "--socks5-hostname", f"127.0.0.1:{socks_port}",
                                            f"http://127.0.0.1:{origin.server_port}/"])
            assert body == b"trusttunnel-smoke-ok", "VPN did not deliver traffic to the test origin"
        finally:
            stop(process)
            origin.shutdown()
            thread.join()

exercise_vpn()
with tempfile.TemporaryDirectory(dir=Path(sys.argv[1]).parent, prefix="cascade-") as directory:
    root = Path(directory)
    for filename in ("endpoint-cert.pem", "endpoint-key.pem"):
        (root / filename).write_bytes(subprocess.check_output(["sudo", "-u", "ttui", "cat", "/etc/trusttunnel/" + filename]))
    remote = tomllib.loads(config_text)
    (root / "credentials.toml").write_text(
        f'[[client]]\nusername = {json.dumps(remote["username"])}\npassword = {json.dumps(remote["password"])}\n')
    (root / "hosts.toml").write_text(
        f'[[main_hosts]]\nhostname = "smoke.example"\ncert_chain_path = {json.dumps(str(root / "endpoint-cert.pem"))}\n'
        f'private_key_path = {json.dumps(str(root / "endpoint-key.pem"))}\n')
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        remote_port = reservation.getsockname()[1]
    (root / "vpn.toml").write_text(
        f'listen_address = "127.0.0.1:{remote_port}"\ncredentials_file = {json.dumps(str(root / "credentials.toml"))}\n'
        'allow_private_network_connections = true\n[listen_protocols.http2]\n')
    upstream = subprocess.Popen(["/opt/trusttunnel/trusttunnel_endpoint", str(root / "vpn.toml"), str(root / "hosts.toml")],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_listener(remote_port, upstream)
        remote["addresses"] = [f"127.0.0.1:{remote_port}"]
        routing_spec = {"enabled": True, "domainStrategy": "IPIfNonMatch", "default": "cascade",
                        "outbounds": [{"tag": "cascade", "protocol": "trusttunnel", "endpoint": remote}], "rules": []}
        routing_page = get("/routing")
        routing_revision = re.search(r'name="revision" value="([^\"]+)"', routing_page)[1]
        assert "Routing settings saved." in submit("/routing", routing_page, operation="apply", revision=routing_revision,
                                                   spec=json.dumps(routing_spec))
        exercise_vpn()
    finally:
        stop(upstream)
routing_page = get("/routing")
routing_revision = re.search(r'name="revision" value="([^\"]+)"', routing_page)[1]
routing_spec["enabled"] = False
assert "Routing settings saved." in submit("/routing", routing_page, operation="apply", revision=routing_revision,
                                           spec=json.dumps(routing_spec))
assert client.open("http://127.0.0.1:11987/metrics", timeout=15).status == 200
deadline = time.monotonic() + 10
while True:
    clients, dashboard = get("/clients"), get("/")
    if "0 sessions" in clients and "<dt>Connected client accounts</dt><dd>0</dd>" in dashboard:
        break
    if time.monotonic() >= deadline:
        raise AssertionError("Client session remained active after disconnect")
    time.sleep(0.2)
assert "Clients updated." in submit("/clients", clients, operation="edit", username="smoke", new_username="smoke",
                                    max_http2_conns="16", max_http3_conns="2")
assert 'name="max_http2_conns" value="16"' in get("/clients")
filters = get("/filters")
rules = {"state": "on", "rule_index": "", "action": "deny", "cidr": "192.0.2.0/24",
         "client_random_prefix": "", "client_random_auth_key": ""}
rules["revision"] = re.search(r'name="revision" value="([^"]+)"', filters)[1]
preview = submit("/filters", filters, operation="preview", **rules)
assert '192.0.2.0/24' in preview
rules["candidate"] = re.search(r'name="candidate" value="([^"]+)"', preview)[1]
assert "Connection filters applied." in submit("/filters", preview, operation="apply", **rules)
assert "Backup schedule saved." in submit("/backups", page, operation="schedule", interval="daily", component="panel")
settings = get("/settings")
assert "Panel settings saved." in submit("/settings", settings, username="admin", path="/ttui",
                                      current_password=password, ip_allowlist="127.0.0.1")
setup = submit("/mfa", get("/settings"), operation="begin", current_password=password)
key = base64.b32decode(re.search(r'<code>([A-Z2-7]{32})</code>', setup)[1])
enrollment = re.search(r'name="enrollment" value="([^"]+)"', setup)[1]

def otp(counter):
    digest = hmac.digest(key, counter.to_bytes(8, "big"), "sha1")
    offset = digest[-1] & 15
    return f"{(int.from_bytes(digest[offset:offset + 4], 'big') & 0x7fffffff) % 1_000_000:06}"

if time.time() % 30 > 24:
    time.sleep(31 - time.time() % 30)
step = int(time.time()) // 30
enabled = submit("/mfa", setup, operation="enable", enrollment=enrollment, code=otp(step - 1))
assert "Two-factor authentication is enabled." in enabled
submit("/logout", enabled)
try:
    submit("/login", get("/login"), username="admin", password=password, code=otp(step - 1))
    raise AssertionError("Authenticator accepted a reused code")
except HTTPError as error:
    assert error.code == 401
submit("/login", get("/login"), username="admin", password=password, code=otp(step))
disabled = submit("/mfa", get("/settings"), operation="disable", current_password=password, code=otp(step + 1))
assert "Set up authenticator" in disabled
assert "Audit: authenticator enabled" in get("/logs?source=panel&q=Audit%3A")
PY
if [[ -n ${TTUI_BROWSER_PYTHON:-} ]]; then
    "$TTUI_BROWSER_PYTHON" scripts/smoke-browser.py "$work/install.log"
fi
sudo -u ttui sed -i -E 's/("next": )"[^"]+"/\1"2000-01-01T00:00:00+00:00"/' /var/lib/ttui/backup-schedule.json
sudo systemctl start ttui-backups.service
sudo grep -Fq -- '-auto.zip' /var/lib/ttui/backup-schedule.json
sudo systemctl is-active --quiet trusttunnel.service
printf 'v0.0.0\n' | sudo -u ttui tee /var/lib/ttui/update-request >/dev/null
sudo -u ttui sudo -n /usr/bin/systemctl start --no-block ttui-update.service
for _ in {1..20}; do
    if systemctl is-failed --quiet ttui-update.service; then break; fi
    sleep 0.25
done
systemctl is-failed --quiet ttui-update.service
sudo -u ttui sudo -n /usr/bin/journalctl --no-pager --output=json --lines=500 --unit=ttui-update.service \
    | grep -F 'The requested release is already installed or older.' >/dev/null
sudo -u ttui rm -f /var/lib/ttui/update-request
sudo systemctl reset-failed ttui-update.service
for config in vpn hosts credentials; do
    sudo test -s "/etc/trusttunnel/$config.toml"
done
sudo -u ttui tee /var/lib/ttui/routing.json >/dev/null <<'JSON'
{"enabled":false,"domainStrategy":"IPIfNonMatch","default":"direct","outbounds":[],"rules":[]}
JSON
snapshot >"$work/before"
version=$(cat "$work/source/VERSION")
patch_version=${version##*.}
next_version="${version%.*}.$((patch_version + 1))"
echo "$next_version" >"$work/source/VERSION"
install_panel
grep -Eq '^Configuration backup: ttui-.+\.zip$' "$work/install.log"
test "$(ttui version)" = "$next_version"
smoke
sudo systemctl is-active --quiet trusttunnel.service
snapshot | diff - "$work/before"

# A live process serving a broken sign-in page must still trigger rollback.
sed -i '/{{ token() }}/d' "$work/source/templates/login.html"
sed -i 's/^Description=.*/Description=ttui test candidate/' "$work/source/systemd/ttui.service"
echo "${version%.*}.$((patch_version + 2))" >"$work/source/VERSION"
if install_panel; then
    echo "Invalid upgrade unexpectedly succeeded." >&2
    exit 1
fi
grep -q 'Restoring previous installation' "$work/install.log"
test "$(ttui version)" = "$next_version"
smoke
sudo systemctl is-active --quiet trusttunnel.service
snapshot | diff - "$work/before"
