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
python3 - "$work/install.log" <<'PY'
import base64
import hmac
import re
import sys
import time
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, build_opener

password = re.search(r"^ttui /ttui \| admin \| (\S+)$", Path(sys.argv[1]).read_text(), re.M)[1]
client = build_opener(HTTPCookieProcessor(CookieJar()))
base = "http://127.0.0.1:8080/ttui"

def get(path):
    return client.open(base + path, timeout=15).read().decode()

def submit(route, page, **fields):
    fields["csrf"] = re.search(r'name="csrf" value="([^"]+)"', page)[1]
    return client.open(base + route, urlencode(fields, doseq=True).encode(), timeout=45).read().decode()

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
assert "tt://?" in submit("/export", page, username="smoke", address="127.0.0.1:17443", format="deeplink")
assert "Set up TrustTunnel" not in get("/server")
assert "Not configured" not in get("/")
backup = submit("/backups", get("/backups"), operation="create", component=["endpoint", "clients"])
assert "Backup created." in backup
archive = re.search(r'name="name" value="(ttui-[^\"]+\.zip)"', backup)[1]
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
assert new_password not in submit("/export", page, username="smoke", address="127.0.0.1:17443", format="toml")
assert "tt://?" in submit("/export", page, username="smoke", address="127.0.0.1:17443", format="deeplink")
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
