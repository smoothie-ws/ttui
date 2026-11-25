#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -e /opt/ttui || -e /etc/trusttunnel/vpn.toml ]] || systemctl cat trusttunnel.service >/dev/null 2>&1; then
    echo "Run this HTTPS test on a fresh VM or CI runner." >&2
    exit 1
fi
umask 077
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
sudo apt-get update -qq
sudo apt-get install -y -qq caddy
sudo bash install.sh --source "$PWD" --external-proxy >"$work/install.log" 2>&1 || {
    sed '/^ttui .* | .* | /d' "$work/install.log" >&2
    exit 1
}
sudo tee /etc/caddy/Caddyfile >/dev/null <<'CADDY'
localhost {
    tls internal
    reverse_proxy 127.0.0.1:8080
}
CADDY
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl restart caddy.service
for _ in {1..30}; do
    if sudo test -s /var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt; then break; fi
    sleep 1
done
sudo cat /var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt >"$work/root.crt"
python3 - "$work/install.log" "$work/root.crt" <<'PY'
import re
import ssl
import sys
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import HTTPSHandler, HTTPCookieProcessor, ProxyHandler, build_opener

password = re.search(r"^ttui /ttui \| admin \| (\S+)$", Path(sys.argv[1]).read_text(), re.M)[1]
context = ssl.create_default_context(cafile=sys.argv[2])
client = build_opener(ProxyHandler({}), HTTPSHandler(context=context), HTTPCookieProcessor(CookieJar()))
base = "https://localhost/ttui"
with client.open(base + "/login", timeout=20) as response:
    page = response.read().decode()
    cookie = response.headers.get("Set-Cookie", "")
assert all(flag in cookie for flag in ("Secure", "HttpOnly", "SameSite=Strict"))
csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
body = urlencode({"csrf": csrf, "username": "admin", "password": password}).encode()
with client.open(base + "/login", body, timeout=20) as response:
    assert "Dashboard" in response.read().decode()
PY
