#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -e /opt/ttui || -e /etc/trusttunnel/vpn.toml ]] || systemctl cat trusttunnel.service >/dev/null 2>&1; then
    echo "Run this upgrade test on a fresh VM or CI runner." >&2
    exit 1
fi
umask 077
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
curl -fsSL --retry 3 https://github.com/trusttunnel-ui/ttui-panel/releases/download/v0.1.0/bootstrap.sh -o "$work/bootstrap.sh"
sudo bash "$work/bootstrap.sh" --version v0.1.0 --panel-only >"$work/old-install.log" 2>&1
test "$(ttui version)" = 0.1.0
sudo sha256sum /var/lib/ttui/panel.json >"$work/panel-before"
sudo bash install.sh --source "$PWD" >"$work/upgrade.log" 2>&1 || {
    cat "$work/upgrade.log" >&2
    exit 1
}
test "$(ttui version)" = "$(cat VERSION)"
sudo sha256sum /var/lib/ttui/panel.json | diff - "$work/panel-before"
grep -Eq '^Configuration backup: ttui-.+\.zip$' "$work/upgrade.log"
systemctl is-active --quiet ttui.service
curl --fail --silent --show-error --retry 5 --retry-connrefused http://127.0.0.1:8080/ttui/login | grep -q ttui
