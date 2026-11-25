#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(cat VERSION)
[[ $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
if [[ ${1:-v$version} != "v$version" ]]; then
    echo "Tag $1 must match v$version from VERSION." >&2
    exit 1
fi
mkdir -p dist
tar -czf dist/ttui.tar.gz VERSION install.sh app.py auth.py backend.py client_manager.py endpoint_settings.py monitoring.py routing.py requirements.txt \
    templates static systemd docs README.md LICENSE CHANGELOG.md
cp install.sh dist/bootstrap.sh
(
    cd dist
    sha256sum --binary ttui.tar.gz > ttui.tar.gz.sha256
)
