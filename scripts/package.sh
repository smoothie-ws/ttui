#!/usr/bin/env bash
# Build the release archive. The version is the publication date: YY.MM.DD.
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(cat VERSION)
[[ $version =~ ^[0-9]{2}\.[0-9]{2}\.[0-9]{2}$ ]]
if [[ ${1:-$version} != "$version" ]]; then
    echo "Tag $1 must match $version from VERSION." >&2
    exit 1
fi
mkdir -p dist
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
python3 scripts/minify.py . "$stage"
install -m 0644 VERSION requirements.txt LICENSE "$stage/"
install -m 0755 install.sh "$stage/"
python3 -m compileall -q "$stage"
if command -v node >/dev/null; then
    for file in "$stage"/static/*.js; do node --check "$file"; done
fi
XZ_OPT=-9 tar -cJf dist/ttui.tar.xz -C "$stage" VERSION install.sh requirements.txt LICENSE \
    $(cd "$stage" && echo *.py) templates static systemd
cp install.sh dist/bootstrap.sh
bash install.sh --release-info >dist/release-info.json
(
    cd dist
    sha256sum --binary ttui.tar.xz > ttui.tar.xz.sha256
)
