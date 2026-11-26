#!/usr/bin/env bash
set -euo pipefail

repository=https://github.com/trusttunnel-ui/ttui-panel
panel=/opt/ttui
endpoint=/opt/trusttunnel/trusttunnel_endpoint
units=/etc/systemd/system
sudoers=/etc/sudoers.d/ttui
launcher=/usr/local/bin/ttui
managed_units=(ttui.service trusttunnel.service ttui-router.service)
support_units=(ttui-acme.service ttui-acme.timer ttui-metrics.service ttui-metrics.timer ttui-backups.service ttui-backups.timer ttui-update.service)
endpoint_tag=v1.3.1
client_tag=v1.3.0
xray_tag=v26.11.9
# Releases are named by publication date: YY.MM.DD.
version_re='[0-9]{2}\.[0-9]{2}\.[0-9]{2}'

release_info() {
    local version
    version=$(cat "$1/VERSION")
    [[ $version =~ ^$version_re$ ]]
    cat <<EOF
{"format":1,"version":"$version","components":{"endpoint":"$endpoint_tag","client":"$client_tag","xray":"$xray_tag"},"systems":["debian","ubuntu"],"architectures":["x86_64","aarch64"],"minimum_python":[3,9]}
EOF
}

start_queued_update() {
    local version installed
    version=$(runuser -u ttui -- /usr/bin/python3 -I -c '
import os, stat, sys

with os.fdopen(os.open("/var/lib/ttui/update-request", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as request:
    if not stat.S_ISREG(os.fstat(request.fileno()).st_mode):
        sys.exit("Skip an invalid update request file.")
    version = request.read(65)
    if len(version) > 64:
        sys.exit("Skip an oversized update request.")
    sys.stdout.write(version.decode("ascii"))
')
    if [[ ! $version =~ ^$version_re$ ]]; then
        echo "Invalid update request version." >&2
        return 1
    fi
    installed=$(cat "$panel/VERSION")
    if ! dpkg --compare-versions "$version" gt "$installed"; then
        echo "The requested release is already installed or older." >&2
        return 1
    fi
    main update --version "$version" --newer-only
}

check_public_domain() {
    local domain=$1 label='[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    if [[ ${#domain} -gt 253 || ! $domain =~ ^$label(\.$label)+$ ]] ||
        ! getent ahosts "$domain" >/dev/null; then
        echo "Set a DNS record for the panel and pass its hostname with --domain." >&2
        return 1
    fi
    if [[ -e /etc/caddy/Caddyfile ]] || systemctl is-active --quiet caddy.service; then
        echo "Existing Caddy installation detected. Use --external-proxy with your own configuration." >&2
        return 1
    fi
    if command -v ss >/dev/null && [[ -n $(ss -H -ltn 'sport = :80 or sport = :443') ]]; then
        echo "TCP ports 80 and 443 must be free for Caddy." >&2
        return 1
    fi
}

check_panel_port() {
    local port=$1
    if [[ -n $(ss -H -ltn "sport = :$port") ]]; then
        echo "TCP port $port is already in use. Choose another port with --port." >&2
        return 1
    fi
}

start_panel_https() {
    local domain=$1 port=$2
    cat >/etc/caddy/Caddyfile <<EOF
$domain {
    encode zstd gzip
    reverse_proxy 127.0.0.1:$port
}

http:// {
    handle /.well-known/acme-challenge/* {
        reverse_proxy 127.0.0.1:$port
    }
    handle {
        respond 404
    }
}
EOF
    caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
    systemctl enable caddy.service
    systemctl restart caddy.service
    systemctl enable --now ttui-acme.timer
    if ! curl -fsS --retry 12 --retry-all-errors --retry-delay 5 --max-time 5 \
        --resolve "$domain:443:127.0.0.1" "https://$domain/ttui/login" -o /dev/null; then
        echo "Panel is installed, but HTTPS verification failed. Check DNS, ports 80/443, and journalctl -u caddy." >&2
        return 1
    fi
    local status
    status=$(curl -fsS --max-time 5 --resolve "$domain:443:127.0.0.1" -o /dev/null \
        -w '%{http_code}' "https://$domain/ttui/")
    if [[ $status != 302 ]]; then
        echo "HTTPS panel did not redirect the unauthenticated request to sign-in." >&2
        return 1
    fi
}

fetch_release() (
    local version=$1 work base digest filename extra
    shift
    if [[ $version == latest ]]; then
        base="$repository/releases/latest/download"
    elif [[ $version =~ ^$version_re$ ]]; then
        base="$repository/releases/download/$version"
    else
        echo "Expected latest or a release date such as 26.11.26." >&2
        exit 2
    fi
    work=$(mktemp -d)
    trap 'rm -rf -- "$work"' EXIT
    curl -fLSs --retry 3 --retry-all-errors --connect-timeout 20 "$base/ttui.tar.xz" -o "$work/ttui.tar.xz"
    curl -fLSs --retry 3 --retry-all-errors --connect-timeout 20 "$base/ttui.tar.xz.sha256" -o "$work/ttui.tar.xz.sha256"
    read -r digest filename extra < "$work/ttui.tar.xz.sha256"
    filename=${filename#\*}
    if [[ ! $digest =~ ^[a-f0-9]{64}$ || $filename != ttui.tar.xz || -n $extra ]]; then
        echo "Invalid release checksum." >&2
        exit 1
    fi
    printf '%s *%s\n' "$digest" "$work/ttui.tar.xz" | sha256sum --check --status
    mkdir "$work/source"
    tar -xJf "$work/ttui.tar.xz" -C "$work/source"
    if [[ $version != latest && "$(cat "$work/source/VERSION")" != "$version" ]]; then
        echo "Release asset version mismatch." >&2
        exit 1
    fi
    bash "$work/source/install.sh" --source "$work/source" "$@"
)

download() {
    local url=$1 digest=$2 target=$3
    curl -fLSs --retry 3 --retry-all-errors --connect-timeout 20 "$url" -o "$target"
    printf '%s  %s\n' "$digest" "$target" | sha256sum --check --status
}

seed_geofile() {
    # shellcheck disable=SC2016
    runuser -u ttui -- bash -c '
        set -e
        umask 077
        target=$1
        if [[ -e $target || -L $target ]]; then exit 0; fi
        temporary=$(mktemp -- "$(dirname -- "$target")/.seed.XXXXXX")
        trap '\''rm -f -- "$temporary"'\'' EXIT
        cat > "$temporary"
        if ! ln -T -- "$temporary" "$target"; then
            [[ -e $target || -L $target ]]
        fi
    ' bash "$1" < "$2"
}

wait_service() {
    local unit=$1 before after
    before=$(systemctl show -p MainPID --value "$unit")
    for _ in {1..6}; do
        sleep 0.5
        systemctl is-active --quiet "$unit" || return 1
    done
    after=$(systemctl show -p MainPID --value "$unit")
    [[ $before != 0 && $before == "$after" ]]
}

restore_install() {
    local backup=$1 unit file failed=0
    shift
    systemctl stop "${managed_units[@]}" || failed=1
    mv -- "$panel" "$backup/rejected-panel" || failed=1
    cp -a -- "$backup/panel" "$panel" || failed=1
    for file in "$endpoint" "$sudoers" "${support_units[@]/#/$units/}" "${managed_units[@]/#/$units/}"; do
        if [[ -e $backup/$file ]]; then
            cp -a -- "$backup/$file" "$file" || failed=1
        else
            if [[ -e $file && $file == "$units/ttui-"*.timer ]]; then
                systemctl disable --now "${file##*/}" || failed=1
            fi
            rm -f -- "$file" || failed=1
        fi
    done
    systemctl daemon-reload || failed=1
    for unit in "$@"; do
        if ! systemctl start "$unit" || ! wait_service "$unit"; then failed=1; fi
    done
    return "$failed"
}

backup_before_update() (
    local source_dir=$1 state=$2 version=$3 snapshot_tool
    snapshot_tool=$(mktemp -d "$panel/.snapshot-tool.XXXXXX")
    trap 'rm -rf -- "$snapshot_tool"' EXIT
    chmod 0755 "$snapshot_tool"
    install -m 0644 "$source_dir/"{auth,backend,backups,certificates,routing}.py "$snapshot_tool/"
    cd "$snapshot_tool"
    runuser -u ttui -- env TTUI_STATE="$state" "$panel/venv/bin/python" -c '
import sys
import backend
import backups

with backend.configuration_change():
    archive = backups.create(backups.COMPONENTS, sys.argv[1], reason="pre-update")
print("Configuration backup: " + archive)
' "$version"
)

finish_update() {
    local status=$1 backup=$2 recovery
    shift 2
    if (( status )); then
        echo "Update failed. Restoring previous installation." >&2
        if ! restore_install "$backup" "$@"; then
            recovery=$(mktemp -d /var/tmp/ttui-recovery.XXXXXX)
            cp -a -- "$backup"/. "$recovery"
            echo "Automatic recovery failed. Backup: $recovery" >&2
        fi
    fi
    return "$status"
}

main() {
    local source_dir='' version=latest newer_only=0 updating=0 target current=unknown
    local domain='' access='' adding_https=0 panel_port=8080 port_set=0
    local -a packages=(ca-certificates curl iproute2 openssl python3 python3-venv sudo unzip util-linux xz-utils)
    local architecture xray_arch endpoint_sha client_sha xray_sha
    local config=/etc/trusttunnel state=/var/lib/ttui
    local -a forwarded=() active=()
    local unit file directory credentials
    if [[ $# == 1 && $1 == --release-info ]]; then
        release_info "$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
        return
    fi
    if [[ $# == 1 && $1 == --queued-update ]]; then
        if [[ $EUID != 0 ]]; then echo "Run as root." >&2; return 1; fi
        start_queued_update
        return
    fi
    if [[ ${1:-} == version || ( $# == 1 && ${1:-} == --version ) ]]; then
        if [[ -r $panel/VERSION ]]; then cat "$panel/VERSION"; else echo "ttui version unavailable." >&2; return 1; fi
        return
    fi
    if [[ ${1:-} == update ]]; then shift; fi
    while (( $# )); do
        case "$1" in
            --source) source_dir=$(realpath "${2:?Missing source directory}"); shift ;;
            --version) version=${2:?Missing release version}; shift ;;
            --domain) domain=${2:?Missing panel domain}; forwarded+=(--domain "$domain"); shift ;;
            --port) panel_port=${2:?Missing panel port}; port_set=1; forwarded+=(--port "$panel_port"); shift ;;
            --local) access=local; forwarded+=(--local) ;;
            --external-proxy) access=external; forwarded+=(--external-proxy) ;;
            --newer-only) newer_only=1; forwarded+=(--newer-only) ;;
            *) echo "Usage: ttui [update] [--version YY.MM.DD | --source DIR] [--domain HOST | --local | --external-proxy] [--port PORT]" >&2; return 2 ;;
        esac
        shift
    done
    if [[ $EUID != 0 || ! -d /run/systemd/system ]] || ! command -v apt-get >/dev/null; then
        echo "Run as root on Debian or Ubuntu with systemd." >&2
        return 1
    fi
    umask 022
    if [[ -z $source_dir ]]; then
        fetch_release "$version" "${forwarded[@]}"
        return
    fi
    if [[ $version != latest ]]; then echo "Choose --version or --source." >&2; return 2; fi
    exec 9>/run/lock/ttui-install.lock
    flock -n 9 || { echo "Another ttui installation is in progress." >&2; return 1; }
    target=$(cat "$source_dir/VERSION")
    [[ $target =~ ^$version_re$ ]] || {
        echo "Invalid VERSION file." >&2; return 1;
    }
    echo "Installing ttui $target (web panel and TrustTunnel tools)."
    if [[ -f $state/panel.json && -f $panel/app.py && -x $panel/venv/bin/python ]]; then
        updating=1
        if [[ -f $panel/VERSION ]]; then
            current=$(cat "$panel/VERSION")
            if dpkg --compare-versions "$target" lt "$current"; then
                echo "Release $target is older than the installed $current." >&2
                return 1
            fi
            if (( newer_only )) && ! dpkg --compare-versions "$target" gt "$current"; then
                echo "The requested release is already installed or older." >&2
                return 1
            fi
        fi
    fi
    if (( newer_only && ! updating )); then
        echo "An existing ttui installation is required." >&2
        return 1
    fi
    if [[ ! $panel_port =~ ^[1-9][0-9]{0,4}$ ]] || (( 10#$panel_port < 1024 || 10#$panel_port > 65535 )); then
        echo "Choose an internal panel port from 1024 to 65535." >&2
        return 2
    fi
    if (( updating && port_set )); then
        echo "Updates keep the existing panel port. Change TTUI_PORT in /etc/default/ttui and the proxy configuration instead." >&2
        return 2
    fi
    if [[ -n $domain && -n $access ]]; then
        echo "Choose one panel access mode." >&2; return 2
    fi
    if (( updating )) && [[ -n $domain || -n $access ]]; then
        echo "Updates preserve the existing access mode. Omit access options when updating." >&2; return 2
    fi
    if (( ! updating )) && [[ -z $access ]]; then
        if [[ -z $domain ]]; then
            echo "Panel HTTPS domain (or rerun with --local for SSH access):" >&2
            if ! read -r domain </dev/tty || [[ -z $domain ]]; then
                echo "Pass --domain HOST, --external-proxy, or --local." >&2; return 2
            fi
        fi
        check_public_domain "$domain"
        packages+=(caddy certbot)
        adding_https=1
    elif [[ $access == external ]]; then
        adding_https=1
    fi
    if [[ ( -e $launcher || -L $launcher ) && $(readlink "$launcher") != "$panel/install.sh" ]]; then
        echo "An unmanaged $launcher already exists." >&2
        return 1
    fi
    if systemctl cat trusttunnel.service >/dev/null 2>&1 \
        && ! grep -Fxq '# Managed by ttui' "$units/trusttunnel.service" 2>/dev/null; then
        echo "An existing unmanaged trusttunnel.service was found. See the migration notes." >&2
        return 1
    fi
    if (( ! updating )) && [[ ! -f "$config/vpn.toml" || ! -f "$config/hosts.toml" ]]; then
        echo "You will configure TrustTunnel in the web panel after signing in."
    fi
    architecture=$(uname -m)
    case "$architecture" in
        x86_64)
            xray_arch=64
            endpoint_sha=29fd330eafab37eb8ab668dcbd57aa8f99b46e26b268e5dc9b416a483fadca97
            client_sha=99e764bb2c080f7a60c441b51ad75fa7ec00e6c8a80afe36030af37201ba32f7
            xray_sha=b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82 ;;
        aarch64)
            xray_arch=arm64-v8a
            endpoint_sha=b82795893d50ea1ffe92fe5712d14282a024e87ee968cca25afdc4cb0aae6238
            client_sha=837ec64520d546cdf8e7a327614589f64dc6c4f30e408e3788de7bfaef05b52b
            xray_sha=64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be ;;
        *) echo "Unsupported architecture: $architecture" >&2; return 1 ;;
    esac
    if (( ! updating )); then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
    fi
    if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))'; then
        echo "Python 3.9 or newer is required." >&2
        return 1
    fi
    if (( ! updating )) && ! check_panel_port "$panel_port"; then
        return 1
    fi
    local work
    work=$(mktemp -d)
    # Capture the path now because work is local to main.
    # shellcheck disable=SC2064
    trap "rm -rf -- $(printf '%q' "$work")" EXIT
    mkdir "$work/endpoint" "$work/client" "$work/xray"
    download "https://github.com/TrustTunnel/TrustTunnel/releases/download/$endpoint_tag/trusttunnel-$endpoint_tag-linux-$architecture.tar.gz" \
        "$endpoint_sha" "$work/endpoint.tar.gz"
    download "https://github.com/TrustTunnel/TrustTunnelClient/releases/download/$client_tag/trusttunnel_client-$client_tag-linux-$architecture.tar.gz" \
        "$client_sha" "$work/client.tar.gz"
    download "https://github.com/XTLS/Xray-core/releases/download/$xray_tag/Xray-linux-$xray_arch.zip" \
        "$xray_sha" "$work/xray.zip"
    tar -xzf "$work/endpoint.tar.gz" -C "$work/endpoint"
    tar -xzf "$work/client.tar.gz" -C "$work/client"
    unzip -q "$work/xray.zip" -d "$work/xray"
    test -f "$source_dir/app.py"
    if (( updating )); then backup_before_update "$source_dir" "$state" "$current"; fi
    (
    if (( updating )); then
        local backup="$work/backup"
        mkdir "$backup"
        cp -a -- "$panel" "$backup/panel"
        for file in "$endpoint" "$sudoers" "${support_units[@]/#/$units/}" "${managed_units[@]/#/$units/}"; do
            if [[ -e $file ]]; then
                (cd / && cp -a --parents -- "${file#/}" "$backup")
            fi
        done
        for unit in ttui-router.service trusttunnel.service ttui.service; do
            if systemctl is-active --quiet "$unit"; then active+=("$unit"); fi
        done
        trap 'finish_update "$?" "$backup" "${active[@]}"' EXIT
        trap 'exit 130' INT
        trap 'exit 143' TERM
    fi
    id ttui >/dev/null 2>&1 || useradd --system --user-group --home-dir "$state" --shell /usr/sbin/nologin ttui
    for directory in "$state" "$config"; do
        if [[ -L $directory ]]; then
            echo "Expected a regular directory at $directory." >&2
            exit 1
        fi
        if [[ ! -d $directory ]]; then install -d -m 0750 -o ttui -g ttui "$directory"; fi
    done
    runuser -u ttui -- mkdir -m 0750 -p -- "$state/geo"
    install -d -m 0755 "$panel" "$panel/xray" "$panel/templates" "$panel/static" /opt/trusttunnel
    install -m 0755 "$(find "$work/endpoint" -type f -name trusttunnel_endpoint -print -quit)" "$endpoint"
    install -m 0755 "$(find "$work/client" -type f -name trusttunnel_client -print -quit)" "$panel/trusttunnel_client"
    install -m 0755 "$work/xray/xray" "$panel/xray/xray"
    for file in geoip.dat geosite.dat; do
        seed_geofile "$state/geo/$file" "$work/xray/$file"
    done
    install -m 0644 "$source_dir/"*.py "$source_dir/"{requirements.txt,VERSION} "$panel/"
    install -m 0755 "$source_dir/install.sh" "$panel/install.sh"
    release_info "$source_dir" >"$panel/release-info.json"
    install -m 0644 "$source_dir"/templates/*.html "$panel/templates/"
    install -m 0644 "$source_dir"/static/* "$panel/static/"
    python3 -m venv "$panel/venv"
    "$panel/venv/bin/python" -m pip install --disable-pip-version-check --no-compile -r "$panel/requirements.txt"
    chmod -R a+rX "$panel/venv"
    install -m 0644 "$source_dir"/systemd/*.service "$units/"
    install -m 0644 "$source_dir"/systemd/*.timer "$units/"
    install -m 0440 "$source_dir/systemd/ttui.sudoers" /etc/sudoers.d/ttui
    visudo -cf /etc/sudoers.d/ttui
    if (( adding_https )); then
        install -d -m 0755 "$units/ttui.service.d"
        printf '[Service]\nEnvironment=TTUI_REQUIRE_HTTPS=1\n' >"$units/ttui.service.d/10-https.conf"
        if [[ -n $domain ]]; then
            printf 'Environment=TTUI_ACME=1\n' >>"$units/ttui.service.d/10-https.conf"
        fi
    fi
    systemctl daemon-reload

    if (( ! updating )); then
        touch /etc/default/ttui
        awk -v port="$panel_port" '!/^TTUI_PORT=/{print} END{print "TTUI_PORT=" port}' \
            /etc/default/ttui >"$work/ttui.default"
        install -m 0644 "$work/ttui.default" /etc/default/ttui
        credentials=$(runuser -u ttui -- env TTUI_STATE="$state" "$panel/venv/bin/python" "$panel/app.py" --init)
        echo
        echo "ttui web panel sign-in"
        if [[ -n $domain ]]; then
            echo "Sign-in URL: https://$domain/ttui/"
        elif [[ $access == external ]]; then
            echo "Point your HTTPS reverse proxy at http://127.0.0.1:$panel_port and open /ttui/ on your HTTPS origin."
        else
            echo "Default sign-in URL: http://127.0.0.1:$panel_port/ttui/"
            echo "Remote access with the default bind: ssh -L $panel_port:127.0.0.1:$panel_port USER@SERVER"
        fi
        runuser -u ttui -- env TTUI_STATE="$state" "$panel/venv/bin/python" "$panel/app.py" --panel-info
        if [[ -n $credentials ]]; then
            echo "Save these administrator credentials (path | username | password):"
            printf '%s\n' "$credentials"
        else
            echo "The existing administrator password was kept."
        fi
        echo "Password reset: sudo -u ttui env TTUI_STATE=$state $panel/venv/bin/python $panel/app.py --reset-login"
        echo
        systemctl enable ttui.service trusttunnel.service
        systemctl restart ttui.service
        wait_service ttui.service
        ln -sfn "$panel/install.sh" "$launcher"
        echo "ttui web panel is running."
        if [[ -n $domain ]]; then start_panel_https "$domain" "$panel_port"; fi
        if [[ -f "$config/vpn.toml" && -f "$config/hosts.toml" ]]; then
            if ! systemctl restart trusttunnel.service || ! wait_service trusttunnel.service; then
                echo "TrustTunnel failed to start. The ttui panel is still running. Check journalctl -u trusttunnel.service." >&2
                exit 1
            fi
        else
            echo "Sign in and open TrustTunnel to create the VPN node."
        fi
    fi
    for unit in "${active[@]}"; do
        systemctl restart "$unit"
        wait_service "$unit"
    done
    ln -sfn "$panel/install.sh" "$launcher"
    systemctl enable --now ttui-metrics.timer ttui-backups.timer
    )
    echo "ttui $target installed."
}

main "$@"
