#!/usr/bin/env bash
set -euo pipefail

repository=https://github.com/smoothie-ws/ttui
panel=/opt/ttui
endpoint=/opt/trusttunnel/trusttunnel_endpoint
units=/etc/systemd/system
sudoers=/etc/sudoers.d/ttui
launcher=/usr/local/bin/ttui
managed_units=(ttui.service trusttunnel.service ttui-router.service)

fetch_release() (
    local version=$1 work base digest filename extra
    shift
    if [[ $version == latest ]]; then
        base="$repository/releases/latest/download"
    elif [[ $version =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
        base="$repository/releases/download/$version"
    else
        echo "Expected latest or a release such as v0.1.0." >&2
        exit 2
    fi
    work=$(mktemp -d)
    trap 'rm -rf -- "$work"' EXIT
    curl -fLSs --retry 3 "$base/ttui.tar.gz" -o "$work/ttui.tar.gz"
    curl -fLSs --retry 3 "$base/ttui.tar.gz.sha256" -o "$work/ttui.tar.gz.sha256"
    read -r digest filename extra < "$work/ttui.tar.gz.sha256"
    filename=${filename#\*}
    if [[ ! $digest =~ ^[a-f0-9]{64}$ || $filename != ttui.tar.gz || -n $extra ]]; then
        echo "Invalid release checksum." >&2
        exit 1
    fi
    printf '%s *%s\n' "$digest" "$work/ttui.tar.gz" | sha256sum --check --status
    mkdir "$work/source"
    tar -xzf "$work/ttui.tar.gz" -C "$work/source"
    if [[ $version != latest && "v$(cat "$work/source/VERSION")" != "$version" ]]; then
        echo "Release asset version mismatch." >&2
        exit 1
    fi
    bash "$work/source/install.sh" --source "$work/source" "$@"
)

download() {
    local url=$1 digest=$2 target=$3
    curl -fLSs --retry 3 "$url" -o "$target"
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
    for file in "$endpoint" "$sudoers" "${managed_units[@]/#/$units/}"; do
        if [[ -e $backup/$file ]]; then
            cp -a -- "$backup/$file" "$file" || failed=1
        else
            rm -f -- "$file" || failed=1
        fi
    done
    systemctl daemon-reload || failed=1
    for unit in "$@"; do
        if ! systemctl start "$unit" || ! wait_service "$unit"; then failed=1; fi
    done
    return "$failed"
}

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
    local source_dir='' panel_only=0 version=latest allow_downgrade=0 updating=0 target current
    local architecture xray_arch endpoint_sha client_sha xray_sha
    local config=/etc/trusttunnel state=/var/lib/ttui
    local endpoint_tag=v1.3.1 client_tag=v1.3.0 xray_tag=v26.11.9
    local -a forwarded=() active=()
    local unit file directory
    if [[ ${1:-} == version || ( $# == 1 && ${1:-} == --version ) ]]; then
        if [[ -r $panel/VERSION ]]; then cat "$panel/VERSION"; else echo "ttui version unavailable." >&2; return 1; fi
        return
    fi
    if [[ ${1:-} == update ]]; then shift; fi
    while (( $# )); do
        case "$1" in
            --source) source_dir=$(realpath "${2:?Missing source directory}"); shift ;;
            --version) version=${2:?Missing release version}; shift ;;
            --panel-only) panel_only=1; forwarded+=(--panel-only) ;;
            --allow-downgrade) allow_downgrade=1; forwarded+=(--allow-downgrade) ;;
            *) echo "Usage: ttui [update] [--version vX.Y.Z | --source DIR] [--panel-only] [--allow-downgrade]" >&2; return 2 ;;
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
    [[ $target =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
        echo "Invalid VERSION file." >&2; return 1;
    }
    if [[ -f $state/panel.json && -f $panel/app.py && -x $panel/venv/bin/python ]]; then
        updating=1
        if [[ -f $panel/VERSION ]]; then
            current=$(cat "$panel/VERSION")
            if (( ! allow_downgrade )) && dpkg --compare-versions "$target" lt "$current"; then
                echo "Downgrade from $current to $target requires --allow-downgrade." >&2
                return 1
            fi
        fi
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
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            ca-certificates curl python3 python3-venv sudo unzip util-linux
    fi
    if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))'; then
        echo "Python 3.9 or newer is required." >&2
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
    (
    if (( updating )); then
        local backup="$work/backup"
        mkdir "$backup"
        cp -a -- "$panel" "$backup/panel"
        for file in "$endpoint" "$sudoers" "${managed_units[@]/#/$units/}"; do
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
    install -m 0644 "$source_dir/"{app.py,backend.py,routing.py,requirements.txt,VERSION} "$panel/"
    install -m 0755 "$source_dir/install.sh" "$panel/install.sh"
    install -m 0644 "$source_dir"/templates/*.html "$panel/templates/"
    install -m 0644 "$source_dir"/static/* "$panel/static/"
    python3 -m venv "$panel/venv"
    "$panel/venv/bin/python" -m pip install --disable-pip-version-check -r "$panel/requirements.txt"
    chmod -R a+rX "$panel/venv"
    install -m 0644 "$source_dir"/systemd/*.service "$units/"
    install -m 0440 "$source_dir/systemd/ttui.sudoers" /etc/sudoers.d/ttui
    visudo -cf /etc/sudoers.d/ttui
    systemctl daemon-reload

    if (( ! updating && ! panel_only )) && [[ ! -e "$config/vpn.toml" && ! -e "$config/hosts.toml" ]]; then
        if ( : </dev/tty ) 2>/dev/null; then
            (
                cd "$config"
                umask 077
                setpriv --reuid ttui --regid ttui --init-groups --inh-caps +net_bind_service \
                    --ambient-caps +net_bind_service "$endpoint" --setup-wizard \
                    --lib-settings vpn.toml --hosts-settings hosts.toml </dev/tty
            )
        else
            echo "No terminal for the TrustTunnel wizard. Configure the endpoint via the Server tab."
        fi
    fi
    if (( ! updating )); then
        runuser -u ttui -- env TTUI_STATE="$state" "$panel/venv/bin/python" "$panel/app.py" --init
        systemctl enable ttui.service trusttunnel.service
        active=(ttui.service)
        if [[ -f "$config/vpn.toml" && -f "$config/hosts.toml" ]]; then
            active+=(trusttunnel.service)
        fi
    fi
    for unit in "${active[@]}"; do
        systemctl restart "$unit"
        wait_service "$unit"
    done
    ln -sfn "$panel/install.sh" "$launcher"
    )
    echo "ttui $target installed."
    if (( ! updating )); then
        echo "Default panel address: http://127.0.0.1:8080/ttui/"
        echo "Remote access: ssh -L 8080:127.0.0.1:8080 USER@SERVER"
    fi
}

main "$@"
