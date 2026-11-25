"""Private, checksummed snapshots of ttui configuration."""
import hashlib
import json
import os
import posixpath
import re
import secrets
import stat
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile
from zlib import error as CompressionError

import tomlkit

import auth
import backend as b
import certificates as tls
from routing import DEFAULT_ROUTING, compile_routing

COMPONENTS = {"panel": "Panel settings", "endpoint": "Endpoint and managed TLS files",
              "clients": "Client credentials and profiles", "routing": "Routing", "geo": "Geodata"}
NAME = re.compile(r"ttui-\d{8}T\d{6}Z-[a-f0-9]{12}(?:-auto)?\.zip")
MANIFEST = "manifest.json"
MAX_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE = MAX_BYTES + 1024 * 1024
MAX_FILES = 256
MAX_MANIFEST = 256 * 1024
BLOCK_SIZE = 128 * 1024
TEXT_LIMIT = 32 * 1024 * 1024
HOST_GROUPS = ("main_hosts", "ping_hosts", "speedtest_hosts", "reverse_proxy_hosts")
INTERVALS = {"off": ("Off", 0), "daily": ("Daily", 1), "weekly": ("Weekly", 7)}
SCHEDULED_RETENTION = 7


def location():
    root = b.STATE / "backups"
    root.mkdir(mode=0o700, exist_ok=True)
    if root.is_symlink() or (os.name == "posix" and stat.S_IMODE(root.stat().st_mode) & 0o077):
        raise ValueError("The backup directory must be a local directory with private permissions (0700).")
    return root


def archive_path(name):
    if not NAME.fullmatch(name):
        raise ValueError("Invalid backup name.")
    path = location() / name
    if path.is_symlink() or not path.is_file():
        raise ValueError("Backup is unavailable.")
    return path


def sources(selected):
    files = {}

    def include(path, root, prefix):
        path = path.resolve()
        if not path.is_relative_to(root):
            return
        if path.is_file():
            files[f"{prefix}/{path.relative_to(root).as_posix()}"] = path

    if "panel" in selected:
        include(b.STATE / "panel.json", b.STATE, "state")
    vpn = {}
    if {"endpoint", "clients"} & selected:
        vpn = tomlkit.parse(b.read(b.VPN, ""))
    if "endpoint" in selected:
        include(b.VPN, b.CONFIG, "config")
        include(b.HOSTS, b.CONFIG, "config")
        include(b.LAUNCH, b.STATE, "state")
        include(b.STATE / "tls-history.json", b.STATE, "state")
        include(b.related(vpn)[1], b.CONFIG, "config")
        hosts = tomlkit.parse(b.read(b.HOSTS, ""))
        for _, paths in host_files(hosts):
            for path in paths:
                include(path, b.CONFIG, "config")
    if "clients" in selected:
        credentials, _ = b.related(vpn)
        include(credentials, b.CONFIG, "config")
        profiles = b.STATE / "clients.json"
        include(profiles, b.STATE, "state")
        for path in json.loads(b.read(profiles, "{}")):
            include(b.managed_path(path, "credentials.toml"), b.CONFIG, "config")
    if "routing" in selected:
        include(b.ROUTING, b.STATE, "state")
    if "geo" in selected:
        for name in ("geoip.dat", "geosite.dat"):
            include(b.GEO / name, b.STATE, "state")
    return files


def host_files(hosts):
    for group in HOST_GROUPS:
        entries = hosts.get(group, [])
        if not isinstance(entries, list) or any(not isinstance(host, dict) for host in entries):
            raise ValueError("TLS hosts must use separate host tables.")
        for host in entries:
            values = [host.get(key, "") for key in ("cert_chain_path", "private_key_path")]
            if any(not isinstance(value, str) for value in values):
                raise ValueError("TLS certificates and keys must use file paths.")
            yield host.get("hostname", ""), [(b.CONFIG / value).resolve() for value in values if value]


def archive_name(now, scheduled=False):
    suffix = "-auto" if scheduled else ""
    return f"ttui-{now:%Y%m%dT%H%M%SZ}-{secrets.token_hex(6)}{suffix}.zip"


def digest(stream, destination=None, allowance=MAX_BYTES):
    checksum = hashlib.sha256()
    size = 0
    while block := stream.read(BLOCK_SIZE):
        size += len(block)
        if size > allowance:
            raise ValueError("Backup exceeds the supported size.")
        checksum.update(block)
        if destination is not None:
            destination.write(block)
    return {"size": size, "sha256": checksum.hexdigest()}


def selection(selected):
    selected = set(selected)
    if not selected or selected - COMPONENTS.keys():
        raise ValueError("Select at least one valid backup component.")
    return selected


def create(selected, version, reason="manual"):
    selected = selection(selected)
    files = sources(selected)
    if not files or len(files) > MAX_FILES:
        raise ValueError("The selected components contain no files or exceed the supported file count.")
    now = datetime.now(timezone.utc)
    name = archive_name(now, scheduled=reason == "scheduled")
    root = location()
    manifest = {"format": 1, "version": version, "created": now.isoformat(timespec="seconds"), "reason": reason,
                "components": sorted(selected), "files": {}}
    if "endpoint" in selected:
        hosts = tomlkit.parse(b.read(b.HOSTS, ""))
        external = sorted({str(path) for _, paths in host_files(hosts) for path in paths
                           if not path.is_relative_to(b.CONFIG)})
        if external:
            manifest["external_tls_files"] = external
    remaining = MAX_BYTES
    with NamedTemporaryFile(dir=root, prefix=".snapshot-", delete=False) as output:
        temporary = Path(output.name)
        try:
            with ZipFile(output, "w", compression=ZIP_DEFLATED, compresslevel=3) as archive:
                for member, path in sorted(files.items()):
                    with path.open("rb") as stream, archive.open(member, "w") as entry:
                        details = digest(stream, entry, remaining)
                    manifest["files"][member] = details
                    remaining -= details["size"]
                certbot = b.STATE / "acme" / "config"
                if "endpoint" in selected and (certbot.is_symlink() or certbot.exists() and not certbot.is_dir()):
                    raise ValueError("Certbot configuration must be a local directory.")
                if "endpoint" in selected and certbot.is_dir() and not certbot.is_symlink():
                    total = 0
                    count = 0

                    def walk_error(error):
                        raise error

                    for directory, folders, names in os.walk(certbot, followlinks=False, onerror=walk_error):
                        for entry_name in folders + names:
                            path = Path(directory) / entry_name
                            info = path.lstat()
                            count += 1
                            if stat.S_ISREG(info.st_mode):
                                total += info.st_size
                            elif stat.S_ISLNK(info.st_mode):
                                link = os.readlink(path)
                                if os.path.isabs(link) or not path.resolve().is_relative_to(certbot.resolve()):
                                    raise ValueError("Certbot configuration contains a symbolic link outside its directory.")
                            elif not stat.S_ISDIR(info.st_mode):
                                raise ValueError("Certbot configuration contains an unsupported file type.")
                            if count > 10000 or total > remaining:
                                raise ValueError("Certbot configuration exceeds the supported size or file count.")
                    with TemporaryDirectory(dir=root, prefix=".certbot-") as directory:
                        snapshot = Path(directory) / "config.tar.gz"
                        with tarfile.open(snapshot, "w:gz", dereference=False, errorlevel=2) as tar:
                            tar.add(certbot, arcname="config")
                        validate_certbot_archive(snapshot)
                        member = "state/certbot-config.tar.gz"
                        with snapshot.open("rb") as stream, archive.open(member, "w") as entry:
                            details = digest(stream, entry, remaining)
                        manifest["files"][member] = details
                        manifest["certbot_manual_restore"] = True
                        certbot_root = certbot.resolve()
                        external = [value for value in manifest.get("external_tls_files", [])
                                    if not Path(value).is_relative_to(certbot_root)]
                        if external:
                            manifest["external_tls_files"] = external
                        else:
                            manifest.pop("external_tls_files", None)
                metadata = json.dumps(manifest, indent=2).encode("utf-8")
                if len(metadata) > MAX_MANIFEST:
                    raise ValueError("Backup manifest exceeds the supported size.")
                archive.writestr(MANIFEST, metadata)
            output.close()
            temporary.replace(root / name)
        finally:
            output.close()
            temporary.unlink(missing_ok=True)
    return name


def read_manifest(archive):
    entries = archive.infolist()
    if len(entries) > MAX_FILES + 1 or archive.getinfo(MANIFEST).file_size > MAX_MANIFEST:
        raise ValueError("Backup manifest exceeds the supported size.")
    data = json.loads(archive.read(MANIFEST))
    if not isinstance(data, dict) or data.get("format") != 1 or not isinstance(data.get("files"), dict):
        raise ValueError("Unsupported backup manifest.")
    if set(archive.namelist()) != {*data["files"], MANIFEST} or len(entries) != len(data["files"]) + 1:
        raise ValueError("Backup entries do not match the manifest.")
    for name in data["files"]:
        parts = name.split("/")
        if (len(parts) < 2 or parts[0] not in ("config", "state")
                or any(part in ("", ".", "..") or any(char in part for char in "\\:\0") for part in parts)):
            raise ValueError("The backup contains an invalid file path.")
    components = data.get("components")
    if (not isinstance(components, list) or not components
            or any(not isinstance(item, str) or item not in COMPONENTS for item in components)
            or not all(isinstance(data.get(key), str) for key in ("version", "created"))):
        raise ValueError("Backup metadata is invalid.")
    external = data.get("external_tls_files", [])
    if (not isinstance(external, list) or len(external) > MAX_FILES
            or any(not isinstance(path, str) or len(path) > 4096 for path in external)):
        raise ValueError("Backup TLS metadata is invalid.")
    certbot_member = "state/certbot-config.tar.gz"
    certbot_present = certbot_member in data["files"]
    if (data.get("certbot_manual_restore", False) is not certbot_present
            or certbot_present and "endpoint" not in components):
        raise ValueError("Backup Certbot metadata is invalid.")
    if sum(entry.file_size for entry in entries if entry.filename != MANIFEST) > MAX_BYTES:
        raise ValueError("Backup exceeds the supported size.")
    return data


def verify_file(path, stage=None):
    staged = {}
    try:
        with ZipFile(path) as archive:
            manifest = read_manifest(archive)
            remaining = MAX_BYTES
            for index, (member, expected) in enumerate(manifest["files"].items()):
                with archive.open(member) as stream:
                    if stage is None:
                        actual = digest(stream, allowance=remaining)
                    else:
                        staged[member] = stage / str(index)
                        with staged[member].open("xb") as output:
                            actual = digest(stream, output, remaining)
                if actual != expected:
                    raise ValueError("Backup checksums do not match the manifest.")
                remaining -= actual["size"]
            if manifest.get("certbot_manual_restore"):
                member = "state/certbot-config.tar.gz"
                if stage is not None:
                    validate_certbot_archive(staged[member])
                else:
                    with TemporaryDirectory(dir=location(), prefix=".certbot-check-") as directory:
                        temporary = Path(directory) / "config.tar.gz"
                        with archive.open(member) as source, temporary.open("xb") as output:
                            digest(source, output)
                        validate_certbot_archive(temporary)
    except (BadZipFile, CompressionError, KeyError, UnicodeError, NotImplementedError) as error:
        raise ValueError("The backup archive is damaged or unsupported.") from error
    return manifest, staged


def validate_certbot_archive(path):
    try:
        with tarfile.open(path, "r:gz") as archive:
            total = 0
            seen = set()
            links = set()
            for index, member in enumerate(archive):
                parts = member.name.split("/")
                if (index >= 10000 or parts[0] != "config" or any(part in ("", ".", "..") for part in parts)
                        or any("\\" in part or ":" in part for part in parts)
                        or member.name in seen
                        or member.name == "config" and not member.isdir()
                        or not (member.isdir() or member.isfile() or member.issym())):
                    raise ValueError("Invalid Certbot archive entry.")
                seen.add(member.name)
                total += member.size
                if total > MAX_BYTES:
                    raise ValueError("Certbot archive exceeds the supported size.")
                if member.issym():
                    target = member.linkname
                    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(member.name), target))
                    if (posixpath.isabs(target) or "\\" in target or ":" in target
                            or not resolved.startswith("config/")):
                        raise ValueError("Invalid Certbot archive symbolic link.")
                    links.add(member.name)
            for name in seen:
                parts = name.split("/")
                if any("/".join(parts[:index]) in links for index in range(1, len(parts))):
                    raise ValueError("Certbot archive entries cannot be nested under symbolic links.")
            if "config" not in seen:
                raise ValueError("Certbot archive is missing its configuration directory.")
    except (tarfile.TarError, OSError, EOFError, CompressionError) as error:
        raise ValueError("The Certbot archive is damaged.") from error


def verify(name):
    verify_file(archive_path(name))


def import_archive(stream):
    root = location()
    name = archive_name(datetime.now(timezone.utc))
    with NamedTemporaryFile(dir=root, prefix=".import-", delete=False) as output:
        temporary = Path(output.name)
        try:
            digest(stream, output, MAX_ARCHIVE)
            output.close()
            verify_file(temporary)
            temporary.replace(root / name)
        finally:
            output.close()
            temporary.unlink(missing_ok=True)
    return name


def destinations(staged):
    changes = {}
    for name, source in staged.items():
        prefix, member = name.split("/", 1)
        root = b.CONFIG if prefix == "config" else b.STATE
        target = root / member
        if target != target.resolve() or target in changes or not target.is_relative_to(root):
            raise ValueError("A backup destination is duplicated or passes through a symbolic link.")
        changes[target] = source
    return changes


def validate_restore(changes, components, current, client_address=None):
    def read(path, default=""):
        source = changes.get(path, path)
        if isinstance(source, str):
            return source
        if source.is_file() and source.stat().st_size > TEXT_LIMIT:
            raise ValueError("A configuration file in the restore exceeds 32 MiB.")
        return b.read(source, default)

    panel, profiles = b.STATE / "panel.json", b.STATE / "clients.json"
    allowed = set()
    new_path = None
    if "panel" in components:
        allowed.add(panel)
        if panel in changes:
            config = json.loads(read(panel))
            if (not isinstance(config, dict) or not all(isinstance(config.get(key), str)
                    for key in ("path", "username", "password_hash", "address"))
                    or not re.fullmatch(r"(?:/[A-Za-z0-9_-]+)*", config["path"])
                    or not 0 < len(config["username"]) <= 64
                    or not re.fullmatch(r"(?:scrypt|pbkdf2):[^$]+\$[^$]+\$[0-9a-f]+", config["password_hash"])
                    or type(config.get("secure_cookie")) is not bool):
                raise ValueError("The archive contains invalid panel settings.")
            if "totp_secret" in config and not auth.valid_totp_secret(config["totp_secret"]):
                raise ValueError("The archive contains an invalid authenticator secret.")
            networks = auth.normalize_networks(config.get("ip_allowlist", []))
            if client_address is not None and not auth.address_allowed(networks, client_address):
                raise ValueError("The archived allowlist excludes your current IP address.")
            if "ip_allowlist" in config:
                config["ip_allowlist"] = networks
            new_path = config["path"]
            config.update(secret=current["secret"], session_epoch=secrets.token_hex(16))
            changes[panel] = json.dumps(config)
    if "routing" in components:
        allowed.add(b.ROUTING)
        changes.setdefault(b.ROUTING, json.dumps(DEFAULT_ROUTING))
    if "geo" in components:
        allowed.update((b.GEO / "geoip.dat", b.GEO / "geosite.dat"))
    routing_changed = bool((allowed - {panel}) & changes.keys())
    if not ({"endpoint", "clients"} & components or routing_changed):
        if changes.keys() - allowed:
            raise ValueError("The archive includes files outside its selected components.")
        return new_path, False, False, None

    vpn_raw, hosts_raw = read(b.VPN), read(b.HOSTS)
    vpn, hosts = tomlkit.parse(vpn_raw), tomlkit.parse(hosts_raw)
    credentials, rules = b.related(vpn)
    if "endpoint" in components:
        history = b.STATE / "tls-history.json"
        allowed.update((b.VPN, b.HOSTS, b.LAUNCH, rules, history))
        pairs = list(host_files(hosts))
        for _, paths in pairs:
            allowed.update(path for path in paths if path.is_relative_to(b.CONFIG))
        if b.LAUNCH in changes:
            options = json.loads(read(b.LAUNCH))
            if not isinstance(options, dict) or any(not isinstance(value, str) for value in options.values()):
                raise ValueError("The archive contains invalid Endpoint startup options.")
            b.endpoint_command(options)
        if history in changes and not isinstance(json.loads(read(history)), list):
            raise ValueError("The archive contains invalid TLS history.")
    if "clients" in components:
        allowed.update((credentials, profiles))
        changes.setdefault(profiles, "{}")
        data = json.loads(read(profiles, "{}"))
        if not isinstance(data, dict) or any(not isinstance(profile, dict) for profile in data.values()):
            raise ValueError("The archive contains invalid client profiles.")
        allowed.update(b.managed_path(path, "credentials.toml") for path in data)
    if changes.keys() - allowed:
        raise ValueError("The archive includes files outside its selected components or references a different Endpoint configuration.")

    endpoint_changed = any(path.is_relative_to(b.CONFIG) or path == b.LAUNCH for path in changes)
    if endpoint_changed:
        if not vpn_raw or not hosts_raw:
            raise ValueError("Restore the Endpoint configuration together with its credentials and TLS files.")
        b.check_clients(vpn, read(credentials))
        if vpn.get("rules_file") and rules not in changes and not rules.is_file():
            raise ValueError("The restored Endpoint rules file is missing.")
        if "endpoint" in components:
            for host, paths in pairs:
                if not paths:
                    continue
                if not isinstance(host, str) or len(paths) != 2:
                    raise ValueError("Restore both the certificate and key for each TLS hostname.")
                tls.validate(*(changes.get(path, path) for path in paths), tls.hostname(host))
    spec = json.loads(read(b.ROUTING, json.dumps(DEFAULT_ROUTING)))
    config, _ = compile_routing(spec)
    if spec["enabled"] and vpn.get("forward_protocol") != b.ROUTER_FORWARD:
        raise ValueError("Restore a matching Endpoint configuration and routing snapshot together.")
    if (not spec["enabled"] and b.ROUTING in changes and b.VPN not in changes
            and vpn.get("forward_protocol") == b.ROUTER_FORWARD and b.load_routing()["enabled"]):
        raise ValueError("The Endpoint expects ttui routing. Restore the matching routing snapshot.")
    return new_path, endpoint_changed, routing_changed, config if spec["enabled"] else None


def restore(name, current, client_address=None):
    with TemporaryDirectory(dir=location(), prefix=".restore-") as directory:
        manifest, staged = verify_file(archive_path(name), Path(directory))
        staged.pop("state/certbot-config.tar.gz", None)
        changes = destinations(staged)
        result = validate_restore(changes, set(manifest["components"]), current, client_address)
        path, endpoint_changed, routing_changed, config = result
        runtime_changed = endpoint_changed or routing_changed
        endpoint_active = runtime_changed and b.service_state(b.ENDPOINT_UNIT) == "active"
        router_active = runtime_changed and b.service_state(b.ROUTER_UNIT) == "active"
        start_endpoint = endpoint_changed and (endpoint_active or (b.VPN in changes and b.HOSTS in changes))
        touched = set()

        def switch(action, unit):
            touched.add(unit)
            b.service(action, unit)
            if action == "restart" and unit == b.ENDPOINT_UNIT:
                b.active_endpoint()

        def apply():
            if config is not None and runtime_changed:
                b.validate_xray(config)
                if (routing_changed and (router_active or endpoint_active)) or start_endpoint:
                    switch("restart", b.ROUTER_UNIT)
            if start_endpoint:
                switch("restart", b.ENDPOINT_UNIT)
            if config is None and routing_changed and router_active:
                switch("stop", b.ROUTER_UNIT)

        def recover():
            if b.ROUTER_UNIT in touched and router_active:
                switch("restart", b.ROUTER_UNIT)
            if b.ENDPOINT_UNIT in touched:
                switch("restart" if endpoint_active else "stop", b.ENDPOINT_UNIT)
            if b.ROUTER_UNIT in touched and not router_active:
                switch("stop", b.ROUTER_UNIT)

        for target in changes:
            if target != target.resolve():
                raise ValueError("A backup destination passes through a symbolic link.")
        for target in changes:
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        b.change_files(changes, apply, recover)
    return path


def history():
    rows = []
    for path in sorted(location().glob("ttui-*.zip"), reverse=True):
        if not NAME.fullmatch(path.name) or path.is_symlink() or not path.is_file():
            continue
        try:
            with ZipFile(path) as archive:
                data = read_manifest(archive)
        except (OSError, ValueError, RuntimeError, BadZipFile, CompressionError, KeyError):
            data = None
        rows.append((path.name, data))
    return rows


def load_schedule():
    default = {"interval": "off", "components": list(COMPONENTS), "next": None}
    try:
        config = json.loads(b.read(b.STATE / "backup-schedule.json", "{}"))
        if config:
            if not isinstance(config, dict) or config.get("interval") not in INTERVALS:
                raise ValueError("Invalid interval")
            selection(config["components"])
            if config["interval"] != "off" and not datetime.fromisoformat(config["next"]).tzinfo:
                raise ValueError("Invalid due date")
            return config
    except (ValueError, TypeError, KeyError):
        default["error"] = "The backup schedule is invalid. Save a new schedule to resume automatic backups."
    return default


def schedule(interval, components, now=None):
    if interval not in INTERVALS:
        raise ValueError("Select a supported backup interval.")
    days = INTERVALS[interval][1]
    selected = sorted(selection(components)) if days else list(COMPONENTS)
    now = datetime.now(timezone.utc) if now is None else now
    due = (now + timedelta(days=days)).isoformat(timespec="seconds") if days else None
    b.write_json(b.STATE / "backup-schedule.json", {"interval": interval, "components": selected, "next": due})


def run_scheduled(version, now=None):
    config = load_schedule()
    if config["interval"] == "off":
        return
    now = datetime.now(timezone.utc) if now is None else now
    if now < datetime.fromisoformat(config["next"]):
        return
    try:
        name = create(config["components"], version, reason="scheduled")
    except (OSError, ValueError, tomlkit.exceptions.ParseError):
        config["error"] = "The last scheduled backup failed. Check the ttui backup service journal."
        b.write_json(b.STATE / "backup-schedule.json", config)
        raise
    days = INTERVALS[config["interval"]][1]
    config.update(last=name, next=(now + timedelta(days=days)).isoformat(timespec="seconds"))
    config.pop("error", None)
    b.write_json(b.STATE / "backup-schedule.json", config)
    scheduled = [archive for archive, data in history() if archive.endswith("-auto.zip")]
    for archive in scheduled[SCHEDULED_RETENTION:]:
        archive_path(archive).unlink()
