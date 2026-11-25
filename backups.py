"""Private, checksummed snapshots of ttui configuration."""
import hashlib
import json
import os
import re
import secrets
import stat
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile

import tomlkit

import backend as b

COMPONENTS = {"panel": "Panel settings", "endpoint": "Endpoint and managed TLS files",
              "clients": "Client credentials and profiles", "routing": "Routing", "geo": "Geodata"}
NAME = re.compile(r"ttui-\d{8}T\d{6}Z-[a-f0-9]{12}\.zip")
MANIFEST = "manifest.json"
MAX_BYTES = 512 * 1024 * 1024
MAX_FILES = 256
MAX_MANIFEST = 256 * 1024
BLOCK_SIZE = 128 * 1024


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
        include(b.related(vpn)[1], b.CONFIG, "config")
        hosts = tomlkit.parse(b.read(b.HOSTS, ""))
        for group in ("main_hosts", "ping_hosts", "speedtest_hosts", "reverse_proxy_hosts"):
            entries = hosts.get(group, [])
            if not isinstance(entries, list) or any(not isinstance(host, dict) for host in entries):
                raise ValueError("Check the TLS host configuration before creating an endpoint backup.")
            for host in entries:
                for key in ("cert_chain_path", "private_key_path"):
                    if value := host.get(key):
                        if not isinstance(value, str):
                            raise ValueError("TLS certificates and keys must use file paths.")
                        include(b.CONFIG / value, b.CONFIG, "config")
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


def create(selected, version):
    selected = set(selected)
    if not selected or selected - COMPONENTS.keys():
        raise ValueError("Select at least one valid backup component.")
    files = sources(selected)
    if not files or len(files) > MAX_FILES:
        raise ValueError("The selected components contain no files or exceed the supported file count.")
    now = datetime.now(timezone.utc)
    name = f"ttui-{now:%Y%m%dT%H%M%SZ}-{secrets.token_hex(6)}.zip"
    root = location()
    manifest = {"format": 1, "version": version, "created": now.isoformat(timespec="seconds"),
                "components": sorted(selected), "files": {}}
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
    components = data.get("components")
    if (not isinstance(components, list) or not components
            or any(not isinstance(item, str) or item not in COMPONENTS for item in components)
            or not all(isinstance(data.get(key), str) for key in ("version", "created"))):
        raise ValueError("Backup metadata is invalid.")
    if sum(entry.file_size for entry in entries if entry.filename != MANIFEST) > MAX_BYTES:
        raise ValueError("Backup exceeds the supported size.")
    return data


def verify(name):
    try:
        with ZipFile(archive_path(name)) as archive:
            manifest = read_manifest(archive)
            remaining = MAX_BYTES
            for member, expected in manifest["files"].items():
                with archive.open(member) as stream:
                    actual = digest(stream, allowance=remaining)
                if actual != expected:
                    raise ValueError("Backup checksums do not match the manifest.")
                remaining -= actual["size"]
    except (BadZipFile, KeyError, UnicodeError, NotImplementedError) as error:
        raise ValueError("The backup archive is damaged or unsupported.") from error


def history():
    rows = []
    for path in sorted(location().glob("ttui-*.zip"), reverse=True):
        if not NAME.fullmatch(path.name) or path.is_symlink() or not path.is_file():
            continue
        try:
            with ZipFile(path) as archive:
                data = read_manifest(archive)
        except (OSError, ValueError, RuntimeError, BadZipFile, KeyError, NotImplementedError):
            data = None
        rows.append((path.name, data))
    return rows
