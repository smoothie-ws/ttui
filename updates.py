"""Official release discovery and the systemd update request."""
import json
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

import backend as b

REPOSITORY = "https://github.com/trusttunnel-ui/ttui-panel"
LATEST = "https://api.github.com/repos/trusttunnel-ui/ttui-panel/releases/latest"
UNIT = "ttui-update.service"
RELEASE_INFO = Path(__file__).with_name("release-info.json")
COMPONENTS = {"endpoint": "TrustTunnel Endpoint", "client": "TrustTunnel Client", "xray": "Xray"}
SEMVER = r"(?:0|[1-9][0-9]{0,5})(?:\.(?:0|[1-9][0-9]{0,5})){2}"
ASSETS = {"ttui.tar.gz", "ttui.tar.gz.sha256", "release-info.json"}
MIN_SPACE = 256 * 1024 * 1024


def version_number(value):
    if not isinstance(value, str) or not re.fullmatch(SEMVER, value):
        raise ValueError("Expected a stable numeric release version.")
    return tuple(map(int, value.split(".")))


def metadata(data, version):
    if not isinstance(data, dict) or data.get("format") != 1 or data.get("version") != version:
        raise ValueError("The release compatibility metadata is missing or invalid.")
    components = data.get("components")
    minimum = data.get("minimum_python")
    if (not isinstance(components, dict) or set(components) != COMPONENTS.keys()
            or any(not isinstance(tag, str) or not re.fullmatch("v" + SEMVER, tag) for tag in components.values())
            or any(not isinstance(data.get(key), list) or any(not isinstance(item, str) for item in data[key])
                   for key in ("systems", "architectures"))
            or not isinstance(minimum, list) or len(minimum) != 2 or any(type(part) is not int or part < 0 for part in minimum)):
        raise ValueError("The release compatibility metadata is invalid.")
    return data


def fetch(url, limit):
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "ttui-update-check"})
    try:
        with urlopen(request, timeout=6) as response:
            data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("The release metadata exceeds the supported size.")
        return json.loads(data)
    except (URLError, OSError, UnicodeError, ValueError) as error:
        raise ValueError("Could not read the official ttui release metadata. Try again later.") from error


def installed_components(version):
    try:
        return metadata(json.loads(b.read(RELEASE_INFO)), version)["components"]
    except (OSError, ValueError):
        return {}


def compatibility(info):
    distro = next((line[3:].strip("\"'") for line in b.read(Path("/etc/os-release"), "").splitlines()
                   if line.startswith("ID=")), "")
    if platform.system() != "Linux" or distro not in info["systems"] or platform.machine() not in info["architectures"]:
        return "This release does not support this operating system or CPU architecture."
    if sys.version_info[:2] < tuple(info["minimum_python"]):
        return "This release requires a newer Python version."
    if any(shutil.disk_usage(path).free < MIN_SPACE for path in (b.STATE, RELEASE_INFO.parent, Path("/tmp"))):
        return "Free at least 256 MiB on the panel, state, and temporary filesystems before updating."
    return None


def latest(installed):
    data = fetch(LATEST, 1024 * 1024)
    if not isinstance(data, dict) or data.get("prerelease") is not False or data.get("draft") is not False:
        raise ValueError("Could not confirm a stable ttui release.")
    tag = data.get("tag_name")
    if not isinstance(tag, str) or not tag.startswith("v"):
        raise ValueError("The latest stable release has an unsupported version.")
    newer = version_number(tag[1:]) > version_number(installed)
    notes = data.get("body") or ""
    release = {"tag": tag, "notes": notes[:24000] if isinstance(notes, str) else "",
               "url": f"{REPOSITORY}/releases/tag/{tag}", "compatible": False, "components": {}, "problem": None}
    if not newer:
        release["problem"] = "This installation is already at or above the latest stable release."
        return release
    items = data.get("assets")
    if not isinstance(items, list):
        raise ValueError("The release asset information is invalid.")
    assets = {asset.get("name") for asset in items if isinstance(asset, dict)
              and isinstance(asset.get("name"), str) and asset.get("state") == "uploaded"}
    if not ASSETS <= assets:
        release["problem"] = "The release is missing the package, checksum, or compatibility metadata."
        return release
    info = metadata(fetch(f"{REPOSITORY}/releases/download/{tag}/release-info.json", 16384), tag[1:])
    release["components"] = info["components"]
    release["problem"] = compatibility(info)
    release["compatible"] = release["problem"] is None
    return release


def request_file():
    return b.STATE / "update-request"


def status():
    try:
        raw = b.command([b.SYSTEMCTL, "show", "-p", "LoadState", "-p", "ActiveState", UNIT], timeout=3)
        values = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        values = {}
    tag = b.read(request_file(), "").strip()
    return {"available": values.get("LoadState") == "loaded", "tag": tag if re.fullmatch("v" + SEMVER, tag) else "",
            "busy": values.get("ActiveState") in ("activating", "active", "deactivating"),
            "failed": values.get("ActiveState") == "failed"}


def queue(tag):
    if not isinstance(tag, str) or not re.fullmatch("v" + SEMVER, tag):
        raise ValueError("Invalid update release version.")
    state = status()
    if not state["available"] or state["busy"]:
        raise ValueError("The updater is unavailable or an update is already running.")
    previous = state["tag"]
    b.atomic(request_file(), tag + "\n")
    try:
        b.command(["/usr/bin/sudo", "-n", b.SYSTEMCTL, "start", "--no-block", UNIT], timeout=5)
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        # Keep a request that systemd accepted before a client-side timeout.
        if not status()["busy"]:
            if previous:
                b.atomic(request_file(), previous + "\n")
            else:
                request_file().unlink(missing_ok=True)
            raise
