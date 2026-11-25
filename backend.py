"""TrustTunnel files, native export, and systemd integration."""
import json
from ipaddress import ip_address
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from threading import RLock

import tomlkit

from routing import DEFAULT_ROUTING, ROUTER_ADDRESS, compile_routing, xray_env

LOCK = RLock()
ROUTER_FORWARD = {"socks5": {"address": ROUTER_ADDRESS, "extended_auth": False}}
STATE = Path(os.environ.get("TTUI_STATE", ".ttui")).resolve()
CONFIG = Path(os.environ.get("TTUI_CONFIG", "/etc/trusttunnel")).resolve()
ENDPOINT = os.environ.get("TTUI_ENDPOINT", "/opt/trusttunnel/trusttunnel_endpoint")
XRAY = os.environ.get("TTUI_XRAY", "/opt/ttui/xray/xray")
VPN, HOSTS, ROUTING = CONFIG / "vpn.toml", CONFIG / "hosts.toml", STATE / "routing.json"
LAUNCH = STATE / "endpoint.json"
GEO = STATE / "geo"
ENDPOINT_UNIT, ROUTER_UNIT = "trusttunnel.service", "ttui-router.service"
SYSTEMCTL = os.environ.get("TTUI_SYSTEMCTL", "/usr/bin/systemctl")


def read(path, default=None):
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if default is None:
            raise
        return default


def atomic(path, data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as file:
        temporary = Path(file.name)
        try:
            if isinstance(data, bytes):
                file.write(data)
            else:
                shutil.copyfileobj(data, file, length=128 * 1024)
            file.close()
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def write_json(path, value):
    atomic(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def command(args, **kwargs):
    result = subprocess.run(args, text=True, encoding="utf-8", errors="replace",
                            capture_output=True, timeout=kwargs.pop("timeout", 20), **kwargs)
    if result.returncode:
        message = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(message[-2500:] or f"Command exited with code {result.returncode}.")
    return result.stdout


def service(action, unit):
    command(["/usr/bin/sudo", "-n", SYSTEMCTL, action, unit], timeout=90)


def service_state(unit):
    try:
        return command([SYSTEMCTL, "is-active", unit], timeout=3).strip()
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        return "inactive"


def active_endpoint():
    args = [SYSTEMCTL, "show", "-p", "MainPID", "-p", "ActiveState", ENDPOINT_UNIT]
    initial = set(command(args, timeout=3).splitlines())
    if "ActiveState=active" in initial and any(re.fullmatch(r"MainPID=[1-9][0-9]*", item) for item in initial):
        time.sleep(2)
        if initial == set(command(args, timeout=3).splitlines()):
            return
    raise RuntimeError("TrustTunnel exited during startup. Check journalctl -u trusttunnel.")


def managed_path(value, fallback):
    if not isinstance(value if value is not None else fallback, str):
        raise ValueError("The configuration path must be a string.")
    path = (CONFIG / (value or fallback)).resolve()
    if not path.is_relative_to(CONFIG) or path in (CONFIG, VPN, HOSTS):
        raise ValueError("Client credentials and connection filter files must be inside the TrustTunnel configuration directory.")
    return path


def related(vpn):
    credentials = managed_path(vpn.get("credentials_file"), "credentials.toml")
    rules = managed_path(vpn.get("rules_file"), "rules.toml")
    if credentials == rules:
        raise ValueError("Client credentials and connection filters must use separate files.")
    return credentials, rules


def clients(document):
    entries = document.get("client", [])
    if not isinstance(entries, list):
        raise ValueError("Use a separate [[client]] table for each client.")
    names = set()
    for entry in entries:
        if (not isinstance(entry, dict) or not all(isinstance(entry.get(key), str) and entry[key]
                                                  for key in ("username", "password"))):
            raise ValueError("Each client must have a username and password.")
        if entry["username"] in names:
            raise ValueError("Client usernames must be unique.")
        names.add(entry["username"])
    return entries


def loopback(vpn):
    try:
        host, port = vpn.get("listen_address", "").rsplit(":", 1)
        return port.isascii() and port.isdecimal() and ip_address(host.strip("[]")).is_loopback
    except (AttributeError, ValueError):
        return False


def configured_clients(vpn, raw=None):
    if not vpn.get("credentials_file"):
        return []
    return clients(tomlkit.parse(read(related(vpn)[0], "") if raw is None else raw))


def check_clients(vpn, raw=None):
    if not configured_clients(vpn, raw) and not loopback(vpn):
        raise ValueError("An endpoint listening outside loopback requires credentials_file and at least one client.")


def load_routing():
    return json.loads(read(ROUTING, json.dumps(DEFAULT_ROUTING)))


def launch_options():
    return json.loads(read(LAUNCH, "{}"))


def endpoint_command(options):
    command_line = [ENDPOINT, str(VPN), str(HOSTS)]
    log_level = options.get("loglvl", "info")
    if log_level not in ("info", "debug", "trace"):
        raise ValueError("Select a valid log level.")
    command_line.append(f"--loglvl={log_level}")
    if jobs := options.get("jobs"):
        if not re.fullmatch(r"[1-9][0-9]{0,3}", jobs):
            raise ValueError("Enter a thread count from 1 to 9999.")
        command_line.append(f"--jobs={jobs}")
    for key in ("logfile", "sentry_dsn"):
        if value := options.get(key):
            command_line.append(f"--{key}={value}")
    return command_line


def validate_xray(config):
    with tempfile.TemporaryDirectory(dir=STATE) as directory:
        path = Path(directory) / "xray.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        command([XRAY, "run", "-test", "-c", str(path)], env=xray_env(GEO))


def change_files(changes, apply, recover):
    originals = {path: path.read_bytes() if path.exists() else None for path in changes}
    written = []
    applying = False
    try:
        for path, content in changes.items():
            atomic(path, content)
            written.append(path)
        applying = True
        apply()
    except Exception as error:
        failures = []
        for path in reversed(written):
            try:
                if originals[path] is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic(path, originals[path])
            except OSError as failed_restore:
                failures.append(str(failed_restore))
        if applying and not failures:
            try:
                recover()
            except Exception as failed_restart:
                failures.append(str(failed_restart))
        if failures:
            raise RuntimeError(f"{error}\nRecovery failed: {'; '.join(failures)}") from error
        raise


def apply_endpoint(changes, vpn):
    credentials, rules = related(vpn)
    check_clients(vpn, changes.get(credentials))
    if vpn.get("rules_file") and not (rules in changes or rules.is_file()):
        raise ValueError("The specified connection filter file does not exist.")
    if load_routing()["enabled"]:
        forward = vpn.get("forward_protocol", {})
        if forward != ROUTER_FORWARD:
            raise ValueError("The panel manages the SOCKS5 outbound while routing is enabled.")
    was_active = service_state(ENDPOINT_UNIT) == "active"

    def restart():
        service("restart", ENDPOINT_UNIT)
        active_endpoint()

    change_files(changes, restart, restart if was_active else lambda: service("stop", ENDPOINT_UNIT))


def apply_routing(spec):
    config, _ = compile_routing(spec)
    spec = {key: value for key, value in spec.items() if key != "_native_forward"}
    if spec["enabled"]:
        validate_xray(config)
    old = load_routing()
    if not old["enabled"] and not spec["enabled"]:
        write_json(ROUTING, spec)
        return
    vpn = tomlkit.parse(read(VPN))
    check_clients(vpn)
    if old["enabled"]:
        spec["_native_forward"] = old.get("_native_forward")
    elif spec["enabled"]:
        forward = vpn.get("forward_protocol")
        spec["_native_forward"] = forward.unwrap() if forward is not None else None
    previous_vpn = tomlkit.dumps(vpn)
    if spec["enabled"]:
        if vpn.get("forward_protocol") != ROUTER_FORWARD:
            vpn["forward_protocol"] = ROUTER_FORWARD
    elif old["enabled"]:
        original = spec.pop("_native_forward", None)
        if original is None:
            vpn.pop("forward_protocol", None)
        else:
            vpn["forward_protocol"] = original
    changes = {ROUTING: json.dumps(spec, ensure_ascii=False, indent=2) + "\n"}
    if tomlkit.dumps(vpn) != previous_vpn:
        changes[VPN] = tomlkit.dumps(vpn)
    endpoint_active = service_state(ENDPOINT_UNIT) == "active"
    router_active = service_state(ROUTER_UNIT) == "active"
    touched = []
    steps = [
        (spec["enabled"] and (endpoint_active or router_active), "restart", ROUTER_UNIT),
        (VPN in changes and endpoint_active, "restart", ENDPOINT_UNIT),
        (not spec["enabled"] and router_active, "stop", ROUTER_UNIT),
    ]

    def apply():
        for needed, action, unit in steps:
            if needed:
                touched.append(unit)
                service(action, unit)
                if unit == ENDPOINT_UNIT:
                    active_endpoint()

    def recover():
        if ROUTER_UNIT in touched and router_active:
            service("restart", ROUTER_UNIT)
        if ENDPOINT_UNIT in touched:
            service("restart", ENDPOINT_UNIT)
            active_endpoint()
        if not router_active and touched:
            service("stop", ROUTER_UNIT)

    change_files(changes, apply, recover)


def replace_geofile(filename, data):
    spec = load_routing()
    config = compile_routing(spec)[0] if spec["enabled"] else None
    router_active = config is not None and service_state(ROUTER_UNIT) == "active"
    restarting = False

    def apply():
        nonlocal restarting
        if config is not None:
            validate_xray(config)
        if router_active:
            restarting = True
            service("restart", ROUTER_UNIT)

    def recover():
        if restarting:
            service("restart", ROUTER_UNIT)

    change_files({GEO / filename: data}, apply, recover)


def export_client(name, form):
    fmt = form.get("format", "deeplink")
    if fmt not in ("deeplink", "toml"):
        raise ValueError("Unknown export format.")
    args = [ENDPOINT, str(VPN), str(HOSTS), f"--client_config={name}", f"--format={fmt}"]
    for field in ("address", "dns-upstream"):
        args.extend(f"--{field}={value}" for value in form.get(field, "").split() if value)
    for field in ("name", "custom-sni", "client-random-prefix",
                  "client-random-auth-key", "subscription-url"):
        if value := form.get(field, "").strip():
            args.append(f"--{field}={value}")
    if form.get("subscription-only") and fmt == "deeplink":
        args.append("--subscription-only")
    with tempfile.TemporaryDirectory(dir=STATE) as directory:
        # The endpoint otherwise emits warnings on the same stream as the export.
        args.append(f"--logfile={Path(directory) / 'export.log'}")
        output = command(args, cwd=CONFIG)
    if fmt == "deeplink":
        link = re.search(r"(?m)^tt://\?\S+", output)
        if not link:
            raise ValueError("TrustTunnel did not return a link.")
        return link.group()
    # A successful native TOML export must itself be parseable.
    tomlkit.parse(output)
    return output.strip()
