"""TrustTunnel files, native export, and systemd integration."""
import json
from ipaddress import ip_address
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from threading import RLock

import tomlkit

from routing import DEFAULT_ROUTING, ROUTER_ADDRESS, compile_routing, xray_env

LOCK = RLock()
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
            file.write(data)
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
        raise RuntimeError(message[-2500:] or f"Команда завершилась с кодом {result.returncode}.")
    return result.stdout


def service(action, unit):
    command(["/usr/bin/sudo", "-n", SYSTEMCTL, action, unit], timeout=90)


def service_state(unit):
    try:
        return command([SYSTEMCTL, "is-active", unit], timeout=3).strip()
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        return "inactive"


def active_endpoint():
    deadline = time.monotonic() + 2
    while True:
        if service_state(ENDPOINT_UNIT) != "active":
            raise RuntimeError("TrustTunnel завершился при запуске. Проверьте journalctl -u trusttunnel.")
        if time.monotonic() >= deadline:
            return
        time.sleep(0.25)


def managed_path(value, fallback):
    if not isinstance(value if value is not None else fallback, str):
        raise ValueError("Путь конфигурации должен быть строкой.")
    path = (CONFIG / (value or fallback)).resolve()
    if not path.is_relative_to(CONFIG) or path in (CONFIG, VPN, HOSTS):
        raise ValueError("Файлы клиентов и фильтров должны находиться внутри каталога TrustTunnel.")
    return path


def related(vpn):
    credentials = managed_path(vpn.get("credentials_file"), "credentials.toml")
    rules = managed_path(vpn.get("rules_file"), "rules.toml")
    if credentials == rules:
        raise ValueError("Для клиентов и фильтров нужны разные файлы.")
    return credentials, rules


def clients(document):
    entries = document.get("client", [])
    if not isinstance(entries, list):
        raise ValueError("Используйте отдельную таблицу [[client]] для каждого клиента.")
    names = set()
    for entry in entries:
        if (not isinstance(entry, dict) or not all(isinstance(entry.get(key), str) and entry[key]
                                                  for key in ("username", "password"))):
            raise ValueError("У каждого клиента должны быть username и password.")
        if entry["username"] in names:
            raise ValueError("Имена клиентов должны быть уникальны.")
        names.add(entry["username"])
    return entries


def loopback(vpn):
    try:
        host, port = vpn.get("listen_address", "").rsplit(":", 1)
        return port.isascii() and port.isdecimal() and ip_address(host.strip("[]")).is_loopback
    except (AttributeError, ValueError):
        return False


def check_clients(vpn, document):
    if (not vpn.get("credentials_file") or not clients(document)) and not loopback(vpn):
        raise ValueError("Для endpoint вне loopback нужны credentials_file и хотя бы один клиент.")


def load_routing():
    return json.loads(read(ROUTING, json.dumps(DEFAULT_ROUTING)))


def launch_options():
    return json.loads(read(LAUNCH, "{}"))


def endpoint_command(options):
    command_line = [ENDPOINT, str(VPN), str(HOSTS)]
    log_level = options.get("loglvl", "info")
    if log_level not in ("info", "debug", "trace"):
        raise ValueError("Выберите допустимый уровень логов.")
    command_line.append(f"--loglvl={log_level}")
    if jobs := options.get("jobs"):
        if not re.fullmatch(r"[1-9][0-9]{0,3}", jobs):
            raise ValueError("Число потоков должно быть целым положительным числом до 9999.")
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
    try:
        for path, content in changes.items():
            atomic(path, content)
            written.append(path)
        apply()
    except Exception as error:
        for path in reversed(written):
            if originals[path] is None:
                path.unlink(missing_ok=True)
            else:
                atomic(path, originals[path])
        if written:
            try:
                recover()
            except Exception as failed_recovery:
                raise RuntimeError(f"{error}\nОшибка восстановления служб: {failed_recovery}") from error
        raise


def apply_endpoint(changes, vpn):
    credentials, rules = related(vpn)
    document = tomlkit.parse(changes.get(credentials, read(credentials, "")))
    check_clients(vpn, document)
    if vpn.get("rules_file") and not (rules in changes or rules.is_file()):
        raise ValueError("Указанный файл фильтров отсутствует.")
    if load_routing()["enabled"]:
        forward = vpn.get("forward_protocol", {})
        if forward != {"socks5": {"address": ROUTER_ADDRESS, "extended_auth": False}}:
            raise ValueError("Пока маршрутизация включена, её SOCKS5-выход управляется панелью.")
    was_active = service_state(ENDPOINT_UNIT) == "active"

    def restart():
        service("restart", ENDPOINT_UNIT)
        active_endpoint()

    change_files(changes, restart, restart if was_active else lambda: service("stop", ENDPOINT_UNIT))


def apply_routing(spec):
    config, _ = compile_routing(spec)
    if spec["enabled"]:
        validate_xray(config)
    old = load_routing()
    vpn = tomlkit.parse(read(VPN))
    credentials, _ = related(vpn)
    check_clients(vpn, tomlkit.parse(read(credentials, "")))
    spec.pop("_native_forward", None)
    if old["enabled"]:
        spec["_native_forward"] = old.get("_native_forward")
    elif spec["enabled"]:
        forward = vpn.get("forward_protocol")
        spec["_native_forward"] = forward.unwrap() if forward is not None else None
    changes = {ROUTING: json.dumps(spec, ensure_ascii=False, indent=2) + "\n"}
    if spec["enabled"]:
        vpn["forward_protocol"] = {"socks5": {"address": ROUTER_ADDRESS, "extended_auth": False}}
    elif old["enabled"]:
        original = spec.pop("_native_forward", None)
        if original is None:
            vpn.pop("forward_protocol", None)
        else:
            vpn["forward_protocol"] = original
        changes[ROUTING] = json.dumps(spec, ensure_ascii=False, indent=2) + "\n"
    if old["enabled"] != spec["enabled"]:
        changes[VPN] = tomlkit.dumps(vpn)
    was_active = service_state(ENDPOINT_UNIT) == "active"

    def apply():
        if spec["enabled"]:
            service("restart", ROUTER_UNIT)
        if VPN in changes:
            service("restart", ENDPOINT_UNIT)
            active_endpoint()
        if old["enabled"] and not spec["enabled"]:
            service("stop", ROUTER_UNIT)

    def recover():
        if old["enabled"]:
            service("restart", ROUTER_UNIT)
        if VPN in changes:
            service("restart" if was_active else "stop", ENDPOINT_UNIT)
        if not old["enabled"]:
            service("stop", ROUTER_UNIT)

    change_files(changes, apply, recover)


def export_client(name, form):
    fmt = form.get("format", "deeplink")
    if fmt not in ("deeplink", "toml"):
        raise ValueError("Неизвестный формат экспорта.")
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
            raise ValueError("TrustTunnel не вернул ссылку.")
        return link.group()
    # A successful native TOML export must itself be parseable.
    tomlkit.parse(output)
    return output.strip()
