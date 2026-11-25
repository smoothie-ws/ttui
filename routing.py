"""Compile the panel's ordered routing rules into an Xray configuration."""
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import tomlkit

ROUTER_ADDRESS = "127.0.0.1:19080"
FIRST_CASCADE_PORT = 19100
DEFAULT_ROUTING = {"enabled": False, "domainStrategy": "IPIfNonMatch",
                   "default": "direct", "outbounds": [], "rules": []}


def compile_routing(spec):
    if not isinstance(spec, dict) or type(spec.get("enabled")) is not bool:
        raise ValueError("Укажите enabled в настройках маршрутизации.")
    strategy = spec.get("domainStrategy")
    if strategy not in ("AsIs", "IPIfNonMatch", "IPOnDemand"):
        raise ValueError("Неизвестная стратегия DNS.")
    if not all(isinstance(spec.get(key), list) for key in ("outbounds", "rules")):
        raise ValueError("Выходы и правила должны быть списками.")

    outbounds = {"direct": {"tag": "direct", "protocol": "freedom"},
                 "block": {"tag": "block", "protocol": "blackhole"}}
    cascades = {}
    for outbound in spec["outbounds"]:
        if not isinstance(outbound, dict):
            raise ValueError("Выход должен быть объектом.")
        tag, protocol = outbound.get("tag"), outbound.get("protocol")
        if not isinstance(tag, str) or not re.fullmatch(r"[\w.-]{1,64}", tag, re.ASCII) or tag in outbounds:
            raise ValueError("Имена выходов должны быть уникальны (A–Z, 0–9, _, ., -).")
        if protocol == "trusttunnel":
            if len(cascades) >= 32:
                raise ValueError("Допускается не более 32 каскадов.")
            raw = outbound.get("config")
            if not isinstance(raw, str):
                raise ValueError(f"{tag}: требуется конфигурация TrustTunnel в TOML.")
            client = tomlkit.parse(raw)
            # An endpoint export and a full CLI configuration use different shapes.
            if "endpoint" not in client:
                client = tomlkit.document().append("endpoint", client)
            endpoint = client["endpoint"]
            if not isinstance(endpoint, dict):
                raise ValueError(f"{tag}: требуется таблица endpoint.")
            if not all(
                endpoint.get(key) for key in ("hostname", "addresses", "username", "password")
            ):
                raise ValueError(f"{tag}: заполните hostname, addresses, username и password.")
            if endpoint.get("client_random_prefix") and not endpoint.get("client_random"):
                endpoint["client_random"] = endpoint["client_random_prefix"]
            endpoint.pop("client_random_prefix", None)
            endpoint.setdefault("upstream_protocol", "http2")
            endpoint.setdefault("tls_profile", "chrome")
            port = FIRST_CASCADE_PORT + len(cascades)
            client["listener"] = {"socks": {"address": f"127.0.0.1:{port}"}}
            client["vpn_mode"] = "general"
            client["exclusions"] = []
            client["killswitch_enabled"] = False
            cascades[port] = tomlkit.dumps(client)
            outbounds[tag] = {"tag": tag, "protocol": "socks", "settings": {
                "servers": [{"address": "127.0.0.1", "port": port}]}}
        else:
            if not isinstance(protocol, str) or not re.fullmatch(r"[a-z0-9_-]+", protocol):
                raise ValueError(f"{tag}: укажите протокол Xray.")
            outbounds[tag] = outbound

    default = spec.get("default")
    if not isinstance(default, str) or default not in outbounds:
        raise ValueError("Выберите существующий выход по умолчанию.")
    rules = []
    for rule in spec["rules"]:
        if (not isinstance(rule, dict) or not isinstance(rule.get("outboundTag"), str)
                or rule["outboundTag"] not in outbounds):
            raise ValueError("Каждому правилу нужен существующий выход.")
        if not any(value for key, value in rule.items() if key not in ("type", "outboundTag")):
            raise ValueError("Каждому правилу нужно хотя бы одно условие.")
        rules.append({**rule, "type": "field"})
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "trusttunnel", "listen": "127.0.0.1",
                      "port": int(ROUTER_ADDRESS.rsplit(":", 1)[1]), "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
                      "sniffing": {"enabled": True, "routeOnly": True,
                                   "destOverride": ["http", "tls", "quic"]}}],
        "outbounds": [outbounds[default], *(v for k, v in outbounds.items() if k != default)],
        "routing": {"domainStrategy": strategy, "rules": rules},
    }, cascades


def xray_env(assets):
    return {**os.environ, "XRAY_LOCATION_ASSET": str(assets)}


def wait_listener(port, process, timeout=12):
    deadline = time.monotonic() + timeout
    while process.poll() is None and time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.15)
    raise RuntimeError(f"Локальный SOCKS5 на порту {port} не запустился.")


def run_router(state, xray, client_binary):
    from contextlib import ExitStack

    spec = json.loads((state / "routing.json").read_text(encoding="utf-8"))
    config, cascades = compile_routing(spec)
    if not spec["enabled"]:
        raise RuntimeError("Маршрутизация отключена.")
    processes = []

    def start(command, port):
        process = subprocess.Popen(command, cwd=state, env=xray_env(state / "geo"))
        processes.append(process)
        wait_listener(port, process)

    with ExitStack() as stack:
        import tempfile
        import signal
        work = Path(stack.enter_context(tempfile.TemporaryDirectory(dir=state)))

        def cleanup():
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
            for process in reversed(processes):
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

        def stop(*_):
            sys.exit(0)

        signal.signal(signal.SIGTERM, stop)
        stack.callback(cleanup)
        for port, data in cascades.items():
            path = work / f"cascade-{port}.toml"
            path.write_text(data, encoding="utf-8")
            start([client_binary, "--config", str(path)], port)
        path = work / "xray.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        start([xray, "run", "-c", str(path)], int(ROUTER_ADDRESS.rsplit(":", 1)[1]))
        if address := os.environ.get("NOTIFY_SOCKET"):
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notify:
                notify.sendto(b"READY=1", "\0" + address[1:] if address.startswith("@") else address)
        while all(process.poll() is None for process in processes):
            time.sleep(0.5)
        raise RuntimeError("Процесс Xray или TrustTunnel Client завершился.")


if __name__ == "__main__":
    run_router(Path(sys.argv[1]).resolve(), *sys.argv[2:])
