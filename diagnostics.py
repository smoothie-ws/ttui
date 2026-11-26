"""On-demand checks for this installation, using local services and configured names."""
import os
import shutil
import socket
import subprocess
from ipaddress import ip_address
from pathlib import Path

import tomlkit

import backend as b
import certificates as tls
from routing import compile_routing

ERRORS = (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, tomlkit.exceptions.ParseError)

def port_available(listener):
    if not isinstance(listener, str):
        raise ValueError("Enter a valid IP address and port in Server settings.")
    host, port = listener.rsplit(":", 1)
    host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(host.strip("[]"), host.strip("[]"))
    ip_address(host)
    with socket.create_connection((host, int(port)), timeout=2):
        return f"Accepting connections on {listener}."

def readable(path):
    if not path.is_file() or not os.access(path, os.R_OK):
        raise ValueError(f"Check permissions or restore {path}.")
    return f"Readable by the panel service: {path}."

def executable(path):
    if shutil.which(str(path)) is None:
        raise ValueError(f"Restore the installed executable at {path}.")
    return f"Available: {path}."

def running(unit):
    if b.service_state(unit) != "active":
        raise ValueError("Service is stopped or unavailable. See Logs for details.")
    return "Service is running."

def check():
    rows = []

    def run(label, operation):
        try:
            message = operation()
        except ERRORS as error:
            rows.append(("Attention", label, str(error)))
        else:
            rows.append(("OK", label, message))

    run("Panel service", lambda: running("ttui.service"))
    bind = "127.0.0.1" if os.environ.get("TTUI_REQUIRE_HTTPS") == "1" else os.environ.get("TTUI_BIND", "127.0.0.1")
    port = os.environ.get("TTUI_PORT", "8080")
    run("Panel listener", lambda: port_available(f"{bind}:{port}"))
    run("Free space for panel data", lambda: f"{shutil.disk_usage(b.STATE).free / 1073741824:.2f} GiB available.")
    for label, path in (("TrustTunnel binary", b.ENDPOINT), ("Xray binary", b.XRAY),
                        ("Cascade client binary", Path(b.XRAY).parent.parent / "trusttunnel_client")):
        run(label, lambda path=path: executable(path))
    if b.VPN.is_file() and b.HOSTS.is_file():
        run("Endpoint service", lambda: running(b.ENDPOINT_UNIT))

        def check_configuration():
            vpn = tomlkit.parse(b.read(b.VPN))
            hosts = tomlkit.parse(b.read(b.HOSTS))
            b.check_clients(vpn)
            primary = hosts.get("main_hosts")
            if not isinstance(primary, list) or not primary or any(not isinstance(host, dict) for host in primary):
                raise ValueError("Add a VPN TLS host in TLS & Certificates.")
            return vpn, primary, b.related(vpn)

        try:
            vpn, primary, (credentials, rules) = check_configuration()
        except ERRORS as error:
            rows.append(("Attention", "Endpoint configuration", str(error)))
        else:
            rows.append(("OK", "Endpoint configuration", "TOML, credentials, and primary TLS host are present."))
            run("VPN listener", lambda: port_available(vpn.get("listen_address", "0.0.0.0:443")))
            for label, path, enabled in (
                ("Endpoint configuration file", b.VPN, True), ("TLS host file", b.HOSTS, True),
                ("Client credentials file", credentials, vpn.get("credentials_file")),
                ("Connection filter file", rules, vpn.get("rules_file")),
            ):
                if enabled:
                    run(label, lambda path=path: readable(path))
            for host in primary:
                name = host.get("hostname", "")
                if not isinstance(name, str) or any(not isinstance(host.get(key), str) for key in ("cert_chain_path", "private_key_path")):
                    rows.append(("Attention", "TLS host", "Check the hostname, certificate and key in TLS & Certificates."))
                    continue
                run(f"TLS certificate: {name}", lambda host=host, name=name:
                    "Valid until " + tls.existing_pair(host.get("cert_chain_path", ""),
                                                      host.get("private_key_path", ""), name)["expires"])
                run(f"DNS: {name}", lambda name=name: dns(name))
    else:
        rows.append(("Skipped", "Endpoint configuration", "Complete setup in Server when you are ready to start the VPN."))
    try:
        spec = b.load_routing()
        if not isinstance(spec, dict) or not isinstance(spec.get("enabled"), bool):
            raise ValueError("Check the routing settings and save the configuration again.")
    except ERRORS as error:
        rows.append(("Attention", "Xray configuration", str(error)))
        return rows
    if spec["enabled"]:
        run("Routing service", lambda: running(b.ROUTER_UNIT))

        def check_router():
            b.validate_xray(compile_routing(spec)[0])
            return "Xray accepted the saved routing configuration."

        run("Xray configuration", check_router)
    else:
        rows.append(("Skipped", "Routing service", "Routing is disabled."))
    return rows

def dns(name):
    host = tls.hostname(name)
    output = b.command(["getent", "ahosts", host], timeout=3)
    addresses = sorted({line.split()[0] for line in output.splitlines() if line.strip()})
    if not addresses:
        raise ValueError("No address records found. Check DNS for this hostname.")
    return ", ".join(addresses)
