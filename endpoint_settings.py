"""Native fields exposed by the TrustTunnel Endpoint form."""
from ipaddress import ip_address

FIELDS = {
    "General": (
        ("ipv6_available", "Allow IPv6 destinations", True),
        ("allow_private_network_connections", "Allow private network destinations", False),
        ("ping_enable", "Enable health checks on VPN hosts", False),
        ("speedtest_enable", "Enable speed tests on VPN hosts", False),
    ),
    "Timeouts (seconds)": (
        ("tls_handshake_timeout_secs", "TLS handshake", 10),
        ("client_listener_timeout_secs", "Client listener", 600),
        ("connection_establishment_timeout_secs", "Connection establishment", 30),
        ("tcp_connections_timeout_secs", "TCP idle", 604800),
        ("udp_connections_timeout_secs", "UDP idle", 300),
    ),
}
PROTOCOLS = {"http1": "HTTP/1.1", "http2": "HTTP/2", "quic": "HTTP/3 (QUIC)"}


def values(vpn):
    bind, port = vpn.get("listen_address", "0.0.0.0:443").rsplit(":", 1)
    result = {"bind": bind.strip("[]"), "port": port}
    result.update((key, vpn.get(key, default)) for group in FIELDS.values() for key, _, default in group)
    result.update((key, key in vpn.get("listen_protocols", {})) for key in PROTOCOLS)
    return result


def update(vpn, form, reserved_ports=()):
    address = ip_address(form["bind"].strip())
    port = int(form["port"])
    if not 1 <= port <= 65535 or port in reserved_ports:
        raise ValueError("Choose an available listen port from 1 to 65535.")
    vpn["listen_address"] = f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"
    selected = {key for key in PROTOCOLS if form.get(key)}
    if not selected:
        raise ValueError("Enable at least one listen protocol.")
    protocols = vpn.setdefault("listen_protocols", {})
    for key in PROTOCOLS:
        if key in selected:
            protocols.setdefault(key, {})
        else:
            protocols.pop(key, None)
    for group in FIELDS.values():
        for key, label, default in group:
            value = bool(form.get(key)) if isinstance(default, bool) else int(form[key])
            if not isinstance(default, bool) and not 1 <= value <= 2**32 - 1:
                raise ValueError(f"{label} timeout must be a positive number of seconds.")
            if key in vpn or value != default:
                vpn[key] = value
