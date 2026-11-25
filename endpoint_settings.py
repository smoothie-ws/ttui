"""Native fields exposed by the TrustTunnel Endpoint form."""
import re
from ipaddress import ip_address, ip_network
from typing import NamedTuple

import tomlkit

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
U32 = 2**32 - 1
I64 = 2**63 - 1
QUIC_VARINT = 2**62 - 1
STATUS_CODES = (407, 405, 404, 403)
HEX_BYTES = r"(?:[a-fA-F0-9]{2})+"
FILTER_FIELDS = ("cidr", "client_random_prefix", "client_random_auth_key", "action")


class Field(NamedTuple):
    key: str
    label: str
    default: object = ""
    kind: str = "text"
    minimum: int = 0
    maximum: int = U32


CORE = (
    Field("ping_path", "Health check path", "/ping"),
    Field("speedtest_path", "Speed test path", "/speedtest"),
    Field("auth_failure_status_code", "CONNECT authentication failure", 407, "status"),
    Field("non_connect_auth_failure_status_code", "Other authentication failures", "", "status"),
    Field("default_max_http2_conns_per_client", "HTTP/1.1 and HTTP/2 connections per client", "", "number"),
    Field("default_max_http3_conns_per_client", "HTTP/3 connections per client", "", "number"),
    Field("credentials_file", "Credentials file"),
    Field("rules_file", "Connection filter file"),
)
PROTOCOL_FIELDS = {
    "http1": (Field("upload_buffer_size", "Upload buffer (bytes)", 32768, "number", 1, I64),),
    "http2": (
        Field("initial_connection_window_size", "Connection window (bytes)", 8388608, "number", 0, 2**31 - 1),
        Field("initial_stream_window_size", "Stream window (bytes)", 131072, "number", 0, 2**31 - 1),
        Field("max_concurrent_streams", "Concurrent streams", 1000, "number"),
        Field("max_frame_size", "Maximum frame size (bytes)", 16384, "number", 16384, 16777215),
        Field("header_table_size", "Header table size (bytes)", 65536, "number"),
    ),
    "quic": (
        Field("recv_udp_payload_size", "Receive UDP payload (bytes)", 1350, "number", 1200, 65527),
        Field("send_udp_payload_size", "Send UDP payload (bytes)", 1350, "number", 1200, 65527),
        Field("initial_max_data", "Initial connection data limit (bytes)", 104857600, "number", 0, QUIC_VARINT),
        Field("initial_max_stream_data_bidi_local", "Local bidirectional stream limit (bytes)", 1048576, "number", 0, QUIC_VARINT),
        Field("initial_max_stream_data_bidi_remote", "Peer bidirectional stream limit (bytes)", 1048576, "number", 0, QUIC_VARINT),
        Field("initial_max_stream_data_uni", "Unidirectional stream data limit (bytes)", 1048576, "number", 0, QUIC_VARINT),
        Field("initial_max_streams_bidi", "Bidirectional streams", 4096, "number", 0, 2**60),
        Field("initial_max_streams_uni", "Unidirectional streams", 4096, "number", 0, 2**60),
        Field("max_connection_window", "Maximum connection window (bytes)", 25165824, "number", 0, QUIC_VARINT),
        Field("max_stream_window", "Maximum stream window (bytes)", 16777216, "number", 0, QUIC_VARINT),
        Field("disable_active_migration", "Disable active migration", True, "bool"),
        Field("enable_early_data", "Allow early data (0-RTT)", True, "bool"),
        Field("message_queue_capacity", "Message queue capacity", 4096, "number", 1, I64),
    ),
}
OPTIONAL = {
    "reverse_proxy": ("Reverse proxy", (
        Field("server_address", "Origin IP address and port"), Field("path_mask", "Path prefix"),
        Field("h3_backward_compatibility", "HTTP/3 to HTTP/1.1 compatibility", False, "bool"),
    )),
    "icmp": ("ICMP forwarding", (
        Field("interface_name", "Network interface", "eth0"),
        Field("request_timeout_secs", "Request timeout (seconds)", 3, "number", 1),
        Field("recv_message_queue_capacity", "Receive queue per client", 256, "number", 1, I64),
    )),
    "metrics": ("Prometheus metrics", (
        Field("address", "Listen IP address and port", "127.0.0.1:1987"),
        Field("request_timeout_secs", "Request timeout (seconds)", 3, "number", 1),
        Field("per_client_metrics", "Include client usernames and IPs", False, "bool"),
    )),
    "subscription": ("HTTPS subscription", (
        Field("hostname", "Main TLS hostname"), Field("address", "Public VPN host and port"),
        Field("path", "Subscription path", "/subscription"), Field("name", "Exported connection name"),
        Field("dns_upstreams", "DNS upstreams (one per line)", (), "list"),
        Field("custom_sni", "Client TLS SNI override"), Field("client_random_prefix", "Client TLS random prefix (hex or hex/mask)"),
    )),
}
FORWARD_FIELDS = (Field("address", "SOCKS5 IP address and port"),
                  Field("extended_auth", "Extended SOCKS5 authentication", False, "bool"))
ALIASES = {field.key: field.key.removeprefix("initial_") for field in PROTOCOL_FIELDS["quic"][3:8]}


def native_key(table, prefix, key):
    alias = ALIASES.get(key) if prefix == "quic." else None
    return alias if key not in table and alias is not None and alias in table else key


def read_fields(table, prefix, fields):
    result = {}
    for field in fields:
        value = table.get(native_key(table, prefix, field.key), field.default)
        result[prefix + field.key] = "\n".join(value) if field.kind == "list" else value
    return result


def write_fields(table, prefix, fields, form):
    for field in fields:
        name = prefix + field.key
        if name not in form:
            continue
        raw = form[name].strip()
        key = native_key(table, prefix, field.key)
        if not raw and field.default in ("", ()):
            table.pop(key, None)
            continue
        if field.kind == "number":
            if not raw.isascii() or not raw.isdecimal() or len(raw) > 19 or not field.minimum <= int(raw) <= field.maximum:
                raise ValueError(f"{field.label} must be between {field.minimum} and {field.maximum}.")
            value = int(raw)
        elif field.kind == "status":
            if raw not in map(str, STATUS_CODES):
                raise ValueError(f"Select a supported status for {field.label.lower()}.")
            value = int(raw)
        elif field.kind == "bool":
            if raw not in ("on", "off"):
                raise ValueError(f"Select on or off for {field.label.lower()}.")
            value = raw == "on"
        else:
            value = [line.strip() for line in raw.splitlines() if line.strip()] if field.kind == "list" else raw
        if key in table or value != field.default:
            table[key] = value


def host_port(value, label, allow_name=False):
    host, sep, port = value.rpartition(":")
    if not sep or not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535:
        raise ValueError(f"{label} requires a host and a port from 1 to 65535.")
    try:
        ip = ip_address(host[1:-1] if host.startswith("[") and host.endswith("]") else host)
    except ValueError as error:
        if allow_name and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9.])?", host):
            return
        raise ValueError(f"Enter a valid IP address for {label.lower()}.") from error
    if (ip.version == 6) != host.startswith("["):
        raise ValueError(f"Use brackets only around IPv6 addresses for {label.lower()}.")


def validate(vpn, hosts):
    ping, speedtest = vpn.get("ping_path", "/ping"), vpn.get("speedtest_path", "/speedtest")
    for path in (ping, speedtest):
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("Health check and speed test paths must start with /.")
    if ping.startswith(speedtest) or speedtest.startswith(ping):
        raise ValueError("Health check and speed test paths must not overlap.")
    if "reverse_proxy" in vpn:
        proxy = vpn["reverse_proxy"]
        host_port(proxy.get("server_address", ""), "Reverse proxy origin")
        if not proxy.get("path_mask", "").startswith("/"):
            raise ValueError("The reverse proxy path must start with /.")
    if "metrics" in vpn:
        if "http1" not in vpn.get("listen_protocols", {}):
            raise ValueError("Enable HTTP/1.1 to use the metrics listener in TrustTunnel 1.3.1.")
        host_port(vpn["metrics"].get("address", "127.0.0.1:1987"), "Metrics listener")
    if "subscription" in vpn:
        sub = vpn["subscription"]
        host_port(sub.get("address", ""), "Public VPN address", allow_name=True)
        if not any(host.get("hostname") == sub.get("hostname") for host in hosts.get("main_hosts", [])):
            raise ValueError("The subscription hostname must match an existing main TLS host.")
        path = sub.get("path", "/subscription")
        if not path.startswith("/") or path == "/":
            raise ValueError("The subscription path must start with / and include a path segment.")
        proxy_path = vpn.get("reverse_proxy", {}).get("path_mask")
        if any(path.startswith(other) or other.startswith(path) for other in (ping, speedtest, proxy_path) if other):
            raise ValueError("The subscription path must not overlap another endpoint path.")
        prefix = sub.get("client_random_prefix", "")
        if prefix and not re.fullmatch(rf"{HEX_BYTES}(?:/{HEX_BYTES})?", prefix):
            raise ValueError("Enter the TLS random prefix and optional mask as whole hexadecimal bytes.")


def filter_rows(document):
    entries = document.get("rule", [])
    if not isinstance(entries, list) or any(not isinstance(rule, dict) for rule in entries):
        raise ValueError("Connection filters must use separate [[rule]] tables.")
    return [(str(index), rule) for index, rule in enumerate(entries)]


def update_filters(document, form):
    previous = dict(filter_rows(document))
    indexes = form.getlist("rule_index")
    columns = [form.getlist(field) for field in FILTER_FIELDS]
    existing = [index for index in indexes if index]
    if (any(len(column) != len(indexes) for column in columns) or len(set(existing)) != len(existing)
            or set(existing) - previous.keys()):
        raise ValueError("Connection filter rows are invalid. Reload the page and try again.")
    rows, rules = [], tomlkit.aot()
    for index, values in zip(indexes, zip(*columns)):
        cidr, prefix, key, action = (value.strip() for value in values)
        if action not in ("allow", "deny"):
            raise ValueError("Select Allow or Deny for each rule.")
        if cidr:
            cidr = str(ip_network(cidr, strict=False))
        if prefix and (key or not re.fullmatch(rf"{HEX_BYTES}(?:/{HEX_BYTES})?", prefix)):
            raise ValueError("Enter a hexadecimal prefix with an optional mask, or use an auth key.")
        if key and not re.fullmatch(HEX_BYTES, key):
            raise ValueError("The TLS random auth key must contain whole hexadecimal bytes.")
        rule = previous.get(index, tomlkit.table())
        for field, value in zip(FILTER_FIELDS, (cidr, prefix, key, action)):
            if value:
                rule[field] = value
            else:
                rule.pop(field, None)
        rules.append(rule)
        rows.append((index, rule))
    if rules or "rule" in document:
        document["rule"] = rules
    return rows


def values(vpn):
    bind, port = vpn.get("listen_address", "0.0.0.0:443").rsplit(":", 1)
    result = {"bind": bind.strip("[]"), "port": port}
    result.update((key, vpn.get(key, default)) for group in FIELDS.values() for key, _, default in group)
    protocols = vpn.get("listen_protocols", {})
    result.update((key, key in protocols) for key in PROTOCOLS)
    result.update(read_fields(vpn, "", CORE))
    for key, fields in PROTOCOL_FIELDS.items():
        result.update(read_fields(protocols.get(key, {}), key + ".", fields))
    for key, (_, fields) in OPTIONAL.items():
        table = vpn.get(key, {})
        result[key] = "on" if key in vpn else "off"
        if key == "subscription" and key in vpn and not table.get("enabled", False):
            result[key] = "disabled"
        result.update(read_fields(table, key + ".", fields))
    forward = vpn.get("forward_protocol", {})
    result["forward"] = "socks5" if "socks5" in forward else "direct"
    result.update(read_fields(forward.get("socks5", {}), "socks5.", FORWARD_FIELDS))
    return result


def update(vpn, form, reserved_ports=(), routed=False):
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
            group = protocols.setdefault(key, {})
            write_fields(group, key + ".", PROTOCOL_FIELDS[key], form)
        else:
            protocols.pop(key, None)
    for group in FIELDS.values():
        for key, label, default in group:
            value = bool(form.get(key)) if isinstance(default, bool) else int(form[key])
            if not isinstance(default, bool) and not 1 <= value <= 2**32 - 1:
                raise ValueError(f"{label} timeout must be a positive number of seconds.")
            if key in vpn or value != default:
                vpn[key] = value
    write_fields(vpn, "", CORE, form)
    for key, (_, fields) in OPTIONAL.items():
        if key not in form:
            continue
        mode = form[key]
        if mode == "off":
            vpn.pop(key, None)
            continue
        if mode != "on" and not (key == "subscription" and mode == "disabled"):
            raise ValueError("Select a valid mode for each service.")
        group = vpn.setdefault(key, {})
        write_fields(group, key + ".", fields, form)
        if key == "subscription" and ("enabled" in group or mode == "on"):
            group["enabled"] = mode == "on"
    if not routed and "forward" in form:
        mode = form["forward"]
        current = vpn.get("forward_protocol", {})
        if mode == "socks5":
            group = current.get("socks5", {})
            write_fields(group, "socks5.", FORWARD_FIELDS, form)
            host_port(group.get("address", ""), "SOCKS5 proxy")
            if "socks5" not in current:
                vpn["forward_protocol"] = {"socks5": group}
        elif mode == "direct":
            if current and "direct" not in current:
                vpn["forward_protocol"] = {"direct": {}}
        else:
            raise ValueError("Select a supported forwarding mode.")
