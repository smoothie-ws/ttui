# Capability map

This map describes the deployment and configuration surface. Use the pinned upstream references before adding fields to the GUI. The executable form schema is `endpoint_settings.py`; the tables below must stay aligned with it.

| Layer | Owner | Lifecycle |
| --- | --- | --- |
| Administrative HTTPS | Caddy or an operator-managed HTTPS proxy | Independent of endpoint TLS. The application binds to loopback in HTTPS mode and requires secure session cookies. |
| Administrative panel | ttui | Starts during installation. A VPN configuration is optional at this point. |
| VPN listener | TrustTunnel Endpoint 1.3.1 | The panel supplies the native TLS host, client credentials, and listener settings. Applying them requires a successful endpoint restart. |
| Traffic routing | Xray 26.11.9 | Uses a local SOCKS5 inbound. Validate changes with Xray before restarting the router. |
| VPN cascades | TrustTunnel Client 1.3.0 | The router starts a local SOCKS5 listener for each configured upstream TrustTunnel connection. |

## Initial endpoint fields

| Native field | Type and validation | Default or requirement |
| --- | --- | --- |
| `listen_address` | IP address and port. Ports range from 1 to 65535. Ports 80 and 443 are reserved while panel HTTPS is managed by Caddy. | Panel setup defaults to `0.0.0.0:8443` in HTTPS mode and `0.0.0.0:443` for local deployments. |
| `listen_protocols.http2` | Optional protocol table in native TOML. | The panel enables it during setup to provide a TCP transport. |
| `listen_protocols.quic` | Optional protocol table in native TOML. | Enabled when selected in the setup form. Requires the chosen port on UDP. |
| `allow_private_network_connections` | Boolean. | Disabled in the initial VPN configuration. |
| `credentials_file` | Path to native client credentials inside `/etc/trusttunnel`. | ttui writes one `[[client]]` with a unique username and generated password during setup. |
| `main_hosts` | List of TLS hosts with a hostname, certificate chain, and private key path. | Setup requires a DNS hostname. Both existing certificate paths can be supplied, ttui can generate a self-signed pair, or ACME can issue a certificate. |

Only the setup form uses these defaults.

## Endpoint tabs

The endpoint form groups native settings into four tabs. Every field is validated before the diff is shown. Applying a change saves a configuration backup, writes files atomically, restarts `trusttunnel.service` when it is active, and restores the previous files if the restart fails.

### General

| Field | Type and validation | Default | Restart |
| --- | --- | --- | --- |
| Listen IP address and port | IPv4 or IPv6 address and port 1-65535. At least one listen protocol is required. | Current value. | Yes |
| `ipv6_available` | Boolean. | `true` | Yes |
| `allow_private_network_connections` | Boolean. | `false` | Yes |
| `ping_enable` | Boolean. Enables health checks on VPN TLS hosts. | `false` | Yes |
| `speedtest_enable` | Boolean. Enables speed tests on VPN TLS hosts. | `false` | Yes |

### Protocols

| Field | Type and validation | Default | Restart |
| --- | --- | --- | --- |
| HTTP/1.1 | Boolean. Required for the Endpoint 1.3.1 metrics handler. | Disabled unless enabled during setup. | Yes |
| HTTP/2 | Boolean. | Enabled during setup. | Yes |
| HTTP/3 (QUIC) | Boolean. Requires the same port on UDP. | Disabled unless selected during setup. | Yes |
| `http1.upload_buffer_size` | Integer 1..2^63-1 bytes. | `32768` | Yes |
| `http2.initial_connection_window_size` | Integer 0..2^31-1 bytes. | `8388608` | Yes |
| `http2.initial_stream_window_size` | Integer 0..2^31-1 bytes. | `131072` | Yes |
| `http2.max_concurrent_streams` | Integer 0..2^32-1. | `1000` | Yes |
| `http2.max_frame_size` | Integer 16384..16777215 bytes. | `16384` | Yes |
| `http2.header_table_size` | Integer 0..2^32-1 bytes. | `65536` | Yes |
| `quic.*_udp_payload_size` | Integer 1200..65527 bytes. | `1350` | Yes |
| `quic.initial_max_data`, `*_stream_data_*`, windows | Integer 0..2^62-1 bytes. | Endpoint defaults, shown in the form. | Yes |
| `quic.initial_max_streams_bidi`, `initial_max_streams_uni` | Integer 0..2^60. | `4096` | Yes |
| `quic.disable_active_migration` | Boolean. | `true` | Yes |
| `quic.enable_early_data` | Boolean. | `true` | Yes |
| `quic.message_queue_capacity` | Integer 1..2^63-1. | `4096` | Yes |

### Network

| Field | Type and validation | Default | Restart |
| --- | --- | --- | --- |
| `tls_handshake_timeout_secs` | Positive seconds, up to 2^32-1. | `10` | Yes |
| `client_listener_timeout_secs` | Positive seconds. | `600` | Yes |
| `connection_establishment_timeout_secs` | Positive seconds. | `30` | Yes |
| `tcp_connections_timeout_secs` | Positive seconds. | `604800` | Yes |
| `udp_connections_timeout_secs` | Positive seconds. | `300` | Yes |
| `ping_path`, `speedtest_path` | Absolute paths; they must not overlap. | `/ping`, `/speedtest` | Yes |
| `auth_failure_status_code` | One of 407, 405, 404, 403. | `407` | Yes |
| `non_connect_auth_failure_status_code` | One of 407, 405, 404, 403, or inherit. | Inherit | Yes |
| `default_max_http2_conns_per_client` | Optional positive integer; blank means unlimited. | Blank | Yes |
| `default_max_http3_conns_per_client` | Optional positive integer; blank means unlimited. | Blank | Yes |
| `credentials_file`, `rules_file` | Managed paths inside `/etc/trusttunnel`; separate files. Credentials are mandatory outside loopback. | `credentials.toml`, optional `rules.toml` | Yes |
| Native outbound | `direct` or `socks5` with address and optional extended authentication. While routing is enabled, the panel owns the SOCKS5 address. | `direct` | Yes |

### Services and advanced

| Section | Native settings | Validation | Restart |
| --- | --- | --- | --- |
| Reverse proxy | Origin address and port, path prefix, HTTP/3 compatibility. | Origin is an IP and port; path starts with `/`. | Yes |
| ICMP forwarding | Interface, timeout, receive queue capacity. | Positive timeout and capacity. | Yes |
| Prometheus metrics | Listen address, timeout, per-client metrics. | IP and port; HTTP/1.1 must be enabled. Keep loopback for private metrics. | Yes |
| HTTPS subscription | Hostname, public address, path, name, DNS upstreams, SNI, random prefix. | Hostname must match a VPN TLS host; path must not overlap other endpoint paths; prefix is whole hex bytes. | Yes |
| Connection filters | Ordered allow/deny rules by source CIDR, TLS random prefix, or auth key. | Valid CIDR and whole hex bytes; order is preserved. | Yes |

## Xray and routing

| Capability | Supported values | Notes |
| --- | --- | --- |
| Built-in outbounds | `direct` (Freedom), `block` (Blackhole) | Always available. |
| Proxy outbounds | HTTP, SOCKS5, VLESS, VMess, Trojan, Shadowsocks | Transport, TLS, REALITY, and protocol fields are exposed only where Xray supports them. |
| TrustTunnel cascades | Structured endpoint form or native Client TOML | Up to 32 cascades; each starts a local SOCKS5 listener. |
| Rules | Domain, full, regexp, geosite, IP/CIDR, geoip, external geodata, ports | Rules are evaluated in order; the first match wins. |
| Default outbound | Any configured outbound | Applies when no rule matches. |
| DNS strategy | `AsIs`, `IPIfNonMatch`, `IPOnDemand` | Used for domain/IP rule evaluation. |
| Geodata | `geoip.dat`, `geosite.dat`, custom `.dat` | Upload, optional SHA-256 verification, file date and size. |
| Validation | `xray run -test` | A draft can be validated without applying it. |

Applying routing validates the compiled Xray configuration, writes `routing.json`, changes the endpoint forwarder only when needed, restarts only active services, and restores the previous files and services on failure. Disabling routing restores the previous native forwarder.

## Panel, TLS, monitoring, and security

| Area | Surface |
| --- | --- |
| Panel setup | Single mandatory public hostname. Access mode: managed Caddy HTTPS, external HTTPS proxy, or loopback/SSH. Advanced internal port with `--port`. Administrator password generated by the installer. |
| Sign-in | Password, optional TOTP, persisted per-address attempt limit, secure cookies in HTTPS mode, CSRF on every state change. |
| Sessions | 12-hour lifetime, sign out all sessions by rotating the session epoch. |
| IP allowlist | Addresses or CIDR ranges; the current address must remain allowed. |
| Activity | Sign-ins and administrative actions in `/var/lib/ttui/activity.jsonl` and the panel journal; dashboard shows the newest events. |
| TLS hosts | VPN, health check, speed test, and reverse proxy hosts. Add, edit, delete, upload PEM, validate hostname/key/expiry, view history. |
| Panel certificates | Managed by Caddy for the panel hostname. Independent from endpoint TLS. |
| Endpoint certificates | Existing files, uploaded PEM, self-signed, or Let's Encrypt through Certbot on managed Caddy installations. `ttui-acme.timer` renews and reloads a validated change. |
| Monitoring | Host CPU, memory, disk, uptime, network rates, service states, and 1h/24h/7d/30d history in SQLite with 30-day retention. |
| Logs | Panel, Endpoint, Xray, cascade client, Caddy, ACME, backups, and updates. Search, level filter, time range, download, auto-refresh. |
| Diagnostics | Services, listeners, binaries, configuration, TLS, DNS, disk space, permissions, and Xray validation with recommendations. |
| Backups | Manual and scheduled ZIP archives with checksums, component selection, import, restore, integrity verification, and rollback on failed service start. |
| Updates | Stable GitHub releases, compatibility metadata, release notes, password confirmation, pre-update snapshot, and automatic rollback. |

## Restart matrix

| Change | Endpoint restart | Xray/routing restart | Panel restart |
| --- | --- | --- | --- |
| Endpoint tab apply | Yes, when the service is active | No | No |
| Connection filters | Yes | No | No |
| TLS host add/edit/delete | Yes | No | No |
| ACME renewal with validated files | Reload when active | No | No |
| Routing rule or outbound change | Only when the forwarder changes | Yes, when routing is active | No |
| Geodata upload | No | Yes, when routing is active | No |
| Panel settings | No | No | Session reissued; path/login changes redirect |
| ttui update | As required by the release | As required by the release | Yes |

See the pinned [TrustTunnel Endpoint settings](https://github.com/TrustTunnel/TrustTunnel/blob/v1.3.1/CONFIGURATION.md), [settings source](https://github.com/TrustTunnel/TrustTunnel/blob/v1.3.1/lib/src/settings.rs), and [metrics handler](https://github.com/TrustTunnel/TrustTunnel/blob/v1.3.1/lib/src/metrics.rs). For Xray, see [outbounds](https://xtls.github.io/en/config/outbound.html) and [routing](https://xtls.github.io/en/config/routing.html).