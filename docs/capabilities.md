# Capability map

This map describes the deployment and configuration surface. Use the pinned upstream references before adding fields to the GUI.

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
| `listen_address` | IP address and port. Ports range from 1 to 65535. | Panel setup defaults to `0.0.0.0:8443` in HTTPS mode and `0.0.0.0:443` for local deployments. |
| `listen_protocols.http2` | Optional protocol table in native TOML. | The panel enables it during setup to provide a TCP transport. |
| `listen_protocols.quic` | Optional protocol table in native TOML. | Enabled when selected in the setup form. Requires the chosen port on UDP. |
| `allow_private_network_connections` | Boolean. | Disabled in the initial VPN configuration. |
| `credentials_file` | Path to native client credentials. | ttui writes one `[[client]]` with a unique username and generated password during setup. |
| `main_hosts` | List of TLS hosts with a hostname, certificate chain, and private key path. | Setup requires a DNS hostname. Both existing certificate paths can be supplied, or ttui generates a self-signed pair. |

Only the setup form uses these defaults.

## Endpoint settings after setup

| Panel section | Native settings |
| --- | --- |
| Listener | All three listeners and their HTTP/1.1 buffer, HTTP/2 frame and flow-control limits, and QUIC payload, stream, window, migration, early-data, and queue settings. |
| General and connection limits | IPv6, private destinations, health checks, speed tests, request paths, timeout values, authentication failure status codes, default connection limits, and credentials and rules file paths. |
| Native outbound | Direct or SOCKS5 with extended authentication. Xray manages the native SOCKS5 address while routing is enabled. |
| Services | Reverse proxy, ICMP, metrics, and HTTPS subscriptions. The metrics handler in Endpoint 1.3.1 uses the HTTP/1.1 codec, so both must be enabled. DNS upstreams configured here belong to exported subscription profiles. |
| Connection filters | Ordered inbound rules matching source CIDR, TLS random prefix with an optional mask, or a TLS random auth key. |

See the pinned [TrustTunnel Endpoint settings](https://github.com/TrustTunnel/TrustTunnel/blob/v1.3.1/CONFIGURATION.md), [settings source](https://github.com/TrustTunnel/TrustTunnel/blob/v1.3.1/lib/src/settings.rs), and [metrics handler](https://github.com/TrustTunnel/TrustTunnel/blob/v1.3.1/lib/src/metrics.rs). For Xray, see [outbounds](https://xtls.github.io/en/config/outbound.html) and [routing](https://xtls.github.io/en/config/routing.html).
