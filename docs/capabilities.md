# Capability map

This map describes the initial deployment and configuration surface. Use the pinned upstream references before adding fields to the GUI.

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

Only the setup form uses these defaults. For the complete native field definitions, see [TrustTunnel Endpoint 1.3.1 configuration](https://github.com/TrustTunnel/TrustTunnel/blob/v1.3.1/CONFIGURATION.md). For the Xray schema, see [outbounds](https://xtls.github.io/en/config/outbound.html) and [routing](https://xtls.github.io/en/config/routing.html).
