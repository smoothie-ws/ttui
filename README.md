# ttui

A minimal web panel for a single TrustTunnel Endpoint. Manage clients, export `tt://` links, and configure TLS hosts and server settings. Xray selects outbounds by domain or IP, and the official TrustTunnel Client connects to upstream endpoints in a cascade.

## Installation

Requires systemd and Python 3.9 or later on Debian or Ubuntu, on x86-64 or ARM64. The TrustTunnel setup wizard needs a TLS hostname for the VPN server. Point its DNS record at the server and open the endpoint port for TCP. Open the same UDP port to use HTTP/3. Let's Encrypt HTTP-01 validation requires TCP port 80.

```bash
curl -fsSL https://github.com/smoothie-ws/ttui/releases/latest/download/bootstrap.sh | sudo bash
```

The installer verifies the release archive's SHA-256 checksum, runs the TrustTunnel setup wizard, and prints the generated administrator password. To install from a working tree, run `sudo bash install.sh --source "$PWD"`. Use `--panel-only` to skip the wizard and configure the endpoint under **Server**. The installer also skips the wizard when no terminal is available. It uses TrustTunnel Endpoint v1.3.1, TrustTunnel Client v1.3.0, and Xray v26.11.9.

The panel is available at [127.0.0.1:8080/ttui/](http://127.0.0.1:8080/ttui/) by default. To access it from another machine, open an SSH tunnel.

```bash
ssh -L 8080:127.0.0.1:8080 USER@SERVER
```

Under **Settings**, change the panel path, username, password, or public VPN address used for exports. When running behind an HTTPS proxy, forward the full panel path and enable HTTPS-only cookies. To change the HTTP bind address or port, set `TTUI_BIND` and `TTUI_PORT` in `/etc/default/ttui` and restart `ttui.service`.

The following command generates a new administrator password and prints the current panel path. Add `--path /ttui` to reset the path as well.

```bash
sudo -u ttui env TTUI_STATE=/var/lib/ttui \
  /opt/ttui/venv/bin/python /opt/ttui/app.py --reset-login
```

## Updates

```bash
ttui version
sudo ttui update
sudo ttui update --version v0.1.0
```

The installer selects the latest stable GitHub release by default. It preserves `/etc/trusttunnel`, `/var/lib/ttui`, systemd drop-in files, and `/etc/default/ttui`. It restarts active services, which can briefly interrupt VPN connections. If the update fails, the installer restores the previous application files and attempts to restart the services. Add `--allow-downgrade` to install an older release explicitly. When switching between versions with different configuration formats, restore a compatible backup.

For an older installation without the `ttui` command, run the installer again. It updates the panel and installs the command for future updates.

## Releases

Work takes place on the `dev` branch. GitHub Actions runs on pushes to `dev` and `main`, and on pull requests. CI checks Python, JavaScript, and Bash, then tests installation, updates, and rollback on Linux. To prepare a stable release, update `VERSION` and [CHANGELOG.md](CHANGELOG.md) on `dev`. After the reviewed changes reach `main`, push the matching SemVer tag from a commit in the history of `main`.

```bash
git tag -a v0.1.0 -m "ttui v0.1.0"
git push origin v0.1.0
```

The **Release** workflow verifies the tagged commit, reruns the checks, and publishes the archive, SHA-256 checksum, and bootstrap script. Run `bash scripts/package.sh` to build the archive locally. Published artifacts are available from [GitHub Releases](https://github.com/smoothie-ws/ttui/releases).

## Server and clients

- **Clients.** Create a client and open its actions to export a `tt://` import link or TOML for the CLI. Rotating a password or deleting a client revokes its old access after the server restarts. An endpoint bound to loopback can run without clients for local development.
- **Domains.** Add TLS hosts for VPN traffic, health checks, speed tests, and reverse proxies. Specify a certificate and key readable by `ttui`. Edit or remove entries in `hosts.toml`. After renewing a certificate, run `sudo systemctl reload trusttunnel`. Manage DNS and PEM renewal separately.
- **Configuration.** The editor opens `vpn.toml`, `hosts.toml`, the client credentials file, and the connection filter file. It supports the native HTTP/1.1, HTTP/2, QUIC, timeout, IPv6, ICMP, metrics, reverse proxy, subscription, and TLS filtering settings. Keep the credentials and filter files inside `/etc/trusttunnel`. Use **Startup options** to set the log level, log file, thread count, and Sentry DSN.
- Applying server configuration restarts services and may interrupt connections. If startup fails, the panel restores the previous files and attempts to restart the service. Back up both `/etc/trusttunnel` and `/var/lib/ttui`.

To switch to an existing credentials or filter file, change only its path in `vpn.toml`. After saving, the editor opens the selected file. You can save routing settings with routing disabled before configuring the endpoint.

The installer stops if it finds an unmanaged `trusttunnel.service`. To migrate an existing installation, back it up, move the configuration and certificates into `/etc/trusttunnel`, verify the paths and permissions for `ttui`, then retire the old service before installing. Reinstalling preserves the endpoint configuration, admin account, routing settings, and uploaded geodata files.

[TrustTunnel Endpoint settings](https://github.com/TrustTunnel/TrustTunnel/blob/v1.3.1/CONFIGURATION.md) · [Setup wizard and client exports](https://github.com/TrustTunnel/TrustTunnel/blob/v1.3.1/README.md)

## Routing and cascades

1. Add an outbound. The built-in `direct` (Freedom) and `block` (Blackhole) outbounds are available immediately. Use the form to add an HTTP or SOCKS5 proxy or a TrustTunnel outbound. Use JSON for other Xray outbound types.
2. For a cascade, paste TOML exported by the remote TrustTunnel Endpoint or a full CLI configuration with an `[endpoint]` table. The cascade requires an address and static credentials for the remote endpoint. ttui starts a separate local SOCKS5 listener for each cascade.
3. Add rules in evaluation order. The first match selects the outbound. Set a default outbound for the remaining traffic. All specified fields in a rule must match.
4. Enable routing. TrustTunnel sends traffic to Xray through a local SOCKS5 listener. Disabling routing restores the previous `forward_protocol`.

| Field | Examples |
| --- | --- |
| Domains | `domain:example.org`, `full:app.example.org`, `regexp:^.*\.example\.org$`, `geosite:category-ads-all`, `ext:custom-site.dat:group` |
| IP | `203.0.113.0/24`, `geoip:private`, `ext:custom-ip.dat:group` |
| Ports | `80,443,1000-2000` |

Upload additional Xray `.dat` databases under **Geodata files**. Xray provides the default `geosite.dat` and `geoip.dat` files. The JSON editor supports advanced rule fields such as `network` and nested outbound settings such as `streamSettings`.

Xray receives the destination address, port, and hostname when available. Rules apply to all clients through the shared SOCKS5 inbound. Use IP rules for connections without an available hostname. UDP support depends on the outbound. HTTP proxies handle TCP.

[Xray routing rules and geodata](https://xtls.github.io/en/config/routing.html) · [Xray outbounds](https://xtls.github.io/en/config/outbound.html) · [TrustTunnel Client SOCKS5 mode](https://github.com/TrustTunnel/TrustTunnelClient/blob/v1.3.0/trusttunnel/README.md)

## Design references

| Reference | How ttui uses it |
| --- | --- |
| [wg-easy](https://github.com/wg-easy/wg-easy) | The client list is the landing page, and exports are available from each client's actions. |
| [3x-ui](https://github.com/MHSanaei/3x-ui/blob/main/docs/content/docs/en/operations/outbounds-routing.mdx) | Named outbounds, ordered rules, geodata, and advanced editing. |
| [TrustTunnel Endpoint CLI](https://github.com/TrustTunnel/TrustTunnel/blob/v1.3.1/CONFIGURATION.md) | ttui preserves the native TOML files and delegates exports to the endpoint. The endpoint sends traffic through one SOCKS5 outbound to a separate router. |
