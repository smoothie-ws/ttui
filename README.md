# ttui

A minimal web panel for a single TrustTunnel Endpoint. Manage clients, export `tt://` links, and configure TLS hosts and server settings. Xray selects outbounds by domain or IP, and the official TrustTunnel Client connects to upstream endpoints in a cascade.

## Installation

Requires systemd and Python 3.9 or later on Debian or Ubuntu, on x86-64 or ARM64.

### Browser-first setup from a working tree

```bash
sudo bash install.sh --source "$PWD" --domain panel.example.com
```

Run the command from a checkout that includes browser-first setup. Point the panel domain's DNS records at the server and allow inbound TCP on ports 80 and 443 for Caddy. The installer starts the web panel and prints its HTTPS URL and sign-in details. It installs TrustTunnel Endpoint v1.3.1, TrustTunnel Client v1.3.0, and Xray v26.11.9. On a fresh server, the VPN endpoint stays unconfigured until you complete setup in the browser.

Sign in and go to **Server → Set up TrustTunnel**. Enter the VPN hostname, listen IP and port, and the first client username. Point the VPN hostname at the server and open the endpoint port for TCP and, for HTTP/3, UDP. Use an existing TLS certificate or let ttui generate a self-signed one. After setup, go to **Clients** to export the first connection.

For a fresh installation with managed Caddy HTTPS, the setup form and **TLS & Certificates** also offer Let's Encrypt. Point the VPN hostname at this server and open TCP port 80 for HTTP-01. Use a separate VPN hostname from the panel hostname. Certbot stores VPN certificates privately under `/var/lib/ttui/acme`, and `ttui-acme.timer` runs renewal checks and reloads an active endpoint after a validated certificate change.

See the [capability map](docs/capabilities.md) for the deployment layers and initial endpoint fields.

The panel and VPN endpoint use separate TLS configurations. With managed HTTPS, use VPN port 8443 by default because Caddy uses port 443. Pass `--external-proxy` on a fresh install if you already operate an HTTPS proxy. Forward the entire panel path to `127.0.0.1:8080` and set `X-Forwarded-For` and `X-Forwarded-Proto` from trusted request data. For an SSH-only installation, pass `--local` and open [127.0.0.1:8080/ttui/](http://127.0.0.1:8080/ttui/) through this tunnel.

```bash
ssh -L 8080:127.0.0.1:8080 USER@SERVER
```

Under **Settings**, change the panel path, username, password, or public VPN address used for exports. When running behind an HTTPS proxy, forward the full panel path and enable HTTPS-only cookies. To change the HTTP bind address or port, set `TTUI_BIND` and `TTUI_PORT` in `/etc/default/ttui` and restart `ttui.service`.

The following command generates a new administrator password and prints the current panel path. Add `--path /ttui` to reset the path as well.

```bash
sudo -u ttui env TTUI_STATE=/var/lib/ttui \
  /opt/ttui/venv/bin/python /opt/ttui/app.py --reset-login
```

In **Settings**, set up a TOTP authenticator, choose an optional IP allowlist, or open **Administrative activity** to review sign-ins and changes. Enable the authenticator by scanning the QR code and entering its six-digit code. Changing the authenticator signs out other sessions. A nonempty allowlist must include your current address. Use IP addresses or CIDR ranges and keep access to the server console if your address changes. With an external reverse proxy, configure it to supply the verified client IP as described above.

If you lose the authenticator or the allowlist blocks your address, use the password reset command from the server console. Add `--clear-totp`, `--clear-allowlist`, or both to clear the affected settings. Backups containing panel settings also contain the authenticator secret.

### Published releases

The stable installer verifies the release archive's SHA-256 checksum. To install `v0.1.0`, use `--panel-only` to skip the terminal wizard. That release uses SSH access and offers manual TOML configuration under **Server**. Browser-first setup requires a newer build.

```bash
curl -fsSL https://github.com/smoothie-ws/ttui/releases/download/v0.1.0/bootstrap.sh | sudo bash -s -- --version v0.1.0 --panel-only
```

## Updates

Open **Updates** to check the latest stable GitHub release, read its notes, compare bundled component versions, and install a compatible release. The panel asks for the current administrator password before queuing the update. A systemd service continues the install while the panel restarts. Follow the result under **Update log**. The release bundle pins the Endpoint, Client, and Xray versions tested together.

```bash
ttui version
sudo ttui update
sudo ttui update --version v0.1.0
```

The installer selects the latest stable GitHub release by default. It preserves `/etc/trusttunnel`, `/var/lib/ttui`, systemd drop-in files, and `/etc/default/ttui`. It restarts active services, which can briefly interrupt VPN connections. If the update fails, the installer restores the previous application files and attempts to restart the services. Add `--allow-downgrade` to install an older release explicitly. When switching between versions with different configuration formats, restore a compatible backup.

For an older installation without the `ttui` command, run the installer again. It updates the panel and installs the command for future updates.

## Backups

Use **Backups** to select configuration components, create a ZIP archive, verify its SHA-256 checksums, and download a copy. ttui stores archives under `/var/lib/ttui/backups` with private permissions. Archives include passwords and private keys. Keep off-server copies in protected storage. Endpoint backups include Certbot configuration in `state/certbot-config.tar.gz` when available. Restore that archive separately to `/var/lib/ttui/acme` before restoring the Endpoint. Retain a separate backup of other certificate files stored outside `/etc/trusttunnel`.

Import a trusted ttui archive in **Backups**, then select **Restore** and confirm with your current administrator password. Browser imports must fit within the panel's 64 MiB request limit. Restoring replaces the matching managed files. Active services may restart, and ttui restores the previous files if they fail to start. A full Endpoint snapshot can also start a stopped Endpoint. Restoring panel settings signs out existing sessions and switches to the archived panel path and login credentials.

Under **Automatic backups**, choose a daily or weekly schedule and the components to include. ttui keeps the seven newest automatic copies. The installer also creates a configuration snapshot before updating an existing installation. These copies appear in **Backup history**.

## Releases

Work takes place on the `dev` branch. GitHub Actions runs on pushes to `dev` and `main`, and on pull requests. CI checks Python, JavaScript, and Bash, then tests installation, updates, and rollback on Linux. To prepare a stable release, update `VERSION` and [CHANGELOG.md](CHANGELOG.md) on `dev`. After the reviewed changes reach `main`, push the matching SemVer tag from a commit in the history of `main`.

```bash
git tag -a v0.1.0 -m "ttui v0.1.0"
git push origin v0.1.0
```

The **Release** workflow verifies the tagged commit, reruns the checks, and publishes the archive, SHA-256 checksum, bootstrap script, and compatibility metadata. Run `bash scripts/package.sh` to build the archive locally. Published artifacts are available from [GitHub Releases](https://github.com/smoothie-ws/ttui/releases).

## Server and clients

In each client card, set HTTP/1.1 and HTTP/2 or HTTP/3 connection limits. Blank limits inherit the Endpoint defaults. To display native session counts, traffic counters, and observed IPs in client cards, enable HTTP/1.1 and per-client metrics on a loopback address in **Endpoint settings**. Traffic counters reset when the Endpoint restarts.

Use **Server → Open endpoint settings** to configure protocol buffers and limits, native forwarding, ICMP, Prometheus metrics, or HTTPS subscriptions. In **Server → Connection filters**, add, reorder, and preview native inbound rules. ttui saves a configuration backup before applying either form and restores the previous files if the Endpoint fails to restart.

- **Clients.** Create, edit, enable, disable, or delete clients individually, and apply enable, disable, or delete to selected clients in one operation. Filter by status or search usernames, groups, devices, and notes. Export enabled clients as a `tt://` link, a locally generated QR code, or TOML. Rotating a password, disabling access, or deleting a client revokes its old access after the server restarts. An endpoint bound to loopback can run without clients for local development. The panel keeps disabled credentials and client profiles under `/var/lib/ttui`, so include that directory in protected backups.
- **TLS & Certificates.** Add, edit, and remove TLS hosts for VPN traffic, health checks, speed tests, and reverse proxies. Select existing files readable by `ttui` or upload a PEM certificate chain and private key. The panel checks the hostname, validity period, and key before applying changes, and displays expiry warnings and recent changes. For certificates renewed outside ttui, reload the endpoint after updating the files.
- **Configuration.** The editor opens `vpn.toml`, `hosts.toml`, the client credentials file, and the connection filter file. It supports the native HTTP/1.1, HTTP/2, QUIC, timeout, IPv6, ICMP, metrics, reverse proxy, subscription, and TLS filtering settings. Keep the credentials and filter files inside `/etc/trusttunnel`. Use **Startup options** to set the log level, log file, thread count, and Sentry DSN.
- Applying server configuration restarts services and may interrupt connections. If startup fails, the panel restores the previous files and attempts to restart the service. Back up both `/etc/trusttunnel` and `/var/lib/ttui`.

To switch to an existing credentials or filter file, change only its path in `vpn.toml`. After saving, the editor opens the selected file. You can save routing settings with routing disabled before configuring the endpoint.

The installer stops if it finds an unmanaged `trusttunnel.service`. To migrate an existing installation, back it up, move the configuration and certificates into `/etc/trusttunnel`, verify the paths and permissions for `ttui`, then retire the old service before installing. Reinstalling preserves the endpoint configuration, admin account, routing settings, and uploaded geodata files.

[TrustTunnel Endpoint settings](https://github.com/TrustTunnel/TrustTunnel/blob/v1.3.1/CONFIGURATION.md) | [Client exports](https://github.com/TrustTunnel/TrustTunnel/blob/v1.3.1/README.md)

## Routing and cascades

1. Add an outbound. The built-in `direct` (Freedom) and `block` (Blackhole) outbounds are available immediately. The editor supports HTTP, SOCKS5, VLESS, VMess, Trojan, Shadowsocks, and TrustTunnel. For VLESS, VMess, Trojan, and Shadowsocks, it also exposes TCP, WebSocket, gRPC, and XHTTP transport options and TLS or REALITY fields. Choose a combination supported by the remote server and validate it with Xray. Use JSON for configurations outside the form.
2. For a TrustTunnel cascade, enter the remote addresses, TLS hostname, and client credentials. You can also paste an endpoint export or a full TrustTunnel Client TOML configuration. ttui starts a separate local SOCKS5 listener for each cascade.
3. Add rules in evaluation order. The first match selects the outbound. Set a default outbound for the remaining traffic. All specified fields in a rule must match.
4. Enable routing. TrustTunnel sends traffic to Xray through a local SOCKS5 listener. Disabling routing restores the previous `forward_protocol`.

| Field | Examples |
| --- | --- |
| Domains | `domain:example.org`, `full:app.example.org`, `regexp:^.*\.example\.org$`, `geosite:category-ads-all`, `ext:custom-site.dat:group` |
| IP | `203.0.113.0/24`, `geoip:private`, `ext:custom-ip.dat:group` |
| Ports | `80,443,1000-2000` |

Upload additional Xray `.dat` databases under **Geodata files**. An optional SHA-256 value verifies uploads before replacement. Xray provides the default `geosite.dat` and `geoip.dat` files. Use **Validate in Xray** to inspect a draft without applying it. The JSON editor supports advanced rule fields and nested outbound settings.

Xray receives the destination address, port, and hostname when available. Rules apply to all clients through the shared SOCKS5 inbound. Use IP rules for connections without an available hostname. UDP support depends on the outbound. HTTP proxies handle TCP.

[Xray routing rules and geodata](https://xtls.github.io/en/config/routing.html) | [Xray outbounds](https://xtls.github.io/en/config/outbound.html) | [TrustTunnel Client SOCKS5 mode](https://github.com/TrustTunnel/TrustTunnelClient/blob/v1.3.0/trusttunnel/README.md)

## Design references

| Reference | How ttui uses it |
| --- | --- |
| [wg-easy](https://github.com/wg-easy/wg-easy) | The client list is the landing page, and exports are available from each client's actions. |
| [3x-ui](https://github.com/MHSanaei/3x-ui/blob/main/docs/content/docs/en/operations/outbounds-routing.mdx) | Named outbounds, ordered rules, geodata, and advanced editing. |
| [TrustTunnel Endpoint CLI](https://github.com/TrustTunnel/TrustTunnel/blob/v1.3.1/CONFIGURATION.md) | ttui preserves the native TOML files and delegates exports to the endpoint. The endpoint sends traffic through one SOCKS5 outbound to a separate router. |
