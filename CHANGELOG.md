# Changelog

## Unreleased

## 0.2.0

- Install the web panel with managed HTTPS and initial administrator credentials; configure TrustTunnel in the browser without its terminal wizard.
- Back up and restore managed Certbot configuration and custom geodata, with recovery if a service fails to start.
- Exercise clean installation, VPN routing, recovery, and upgrades from v0.1.0 in Linux CI.
- Set native per-client connection limits, view live counters from loopback Endpoint metrics, and navigate long client lists by page.
- Configure native HTTP and QUIC settings, limits, forwarding, metrics, ICMP, subscriptions, and inbound connection filters through forms. Save a backup before applying a reviewed change.
- Protect administrator sign-in with an optional TOTP authenticator and IP allowlist. Review administrative actions from the settings page.
- Check official releases and install compatible upgrades from the panel. Verify the sign-in page before accepting a restarted panel service.
- Create, download, verify, import, and restore private configuration backups. Schedule automatic backups in the panel and save a configuration snapshot before an upgrade.
- Review host resource history, inspect or download component journals, and run service diagnostics from the panel.
- Configure VLESS, VMess, Trojan, Shadowsocks, and TrustTunnel cascades in the visual routing editor. Validate drafts in Xray and verify geodata uploads by SHA-256.
- Issue and renew VPN certificates with Let's Encrypt on managed Caddy installations.
- Manage VPN TLS hosts and PEM uploads, with certificate validation, expiry warnings, and change history.
- Manage client profiles, search and filter clients, enable or disable accounts, and perform bulk actions. Export connection QR codes locally.
- Configure the endpoint and first client from the web panel after installation.
- Safely switch between existing client credentials and connection filter files.
- Preserve the state of stopped services when applying routing changes and avoid unnecessary restarts when uploading geodata.
- Run CI on every push to `dev`.
- Translate the panel, diagnostics, and documentation into English.

## 0.1.0

- Initial TrustTunnel web panel with client management, TLS hosts, and Xray routing.
- Install from GitHub Releases and update in place with automatic recovery after a failed startup.
- Build, verify, and publish releases from SemVer tags with GitHub Actions.
