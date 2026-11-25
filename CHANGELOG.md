# Changelog

## Unreleased

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
