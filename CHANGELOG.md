# Changelog

## Unreleased

- Safely switch between existing client credentials and connection filter files.
- Preserve the state of stopped services when applying routing changes and avoid unnecessary restarts when uploading geodata.
- Run CI on every push to `dev`.
- Translate the panel, diagnostics, and documentation into English.

## 0.1.0

- Initial TrustTunnel web panel with client management, TLS hosts, and Xray routing.
- Install from GitHub Releases and update in place with automatic recovery after a failed startup.
- Build, verify, and publish releases from SemVer tags with GitHub Actions.
