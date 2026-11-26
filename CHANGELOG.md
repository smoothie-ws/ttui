# Changelog

Versions are named by publication date: YY.MM.DD.

## 26.11.26

First MVP release of the ttui web panel for a single TrustTunnel Endpoint.

- Browser-first setup: managed HTTPS with Caddy, initial administrator credentials, and one-click node creation on the panel hostname.
- Dashboard with service states, node readiness, host resources, traffic and load history, certificate expiry warnings, and recent administrative activity.
- Client management with `tt://` links, QR codes, TOML exports, per-client connection limits, and live counters from loopback Endpoint metrics.
- TrustTunnel endpoint settings, TLS hosts, connection filters, advanced TOML editing, and startup options with reviewed diffs and automatic recovery.
- Xray routing editor with outbounds, ordered rules, geodata uploads, and TrustTunnel cascades.
- Backups with verification, import, restore, and schedules; TOTP authenticator and IP allowlist; service logs and diagnostics.
- In-panel updates from official GitHub releases with a configuration snapshot and rollback on failure.
- Minimal borderless interface in the agentsys-client style with dark and light themes.
- Release archive ships minified sources without documentation files; installed services skip bytecode caches.
