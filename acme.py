"""Certbot integration for VPN TLS. This state is separate from Caddy's certificates."""
import json
import os
import re
import stat

import tomlkit

import backend as b
import certificates as tls

CHALLENGE_PREFIX = "/.well-known/acme-challenge/"


def enabled():
    return os.environ.get("TTUI_ACME") == "1"


def webroot():
    return b.STATE / "acme" / "webroot"


def challenge(token):
    if not enabled() or not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", token):
        return None
    directory = webroot() / ".well-known" / "acme-challenge"
    try:
        descriptor = os.open(directory / token, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as file:
            if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
                return None
            value = file.read(4097)
    except OSError:
        return None
    return value if 0 < len(value) <= 4096 else None


def certbot(*arguments, timeout):
    state = b.STATE / "acme"
    return b.command(["certbot", "--non-interactive", "--config-dir", str(state / "config"),
                      "--work-dir", str(state / "work"), "--logs-dir", str(state / "logs"),
                      *arguments], timeout=timeout)


def live_pair(host):
    live = b.STATE / "acme" / "config" / "live" / host
    return {"cert_chain_path": str(live / "fullchain.pem"), "private_key_path": str(live / "privkey.pem")}


def issue(host, email):
    if not enabled():
        raise ValueError("ACME HTTP-01 is not enabled for this installation.")
    host = tls.hostname(host)
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise ValueError("Enter an ACME contact email address.")
    webroot().mkdir(parents=True, exist_ok=True)
    certbot("certonly", "--webroot", "-w", str(webroot()), "--cert-name", host,
            "--domain", host, "--email", email, "--agree-tos", "--keep-until-expiring", timeout=75)
    pair = live_pair(host)
    return pair, tls.existing_pair(*pair.values(), host)


def renew():
    if not enabled() or not b.HOSTS.is_file():
        return
    fingerprints = {}
    hosts = tomlkit.parse(b.read(b.HOSTS))
    for entries in hosts.values():
        if not isinstance(entries, list):
            continue
        for record in entries:
            host = record.get("hostname", "") if isinstance(record, dict) else ""
            if not isinstance(host, str) or not host or host in fingerprints:
                continue
            pair = live_pair(host)
            if any(record.get(key) != path for key, path in pair.items()):
                continue
            host = tls.hostname(host)
            certbot("renew", "--cert-name", host, timeout=180)
            fingerprints[host] = tls.existing_pair(*pair.values(), host)["fingerprint"]
    if not fingerprints:
        return
    marker = b.STATE / "acme" / "loaded.json"
    if fingerprints == json.loads(b.read(marker, "{}")):
        return
    if b.service_state(b.ENDPOINT_UNIT) == "active":
        b.service("reload", b.ENDPOINT_UNIT)
        b.write_json(marker, fingerprints)
        print(f"Reloaded TrustTunnel with {len(fingerprints)} managed certificate(s).")
