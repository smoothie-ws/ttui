"""Validation and storage for TrustTunnel TLS certificates."""
import re
import secrets
import subprocess
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Lock

import backend as b

_status_cache = {}
_status_lock = Lock()

PEM_LIMIT = 512 * 1024
DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"

def hostname(value):
    value = value.strip().lower()
    if len(value) > 253 or not re.fullmatch(rf"{DNS_LABEL}(?:\.{DNS_LABEL})*", value):
        raise ValueError("Enter a DNS hostname using ASCII letters, digits, and hyphens.")
    return value

def path(value):
    result = (b.CONFIG / value).resolve()
    if not value or not result.is_file():
        raise ValueError("Provide readable certificate chain and private key files.")
    return result

def inspect(certificate):
    output = b.command(["openssl", "x509", "-in", str(certificate), "-noout", "-enddate",
                        "-fingerprint", "-sha256"], timeout=3)
    fields = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    expiration = parsedate_to_datetime(fields.get("notAfter", ""))
    fingerprint = next((value for key, value in fields.items() if key.lower().endswith("fingerprint")), "")
    if expiration.tzinfo is None or not fingerprint:
        raise ValueError("OpenSSL did not return complete certificate information.")
    days = (expiration - datetime.now(timezone.utc)).days
    return {"expires": expiration.isoformat(timespec="minutes"), "days": days, "fingerprint": fingerprint}

def validate(certificate, key, host):
    public_cert = b.command(["openssl", "x509", "-in", str(certificate), "-noout", "-pubkey"], timeout=5)
    public_key = b.command(["openssl", "pkey", "-in", str(key), "-passin", "pass:", "-pubout"], timeout=5)
    if public_cert.strip() != public_key.strip():
        raise ValueError("The certificate and private key do not match.")
    b.command(["openssl", "verify", "-purpose", "sslserver", "-partial_chain", "-trusted", str(certificate),
               "-verify_hostname", host, str(certificate)], timeout=5)
    return inspect(certificate)

def uploaded_pair(cert_upload, key_upload, host):
    if not cert_upload or not key_upload:
        raise ValueError("Upload the certificate chain and private key together.")
    payloads = [upload.stream.read(PEM_LIMIT + 1) for upload in (cert_upload, key_upload)]
    if any(not data or len(data) > PEM_LIMIT for data in payloads):
        raise ValueError("Each PEM file must contain between 1 byte and 512 KiB.")
    pair_id = secrets.token_hex(12)
    names = {"cert_chain_path": f"tls-{pair_id}-chain.pem", "private_key_path": f"tls-{pair_id}-key.pem"}
    with TemporaryDirectory(dir=b.STATE) as directory:
        files = [Path(directory) / name for name in names.values()]
        for file, data in zip(files, payloads):
            b.atomic(file, data)
        details = validate(*files, host)
    return names, {b.CONFIG / name: data for name, data in zip(names.values(), payloads)}, details

def existing_pair(cert, key, host):
    return validate(path(cert), path(key), host)

def certificate_status(value):
    """Inspect a certificate once per file version; dashboards read it often."""
    try:
        certificate = path(value)
        info = certificate.stat()
    except (ValueError, OSError):
        return None
    key = (str(certificate), info.st_mtime_ns, info.st_ctime_ns, info.st_size)
    with _status_lock:
        if key in _status_cache:
            return _status_cache[key]
    try:
        status = inspect(certificate)
    except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired):
        status = None
    with _status_lock:
        if len(_status_cache) >= 64:
            _status_cache.clear()
        _status_cache[key] = status
    return status
