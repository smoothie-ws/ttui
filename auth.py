"""Administrator sign-in limits, one-time codes and IP restrictions."""
import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from contextlib import closing
from ipaddress import ip_address, ip_network
from urllib.parse import quote, urlencode

WINDOW = 60
LIMIT = 10
OTP_PERIOD = 30

def reserve_attempt(database, address, now=None):
    now = int(time.time()) if now is None else now
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
            address TEXT NOT NULL, started INTEGER NOT NULL, attempts INTEGER NOT NULL,
            PRIMARY KEY (address)
        )""")
        connection.execute("DELETE FROM login_attempts WHERE started <= ?", (now - WINDOW,))
        row = connection.execute(
            "SELECT started, attempts FROM login_attempts WHERE address = ?", (address,)
        ).fetchone()
        if row and row[1] >= LIMIT:
            return max(1, min(WINDOW, row[0] + WINDOW - now))
        connection.execute("""INSERT INTO login_attempts VALUES (?, ?, 1)
            ON CONFLICT(address) DO UPDATE SET attempts = attempts + 1""", (address, now))
        return 0

def clear_attempts(database, address):
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("DELETE FROM login_attempts WHERE address = ?", (address,))

def normalize_networks(value):
    if not isinstance(value, list) or len(value) > 64 or any(
        not isinstance(item, str) or len(item) > 64 or "%" in item for item in value
    ):
        raise ValueError("Enter up to 64 IPv4 or IPv6 addresses or CIDR ranges.")
    try:
        return list(dict.fromkeys(str(ip_network(item, strict=False)) for item in value))
    except ValueError as error:
        raise ValueError("Enter valid IPv4 or IPv6 addresses or CIDR ranges.") from error

def address_allowed(networks, address):
    if networks == []:
        return True
    try:
        ip = ip_address(address)
        candidates = (ip, ip.ipv4_mapped) if getattr(ip, "ipv4_mapped", None) else (ip,)
        return any(candidate in ip_network(network) for network in normalize_networks(networks) for candidate in candidates)
    except ValueError:
        return False

def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")

def valid_totp_secret(secret):
    return isinstance(secret, str) and re.fullmatch(r"[A-Z2-7]{32}", secret) is not None

def totp_uri(secret, account):
    label = "ttui:" + quote(account.replace(":", " "), safe="")
    query = urlencode({"secret": secret, "issuer": "ttui"})
    return f"otpauth://totp/{label}?{query}"

def totp_code(key, counter, digits=6):
    digest = hmac.digest(key, counter.to_bytes(8, "big"), "sha1")
    offset = digest[-1] & 15
    number = int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff
    return str(number % 10 ** digits).zfill(digits)

def use_totp(database, secret, code, now=None):
    if not valid_totp_secret(secret) or not re.fullmatch(r"[0-9]{6}", code):
        return False
    step = int(time.time() if now is None else now) // OTP_PERIOD
    key = base64.b32decode(secret)
    matches = [counter for counter in range(max(0, step - 1), step + 2)
               if hmac.compare_digest(totp_code(key, counter), code)]
    if not matches:
        return False
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("CREATE TABLE IF NOT EXISTS totp_steps (key_id TEXT PRIMARY KEY, last_step INTEGER NOT NULL)")
        accepted = connection.execute("""INSERT INTO totp_steps VALUES (?, ?)
            ON CONFLICT(key_id) DO UPDATE SET last_step = excluded.last_step
            WHERE excluded.last_step > totp_steps.last_step""", (hashlib.sha256(key).hexdigest(), max(matches)))
        return accepted.rowcount == 1
