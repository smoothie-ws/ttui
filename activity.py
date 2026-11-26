"""A small, private audit trail of administrative actions."""
import json
from datetime import datetime, timezone
from threading import Lock

import backend as b

FILENAME = "activity.jsonl"
LIMIT = 500
MAX_BYTES = 256 * 1024
_lock = Lock()

LABELS = {
    "sign_in": "Administrator sign-in",
    "logout": "Administrator signed out",
    "revoke_sessions": "Signed out all sessions",
    "mfa": "Authenticator settings changed",
    "diagnostics": "Diagnostics run",
    "backups": "Backup operation",
    "updates": "Update operation",
    "update_client": "Client settings changed",
    "export": "Client connection exported",
    "save_server": "Advanced configuration saved",
    "save_launch": "Startup options saved",
    "setup_endpoint": "TrustTunnel configured",
    "endpoint": "Endpoint settings changed",
    "filters": "Connection filters changed",
    "update_tls_host": "TLS host changed",
    "save_routing": "Routing settings changed",
    "upload_geo": "Geodata file uploaded",
    "verify_geo": "Geodata checksum checked",
    "save_settings": "Panel settings changed",
}


def path():
    return b.STATE / FILENAME


def label(action):
    return LABELS.get(action, action.replace("_", " ").capitalize())


def trim():
    """Keep the newest entries and bound the file even after a long deployment."""
    source = path()
    lines = source.read_text(encoding="utf-8", errors="replace").splitlines()[-LIMIT:]
    b.atomic(source, "\n".join(lines) + ("\n" if lines else ""))


def record(action, result="completed", address=None):
    """Append one event. Auditing must never make the requested action fail."""
    entry = {
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "action": str(action)[:64],
        "label": label(str(action))[:80],
        "result": "rejected" if result == "rejected" else "completed",
        "address": str(address or "")[:64],
    }
    try:
        b.STATE.mkdir(mode=0o750, parents=True, exist_ok=True)
        with _lock:
            source = path()
            with source.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
            if source.stat().st_size > MAX_BYTES:
                trim()
    except OSError:
        pass


def recent(limit=8):
    """Return the newest events first, ignoring incomplete lines."""
    try:
        lines = path().read_text(encoding="utf-8", errors="replace").splitlines()[-LIMIT:]
    except OSError:
        return []
    events = []
    for line in reversed(lines):
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict) or not isinstance(event.get("at"), str):
            continue
        events.append({
            "at": event["at"],
            "action": str(event.get("action", ""))[:64],
            "label": str(event.get("label") or label(str(event.get("action", ""))))[:80],
            "result": event.get("result") if event.get("result") == "rejected" else "completed",
            "address": str(event.get("address", ""))[:64],
        })
        if len(events) >= max(1, min(limit, LIMIT)):
            break
    return events