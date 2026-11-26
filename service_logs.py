"""Read a bounded set of journals through fixed sudo permissions."""
import json
import re
from datetime import datetime, timezone

import backend as b

SOURCES = {
    "panel": ("ttui", "ttui.service", None),
    "endpoint": ("TrustTunnel Endpoint", "trusttunnel.service", None),
    "router": ("Routing service", "ttui-router.service", None),
    "xray": ("Xray", "ttui-router.service", "ttui-xray"),
    "cascade": ("TrustTunnel Client", "ttui-router.service", "ttui-cascade"),
    "caddy": ("Caddy", "caddy.service", None),
    "acme": ("VPN certificate renewal", "ttui-acme.service", None),
    "backups": ("Scheduled backups", "ttui-backups.service", None),
    "updates": ("Updates", "ttui-update.service", None),
}
LEVELS = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Info", "Debug"]

def read_logs(source, query="", priority=None, after=None, before=None):
    _, unit, identifier = SOURCES[source]
    args = ["/usr/bin/sudo", "-n", "/usr/bin/journalctl",
            "--no-pager", "--output=json", "--lines=500", f"--unit={unit}"]
    if identifier:
        args.append(f"--identifier={identifier}")
    raw = b.command(args, timeout=10)
    rows = []
    for line in reversed(raw.splitlines()):
        try:
            event = json.loads(line)
            when = int(event["__REALTIME_TIMESTAMP"]) / 1_000_000
            message = event["MESSAGE"]
            if isinstance(message, list) and all(isinstance(part, int) for part in message):
                message = bytes(message).decode("utf-8", errors="replace")
            level = int(event.get("PRIORITY", 6))
            if not isinstance(message, str) or not 0 <= level < len(LEVELS):
                continue
        except (KeyError, ValueError, TypeError):
            continue
        if identifier and level == 6:
            hint = re.search(r"\[(warning|error|debug)\]|\b(WARN|ERROR|DEBUG)\b", message, re.IGNORECASE)
            if hint:
                level = {"warning": 4, "warn": 4, "error": 3, "debug": 7}[hint.group().strip("[]").lower()]
        if (priority is not None and level > priority or after is not None and when < after
                or before is not None and when > before or query.casefold() not in message.casefold()):
            continue
        rows.append({"time": datetime.fromtimestamp(when, timezone.utc).isoformat(timespec="seconds"),
                     "level": LEVELS[level], "message": message})
    return rows
