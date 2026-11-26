"""Client records beyond the fields supported by native TrustTunnel credentials."""
import json
import re
import secrets
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPException
from ipaddress import ip_address

import tomlkit

import backend as b

PROFILE_FIELDS = {"group": 64, "device": 128, "notes": 1000}
LIMIT_FIELDS = {"max_http2_conns": "HTTP/1.1 and HTTP/2 limit", "max_http3_conns": "HTTP/3 limit"}
METRICS_LIMIT = 4 * 1024 * 1024


def client_statistics(vpn):
    metrics = vpn.get("metrics")
    protocols = vpn.get("listen_protocols")
    if (not isinstance(metrics, dict) or metrics.get("per_client_metrics") is not True
            or not isinstance(protocols, dict) or "http1" not in protocols):
        return None
    try:
        interface, port = metrics.get("address", "127.0.0.1:1987").rsplit(":", 1)
        address = ip_address(interface.strip("[]"))
        if not address.is_loopback or not 1 <= int(port) <= 65535:
            return None
    except (AttributeError, TypeError, ValueError):
        return None
    connection = HTTPConnection(str(address), int(port), timeout=0.75)
    try:
        connection.request("GET", "/clients", headers={"Connection": "close"})
        with connection.getresponse() as response:
            if response.status != 200:
                return None
            payload = response.read(METRICS_LIMIT + 1)
        if len(payload) > METRICS_LIMIT:
            return None
        clients = json.loads(payload)
        if not isinstance(clients, list):
            return None
        rows = {}
        for item in clients:
            if (not isinstance(item, dict) or not isinstance(item.get("username"), str)
                    or not item["username"] or item["username"] in rows
                    or any(type(item.get(key)) is not int or not 0 <= item[key] <= 2**64 - 1
                           for key in ("sessions", "inbound", "outbound"))):
                return None
            row = {key: item[key] for key in ("sessions", "inbound", "outbound")}
            try:
                row["ip"] = str(ip_address(item.get("ip"))) if isinstance(item.get("ip"), str) else None
            except ValueError:
                row["ip"] = None
            rows[item["username"]] = row
        return rows
    except (OSError, HTTPException, ValueError):
        return None
    finally:
        connection.close()


class ClientManager:
    def __init__(self, vpn):
        self.vpn = vpn
        self.credentials, _ = b.related(vpn)
        self.document = tomlkit.parse(b.read(self.credentials, ""))
        self.entries = b.clients(self.document)
        self.path = b.STATE / "clients.json"
        self.store = json.loads(b.read(self.path, "{}"))
        self.scope = str(self.credentials.relative_to(b.CONFIG))
        self.records = self.store.setdefault(self.scope, {})

    def visible(self, query="", status=""):
        active = {entry["username"] for entry in self.entries} if self.vpn.get("credentials_file") else set()
        disabled = {name for name, record in self.records.items() if "disabled" in record}
        result = []
        for name in sorted(active | disabled, key=str.casefold):
            saved = self.records.get(name, {})
            row = {"username": name, "enabled": name in active, "created": saved.get("created", "")}
            row["history"] = saved.get("history", [])[::-1]
            row.update((key, saved.get(key, "")) for key in PROFILE_FIELDS)
            if status == ("disabled" if row["enabled"] else "enabled"):
                continue
            if not query or any(query in row[key].casefold() for key in ("username", *PROFILE_FIELDS)):
                result.append(row)
        return result

    def native_entry(self, name):
        return next((entry for entry in self.entries if entry["username"] == name), None)

    def display_limits(self, rows):
        active = {entry["username"]: entry for entry in self.entries}
        for row in rows:
            name = row["username"]
            if row["enabled"]:
                entry = active[name]
            else:
                raw = self.records[name]["disabled"]
                try:
                    entry = tomlkit.parse(raw) if isinstance(raw, str) else {}
                except tomlkit.exceptions.ParseError:
                    entry = {}
            row.update((key, entry.get(key, "")) for key in LIMIT_FIELDS)

    @staticmethod
    def save_limits(entry, form):
        for key, label in LIMIT_FIELDS.items():
            if key not in form:
                continue
            value = form[key].strip()
            if not value:
                entry.pop(key, None)
            elif not value.isascii() or not value.isdecimal() or len(value) > 10 or int(value) > 2**32 - 1:
                raise ValueError(f"{label} must be between 0 and 4294967295.")
            else:
                entry[key] = int(value)

    def ensure_unique(self, name):
        if (not re.fullmatch(r"[^\s\x00-\x1f:]{1,64}", name)
                or self.native_entry(name) is not None or "disabled" in self.records.get(name, {})):
            raise ValueError("Enter a unique username of up to 64 characters, with no spaces or colons.")

    def append(self, entry):
        if "client" not in self.document:
            self.document["client"] = tomlkit.aot()
        self.document["client"].append(entry)
        self.entries = self.document["client"]

    def change(self, name, operation, form, *, active_lookup=None, removals=None):
        active = self.native_entry(name) if active_lookup is None else active_lookup.get(name)
        record = self.records.get(name, {})
        disabled = tomlkit.parse(record["disabled"]) if "disabled" in record else None
        if active is not None and disabled is not None:
            raise ValueError("This username also exists in disabled clients. Resolve the duplicate in the credentials file.")
        if active is None and disabled is None and operation != "create":
            raise ValueError("Client not found.")
        if operation == "create":
            self.ensure_unique(name)
            entry = {"username": name, "password": self.password(form)}
            self.save_limits(entry, form)
            self.append(entry)
            self.records[name] = {"created": datetime.now(timezone.utc).date().isoformat()}
        elif operation == "disable" and active is not None:
            self.records.setdefault(name, {})["disabled"] = tomlkit.dumps(active)
            if removals is None:
                self.entries.remove(active)
            else:
                removals.add(name)
        elif operation == "enable" and disabled is not None:
            record.pop("disabled")
            self.append(dict(disabled))
        elif operation == "delete":
            if active is not None:
                if removals is None:
                    self.entries.remove(active)
                else:
                    removals.add(name)
            self.records.pop(name, None)
        elif operation == "rotate":
            (active if active is not None else disabled)["password"] = self.password(form)
            if disabled is not None:
                record["disabled"] = tomlkit.dumps(disabled)
        elif operation == "edit":
            new_name = form.get("new_username", "").strip()
            if new_name != name:
                self.ensure_unique(new_name)
            for key, limit in PROFILE_FIELDS.items():
                value = form.get(key, "").strip()
                if len(value) > limit:
                    raise ValueError(f"The {key} field is too long.")
                record[key] = value
            entry = active if active is not None else disabled
            self.save_limits(entry, form)
            entry["username"] = new_name
            if disabled is not None:
                record["disabled"] = tomlkit.dumps(disabled)
            self.records.pop(name, None)
            self.records[new_name] = record
            name = new_name
        else:
            raise ValueError("The selected operation does not apply to this client.")
        if operation != "delete":
            history = self.records.setdefault(name, {}).setdefault("history", [])
            history.append({"action": operation, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
            del history[:-20]

    def change_many(self, names, operation, form):
        if len(names) <= 1 or operation not in ("enable", "disable", "delete"):
            for name in names:
                self.change(name, operation, form)
            return
        lookup = {entry["username"]: entry for entry in self.entries}
        removals = set()
        for name in names:
            self.change(name, operation, form, active_lookup=lookup, removals=removals)
        if removals:
            entries = tomlkit.aot()
            for entry in self.entries:
                if entry["username"] not in removals:
                    entries.append(entry)
            self.document["client"] = self.entries = entries

    @staticmethod
    def password(form):
        password = form.get("password") or secrets.token_urlsafe(24)
        if len(password) > 512 or any(ord(char) < 32 for char in password):
            raise ValueError("The password is too long or contains control characters.")
        return password

    def save(self, native_before):
        native = tomlkit.dumps(self.document)
        data = json.dumps(self.store, ensure_ascii=False, indent=2) + "\n"
        # Profile-only edits and edits to disabled clients do not affect live VPN sessions.
        if native == native_before:
            b.atomic(self.path, data)
            return
        changes = {self.credentials: native, self.path: data}
        if not self.vpn.get("credentials_file"):
            self.vpn["credentials_file"] = self.scope
            changes[b.VPN] = tomlkit.dumps(self.vpn)
        b.apply_endpoint(changes, self.vpn)
