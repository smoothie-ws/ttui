"""Client records beyond the fields supported by native TrustTunnel credentials."""
import json
import re
import secrets
from datetime import datetime, timezone

import tomlkit

import backend as b

PROFILE_FIELDS = {"group": 64, "device": 128, "notes": 1000}


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

    def ensure_unique(self, name):
        if (not re.fullmatch(r"[^\s\x00-\x1f:]{1,64}", name)
                or self.native_entry(name) is not None or "disabled" in self.records.get(name, {})):
            raise ValueError("Enter a unique username of up to 64 characters, with no spaces or colons.")

    def append(self, entry):
        if "client" not in self.document:
            self.document["client"] = tomlkit.aot()
        self.document["client"].append(entry)
        self.entries = self.document["client"]

    def change(self, name, operation, form):
        active = self.native_entry(name)
        record = self.records.get(name, {})
        disabled = tomlkit.parse(record["disabled"]) if "disabled" in record else None
        if active is not None and disabled is not None:
            raise ValueError("This username also exists in disabled clients. Resolve the duplicate in the credentials file.")
        if active is None and disabled is None and operation != "create":
            raise ValueError("Client not found.")
        if operation == "create":
            self.ensure_unique(name)
            self.append({"username": name, "password": self.password(form)})
            self.records[name] = {"created": datetime.now(timezone.utc).date().isoformat()}
        elif operation == "disable" and active is not None:
            self.records.setdefault(name, {})["disabled"] = tomlkit.dumps(active)
            self.entries.remove(active)
        elif operation == "enable" and disabled is not None:
            record.pop("disabled")
            self.append(dict(disabled))
        elif operation == "delete":
            if active is not None:
                self.entries.remove(active)
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
            (active if active is not None else disabled)["username"] = new_name
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
