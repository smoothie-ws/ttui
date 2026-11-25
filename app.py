"""Server-rendered TrustTunnel admin panel."""
import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import time
from datetime import timedelta
from functools import wraps
from pathlib import Path
from threading import Lock

import tomlkit
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from flask.sessions import SecureCookieSessionInterface
from tomlkit.exceptions import ParseError
from waitress import serve
from werkzeug.security import check_password_hash, generate_password_hash

import backend as b

SETTINGS = b.STATE / "panel.json"
VERSION = b.read(Path(__file__).with_name("VERSION"), "dev").strip()
HOST_TYPES = {"main_hosts": "VPN", "ping_hosts": "Health check",
              "speedtest_hosts": "Speed test", "reverse_proxy_hosts": "Reverse proxy"}
FILE_KEYS = ("vpn", "hosts", "credentials", "rules")
OPERATION_ERRORS = (ValueError, ParseError, OSError, RuntimeError, subprocess.TimeoutExpired)
app = Flask(__name__)
app.config.update(MAX_CONTENT_LENGTH=64 * 1024 * 1024, MAX_FORM_MEMORY_SIZE=4 * 1024 * 1024,
                  SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Strict", PERMANENT_SESSION_LIFETIME=timedelta(hours=12))
login_attempts = []
login_lock = Lock()


def settings():
    return json.loads(b.read(SETTINGS))


def request_settings():
    return request.environ.get("ttui.settings") or settings()


class PanelSession(SecureCookieSessionInterface):
    def get_cookie_path(self, app):
        return request.script_root or "/"

    def get_cookie_secure(self, app):
        return request_settings()["secure_cookie"]


app.session_interface = PanelSession()


def mounted_app(wsgi_app):
    def dispatch(environ, start_response):
        config = environ["ttui.settings"] = settings()
        base = config["path"]
        path = environ["PATH_INFO"]
        if base:
            if path != base and not path.startswith(base + "/"):
                start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
                return [b"Not found"]
            environ["SCRIPT_NAME"] = environ.get("SCRIPT_NAME", "") + base
            environ["PATH_INFO"] = path[len(base):] or "/"
        return wsgi_app(environ, start_response)

    return dispatch


app.wsgi_app = mounted_app(app.wsgi_app)


def session_id(config):
    return hmac.digest(config["secret"].encode(), config["password_hash"].encode()
                       + config.get("session_epoch", "").encode(), "sha256").hex()


@app.before_request
def guard():
    if request.endpoint is None:
        return
    if request.endpoint not in ("login", "static") and not authenticated(request_settings()):
        return redirect(url_for("login"))
    if request.method == "POST":
        token = session.get("csrf", "")
        if not token or not hmac.compare_digest(request.form.get("csrf", "").encode(), token.encode()):
            abort(403)


@app.after_request
def headers(response):
    response.headers.update({
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    })
    return response


@app.context_processor
def template_context():
    return {"csrf": lambda: session.setdefault("csrf", secrets.token_urlsafe(32))}


def authenticated(config):
    return hmac.compare_digest(session.get("auth", ""), session_id(config))


def action(page):
    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            with b.LOCK:
                if request.method == "POST" and "ttui.settings" in request.environ:
                    request.environ["ttui.settings"] = config = settings()
                    if not authenticated(config):
                        return redirect(config["path"] + "/login")
                try:
                    return function(*args, **kwargs)
                except OPERATION_ERRORS as error:
                    flash(str(error), "error")
                    return redirect(url_for(page))
        return wrapped
    return decorate


def saved(page, message):
    flash(message)
    return redirect(url_for(page))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        with login_lock:
            now = time.monotonic()
            login_attempts[:] = [stamp for stamp in login_attempts if now - stamp < 60]
            if len(login_attempts) >= 10:
                return render_template("login.html", error="Too many attempts. Try again in a minute."), 429
            config = settings()
            password_ok = check_password_hash(config["password_hash"], request.form.get("password", ""))
            username_ok = hmac.compare_digest(config["username"].encode(), request.form.get("username", "").encode())
            if not password_ok or not username_ok:
                login_attempts.append(now)
                return render_template("login.html", error="Incorrect username or password."), 401
            login_attempts.clear()
            session.clear()
            session["auth"] = session_id(config)
            session.permanent = True
            return redirect(url_for("index"))
    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


def read_vpn():
    return tomlkit.parse(b.read(b.VPN, ""))


def server_sources():
    raw = b.read(b.VPN, "")
    try:
        vpn = tomlkit.parse(raw)
        paths = b.related(vpn)
    except (ParseError, ValueError):
        vpn, paths = {}, (b.CONFIG / "credentials.toml", b.CONFIG / "rules.toml")
    return vpn, paths, dict(vpn=raw, hosts=b.read(b.HOSTS, ""),
                            credentials=b.read(paths[0], ""), rules=b.read(paths[1], ""))


def host_groups(raw):
    hosts = tomlkit.parse(raw)
    return {group: [entry for entry in entries if isinstance(entry, dict)]
            for group in HOST_TYPES if isinstance(entries := hosts.get(group), list)}


def revision(raw):
    return hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()


def check_revision(raw):
    if request.form.get("revision") != revision(raw):
        raise ValueError("These settings changed after you opened this page. Review the latest version and try again.")


@app.get("/")
def index():
    with b.LOCK:
        try:
            vpn = read_vpn()
            entries = b.configured_clients(vpn)
            hosts = host_groups(b.read(b.HOSTS, "")).get("main_hosts", [])
            address = request_settings().get("address") or (hosts[0].get("hostname", "") if hosts else "")
            initialized = bool(vpn.get("listen_address") and hosts)
            can_remove_last = b.loopback(vpn)
        except (ParseError, ValueError, OSError):
            entries, address, initialized, can_remove_last = [], "", False, False
    return render_template("clients.html", clients=entries, address=address, initialized=initialized,
                           can_remove_last=can_remove_last, endpoint=b.service_state(b.ENDPOINT_UNIT))


@app.post("/clients")
@action("index")
def update_client():
    vpn = read_vpn()
    credentials, _ = b.related(vpn)
    doc = tomlkit.parse(b.read(credentials, ""))
    entries = b.clients(doc)
    name = request.form.get("username", "").strip()
    operation = request.form.get("operation")
    if not vpn.get("credentials_file"):
        if operation != "create":
            raise ValueError("The client credentials file is disabled.")
        if entries:
            raise ValueError("Select the existing client credentials file in Server settings.")
    existing = next((entry for entry in entries if entry["username"] == name), None)
    password = None
    if operation in ("create", "rotate"):
        password = request.form.get("password") or secrets.token_urlsafe(24)
        if len(password) > 512 or any(ord(c) < 32 for c in password):
            raise ValueError("The password is too long or contains control characters.")
    if operation == "create":
        if existing or not re.fullmatch(r"[^\s\x00-\x1f:]{1,64}", name):
            raise ValueError("Enter a unique username of up to 64 characters, with no spaces or colons.")
        if "client" not in doc:
            doc["client"] = tomlkit.aot()
        doc["client"].append({"username": name, "password": password})
    elif operation == "rotate" and existing is not None:
        existing["password"] = password
    elif operation == "delete" and existing is not None:
        entries.remove(existing)
    else:
        raise ValueError("Client not found.")
    changes = {credentials: tomlkit.dumps(doc)}
    if not vpn.get("credentials_file"):
        vpn["credentials_file"] = str(credentials.relative_to(b.CONFIG))
        changes[b.VPN] = tomlkit.dumps(vpn)
    b.apply_endpoint(changes, vpn)
    return saved("index", "Clients updated.")


@app.post("/export")
@action("index")
def export():
    name = request.form.get("username", "")
    if not any(entry["username"] == name for entry in b.configured_clients(read_vpn())):
        raise ValueError("Client not found.")
    return render_template("export.html", username=name, content=b.export_client(name, request.form),
                           fmt=request.form.get("format"))


def render_server(source, version, error=None):
    try:
        hosts = host_groups(source["hosts"])
    except ParseError:
        hosts = {}
    return render_template("server.html", source=source, revision=version, save_error=error,
                           host_types=HOST_TYPES, hosts=hosts, routed=b.load_routing()["enabled"],
                           launch=b.launch_options())


@app.get("/server")
@action("index")
def server():
    _, _, source = server_sources()
    return render_server(source, revision(source))


@app.post("/server")
@action("server")
def save_server():
    data = {key: request.form.get(key, "").replace("\r\n", "\n").replace("\r", "\n") for key in FILE_KEYS}
    before, old_paths, previous = server_sources()
    check_revision(previous)
    try:
        vpn = tomlkit.parse(data["vpn"])
        tomlkit.parse(data["hosts"])
        for key in ("credentials", "rules"):
            option = f"{key}_file"
            if not vpn.get(option) and not before.get(option) and data[key].strip() and data[key] != previous[key]:
                vpn[option] = f"{key}.toml"
        changes = {b.HOSTS: data["hosts"], b.VPN: tomlkit.dumps(vpn)}
        for key, path, old_path in zip(("credentials", "rules"), b.related(vpn), old_paths):
            if not vpn.get(f"{key}_file"):
                continue
            if path != old_path and path.exists():
                if data[key] != previous[key]:
                    raise ValueError(f"Select the existing {key}_file first, then edit its contents.")
                tomlkit.parse(b.read(path))
            else:
                tomlkit.parse(data[key])
                changes[path] = data[key]
        b.apply_endpoint(changes, vpn)
    except OPERATION_ERRORS as error:
        return render_server(data, request.form["revision"], str(error)), 400
    return saved("server", "Configuration saved. TrustTunnel restarted.")


@app.post("/launch")
@action("server")
def save_launch():
    options = {key: request.form.get(key, "").strip() for key in
               ("loglvl", "logfile", "jobs", "sentry_dsn")}
    b.endpoint_command(options)
    b.apply_endpoint({b.LAUNCH: json.dumps(options, indent=2) + "\n"}, read_vpn())
    return saved("server", "Startup options saved.")


@app.post("/hosts")
@action("server")
def add_host():
    vpn, _, source = server_sources()
    check_revision(source)
    hosts = tomlkit.parse(source["hosts"])
    group = request.form.get("group")
    if group not in HOST_TYPES:
        raise ValueError("Unknown host type.")
    hostname = request.form.get("hostname", "").strip()
    if not hostname or any(character.isspace() for character in hostname):
        raise ValueError("Enter a hostname.")
    records = hosts.get(group, [])
    if any(host.get("hostname", "").casefold() == hostname.casefold() for host in records):
        raise ValueError("This hostname already exists in the selected group.")
    record = {"hostname": hostname}
    for key in ("cert_chain_path", "private_key_path"):
        value = request.form.get(key, "").strip()
        if not value or not (b.CONFIG / value).is_file():
            raise ValueError(f"TrustTunnel must be able to read the file specified by {key}.")
        record[key] = value
    if group not in hosts:
        hosts[group] = tomlkit.aot()
    hosts[group].append(record)
    b.apply_endpoint({b.HOSTS: tomlkit.dumps(hosts)}, vpn)
    return saved("server", "Host added.")


def render_routing(source, version, error=None):
    return render_template("routing.html", source=source, revision=version, save_error=error,
                           geofiles=sorted(path.name for path in b.GEO.glob("*.dat")),
                           router=b.service_state(b.ROUTER_UNIT))


@app.get("/routing")
@action("index")
def routing():
    spec = b.load_routing()
    version = revision(spec)
    spec.pop("_native_forward", None)
    return render_routing(json.dumps(spec, ensure_ascii=False, indent=2), version)


@app.post("/routing")
@action("routing")
def save_routing():
    check_revision(b.load_routing())
    source = request.form.get("spec", "")
    try:
        b.apply_routing(json.loads(source))
    except OPERATION_ERRORS as error:
        return render_routing(source, request.form["revision"], str(error)), 400
    return saved("routing", "Routing settings saved.")


@app.post("/geofiles")
@action("routing")
def upload_geo():
    upload = request.files.get("data")
    if not upload or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}\.dat", upload.filename or ""):
        raise ValueError("Select an Xray .dat file.")
    if not upload.stream.read(1):
        raise ValueError("The file is empty.")
    upload.stream.seek(0)
    b.replace_geofile(upload.filename, upload.stream)
    return saved("routing", "Geodata file saved.")


@app.get("/settings")
def panel_settings():
    return render_template("settings.html", config=request_settings(), version=VERSION)


def clean_path(value):
    if value == "/":
        return ""
    if not re.fullmatch(r"(?:/[A-Za-z0-9_-]+)+", value):
        raise ValueError("The path must start with / and contain only letters AвЂ“Z, digits, underscores, hyphens, and slash separators.")
    return value


@app.post("/settings")
@action("panel_settings")
def save_settings():
    config = request_settings().copy()
    form = request.form
    path = clean_path(form.get("path", "").strip())
    username = form.get("username", "").strip()
    password = form.get("password", "")
    if not username or len(username) > 64 or (password and not 12 <= len(password) <= 256):
        raise ValueError("Enter a username of up to 64 characters and a new password of 12вЂ“256 characters.")
    if not check_password_hash(config["password_hash"], form.get("current_password", "")):
        raise ValueError("Enter the current password.")
    old_path = config["path"]
    secure = form.get("secure_cookie") == "on"
    changed_login = username != config["username"] or bool(password)
    config.update(path=path, address=form.get("address", "").strip(),
                  username=username, secure_cookie=secure)
    if password:
        config["password_hash"] = generate_password_hash(password)
    if changed_login or path != old_path:
        config["session_epoch"] = secrets.token_hex(16)
        session.clear()
    b.write_json(SETTINGS, config)
    request.environ["ttui.settings"] = config
    if changed_login or path != old_path:
        return redirect(path + "/login")
    return saved("panel_settings", "Panel settings saved.")


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--init", action="store_true")
    mode.add_argument("--panel-info", action="store_true")
    mode.add_argument("--reset-login", action="store_true")
    mode.add_argument("--run-endpoint", action="store_true")
    mode.add_argument("--routing-enabled", action="store_true")
    parser.add_argument("--path")
    parser.add_argument("--username")
    args = parser.parse_args()
    os.umask(0o077)
    if args.panel_info:
        config = settings()
        print(f"Panel path: {config['path'] or '/'}")
        print(f"Administrator username: {config['username']}")
        return
    if args.routing_enabled:
        raise SystemExit(0 if b.load_routing()["enabled"] else 1)
    if args.run_endpoint:
        vpn = read_vpn()
        b.check_clients(vpn)
        command_line = b.endpoint_command(b.launch_options())
        os.chdir(b.CONFIG)
        os.execv(b.ENDPOINT, command_line)
    if args.init or args.reset_login:
        b.STATE.mkdir(parents=True, exist_ok=True)
        b.GEO.mkdir(exist_ok=True)
        if args.reset_login or not SETTINGS.exists():
            config = settings() if SETTINGS.exists() else {"secret": secrets.token_hex(32), "address": ""}
            password = secrets.token_urlsafe(24)
            path = clean_path(args.path) if args.path is not None else config.get("path", "/ttui")
            config.update(path=path, username=args.username or config.get("username", "admin"),
                          password_hash=generate_password_hash(password), secure_cookie=False)
            b.write_json(SETTINGS, config)
            print(f"ttui {path or '/'} | {config['username']} | {password}")
        return
    app.secret_key = settings()["secret"]
    serve(app, host=os.environ.get("TTUI_BIND", "127.0.0.1"), port=int(os.environ.get("TTUI_PORT", "8080")),
          threads=4, max_request_body_size=app.config["MAX_CONTENT_LENGTH"])


if __name__ == "__main__":
    main()
