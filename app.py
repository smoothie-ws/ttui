"""Server-rendered TrustTunnel admin panel."""
import argparse
from difflib import unified_diff
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import subprocess
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from http.client import HTTPConnection, HTTPException
from ipaddress import ip_address
from pathlib import Path
from tempfile import TemporaryDirectory

import tomlkit
import qrcode
from qrcode.exceptions import DataOverflowError
from qrcode.image.svg import SvgPathFillImage
from flask import Flask, Response, abort, flash, redirect, render_template, request, send_file, session, url_for
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import BadData, URLSafeTimedSerializer
from tomlkit.exceptions import ParseError
from waitress import serve
from werkzeug.security import check_password_hash, generate_password_hash

import backend as b
import acme
import auth
import backups as snapshots
from routing import compile_routing
import certificates as tls
import diagnostics as system_diagnostics
import endpoint_settings as endpoint_form
import service_logs
import updates as updater
from client_manager import ClientManager, LIMIT_FIELDS, client_statistics
from monitoring import PERIODS, collect_sample, history, host_metrics

SETTINGS = b.STATE / "panel.json"
VERSION = b.read(Path(__file__).with_name("VERSION"), "dev").strip()
PUBLIC_HTTPS = os.environ.get("TTUI_REQUIRE_HTTPS") == "1"
HOST_TYPES = {"main_hosts": "VPN", "ping_hosts": "Health check",
              "speedtest_hosts": "Speed test", "reverse_proxy_hosts": "Reverse proxy"}
FILE_KEYS = ("vpn", "hosts", "credentials", "rules")
OPERATION_ERRORS = (ValueError, ParseError, OSError, RuntimeError, subprocess.TimeoutExpired)
app = Flask(__name__)
app.config.update(MAX_CONTENT_LENGTH=64 * 1024 * 1024, MAX_FORM_MEMORY_SIZE=4 * 1024 * 1024,
                  SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Strict", PERMANENT_SESSION_LIFETIME=timedelta(hours=12))


def settings():
    return json.loads(b.read(SETTINGS))


def request_settings():
    return request.environ.get("ttui.settings") or settings()


class PanelSession(SecureCookieSessionInterface):
    def get_cookie_path(self, app):
        return request.script_root or "/"

    def get_cookie_secure(self, app):
        return PUBLIC_HTTPS or request_settings()["secure_cookie"]


app.session_interface = PanelSession()


def mounted_app(wsgi_app):
    def dispatch(environ, start_response):
        if environ["PATH_INFO"].startswith(acme.CHALLENGE_PREFIX):
            return wsgi_app(environ, start_response)
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


def health_token(config):
    return hmac.digest(config["secret"].encode(), b"ttui sign-in health check", "sha256").hex()


@app.before_request
def guard():
    if request.endpoint in (None, "acme_challenge"):
        return
    config = request_settings()
    if not auth.address_allowed(config.get("ip_allowlist", []), request.remote_addr or ""):
        is_probe = (request.endpoint == "login" and request.method == "GET"
                    and hmac.compare_digest(request.headers.get("X-Ttui-Health", "").encode(), health_token(config).encode()))
        if not is_probe:
            abort(403)
    protected = request.endpoint not in ("login", "static")
    if protected and not authenticated(config):
        return redirect(url_for("login"))
    if request.method == "POST":
        if protected:
            request.environ["ttui.audit_action"] = request.endpoint
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
    event = request.environ.get("ttui.audit_action")
    if event:
        result = "rejected" if response.status_code >= 400 or request.environ.get("ttui.action_failed") else "completed"
        app.logger.info("Audit: %s %s from %r", event, result, request.remote_addr)
    return response


@app.get(acme.CHALLENGE_PREFIX + "<token>")
def acme_challenge(token):
    payload = acme.challenge(token)
    if payload is None:
        abort(404)
    return payload, 200, {"Content-Type": "text/plain; charset=ascii"}


@app.context_processor
def template_context():
    return {"csrf": lambda: session.setdefault("csrf", secrets.token_urlsafe(32))}


def authenticated(config):
    return hmac.compare_digest(session.get("auth", ""), session_id(config))


def action(page):
    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            try:
                with (b.configuration_change() if request.method == "POST" else b.LOCK):
                    if request.method == "POST" and "ttui.settings" in request.environ:
                        request.environ["ttui.settings"] = config = settings()
                        if not auth.address_allowed(config.get("ip_allowlist", []), request.remote_addr or ""):
                            abort(403)
                        if not authenticated(config):
                            request.environ["ttui.action_failed"] = True
                            return redirect(config["path"] + "/login")
                    return function(*args, **kwargs)
            except OPERATION_ERRORS as error:
                request.environ["ttui.action_failed"] = True
                flash(str(error), "error")
                return redirect(url_for(page))
        return wrapped
    return decorate


def saved(page, message):
    flash(message)
    return redirect(url_for(page))


def panel_bind():
    host = "127.0.0.1" if PUBLIC_HTTPS else os.environ.get("TTUI_BIND", "127.0.0.1")
    return host, int(os.environ.get("TTUI_PORT", "8080"))


def verify_panel_http():
    host, port = panel_bind()
    host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(host, host)
    config = settings()
    path = config["path"] + "/login"
    headers = {"X-Ttui-Health": health_token(config)}
    for _ in range(12):
        connection = HTTPConnection(host, port, timeout=1)
        try:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            if response.status == 200 and b'name="csrf"' in response.read(65536):
                return
        except (OSError, HTTPException):
            pass
        finally:
            connection.close()
        time.sleep(0.5)
    raise RuntimeError("The panel sign-in page did not respond on its configured address.")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        address = request.remote_addr or "unknown"
        database = b.STATE / "sign-in.sqlite3"
        if delay := auth.reserve_attempt(database, address):
            return render_template("login.html", error="Too many attempts. Try again in a minute."), 429, {
                "Retry-After": str(delay),
            }
        config = settings()
        if not auth.address_allowed(config.get("ip_allowlist", []), address):
            abort(403)
        password = request.form.get("password", "")
        password_ok = len(password) <= 256 and check_password_hash(config["password_hash"], password)
        username_ok = hmac.compare_digest(config["username"].encode(), request.form.get("username", "").encode())
        secret = config.get("totp_secret")
        if not password_ok or not username_ok or (secret and not auth.use_totp(database, secret, request.form.get("code", ""))):
            app.logger.info("Audit: sign-in rejected from %r", address)
            return render_template("login.html", error="Incorrect credentials or authenticator code."), 401
        auth.clear_attempts(database, address)
        app.logger.info("Audit: sign-in completed from %r", address)
        session.clear()
        session["auth"] = session_id(config)
        session.permanent = True
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.post("/sessions/revoke")
@action("panel_settings")
def revoke_sessions():
    config = request_settings().copy()
    if not check_password_hash(config["password_hash"], request.form.get("current_password", "")):
        raise ValueError("Enter the current password.")
    config["session_epoch"] = secrets.token_hex(16)
    b.write_json(SETTINGS, config)
    session.clear()
    return redirect(url_for("login"))


@app.post("/mfa")
@action("panel_settings")
def mfa():
    config = request_settings().copy()
    operation = request.form.get("operation")
    serializer = URLSafeTimedSerializer(config["secret"], salt="ttui-totp-enrollment")
    database = b.STATE / "sign-in.sqlite3"
    code = request.form.get("code", "")
    if operation in ("begin", "disable") and not check_password_hash(
        config["password_hash"], request.form.get("current_password", "")
    ):
        raise ValueError("Enter the current password.")
    if operation == "begin" and not config.get("totp_secret"):
        secret = auth.new_totp_secret()
        enrollment = serializer.dumps({"secret": secret, "csrf": session["csrf"]})
        account = f"{config['username']}@{request.host[:128]}"
        svg = qrcode.make(auth.totp_uri(secret, account), image_factory=SvgPathFillImage)
        return render_template("mfa.html", enrollment=enrollment, secret=secret, qr=svg.to_string(encoding="unicode"))
    if operation == "enable" and not config.get("totp_secret"):
        try:
            pending = serializer.loads(request.form.get("enrollment", ""), max_age=600)
        except BadData as error:
            raise ValueError("Set up the authenticator again. The setup link has expired or is invalid.") from error
        if not isinstance(pending, dict) or pending.get("csrf") != session.get("csrf"):
            raise ValueError("Start authenticator setup in this session.")
        secret = pending.get("secret")
        if not auth.use_totp(database, secret, code):
            raise ValueError("The authenticator code was invalid or already used. Start setup again.")
        config["totp_secret"] = secret
    elif operation == "disable" and config.get("totp_secret"):
        if not auth.use_totp(database, config["totp_secret"], code):
            raise ValueError("Enter a fresh authenticator code.")
        config.pop("totp_secret")
    else:
        raise ValueError("The requested authenticator change is unavailable.")
    config["session_epoch"] = secrets.token_hex(16)
    b.write_json(SETTINGS, config)
    session["auth"] = session_id(config)
    session.pop("csrf", None)
    app.logger.info("Audit: authenticator %s from %r", "enabled" if operation == "enable" else "disabled", request.remote_addr)
    return saved("panel_settings", "Authenticator settings saved. Other sessions were signed out.")


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
def dashboard():
    vpn = {}
    with b.LOCK:
        configured = b.VPN.is_file() and b.HOSTS.is_file()
        try:
            if configured:
                vpn = read_vpn()
            accounts = {entry["username"] for entry in b.configured_clients(vpn)}
        except OPERATION_ERRORS:
            accounts = None
    live = client_statistics(vpn) if accounts else None
    connected = sum(name in accounts and item["sessions"] > 0 for name, item in live.items()) if live is not None else None
    return render_template("dashboard.html", version=VERSION,
                           endpoint=b.service_state(b.ENDPOINT_UNIT) if configured else "unconfigured",
                           router=b.service_state(b.ROUTER_UNIT), clients=len(accounts) if accounts is not None else None,
                           connected=connected,
                           metrics=host_metrics(b.STATE))


@app.get("/clients")
def index():
    query = request.args.get("q", "").strip()[:256]
    status = request.args.get("status", "")
    page = max(1, request.args.get("page", 1, type=int))
    page_size = 50
    stats = None
    with b.LOCK:
        try:
            vpn = read_vpn()
            manager = ClientManager(vpn)
            entries = manager.visible(query.casefold(), status)
            count = len(entries)
            pages = max(1, (count + page_size - 1) // page_size)
            page = min(page, pages)
            entries = entries[(page - 1) * page_size:page * page_size]
            manager.display_limits(entries)
            enabled_count = len(manager.entries) if vpn.get("credentials_file") else 0
            hosts = host_groups(b.read(b.HOSTS, "")).get("main_hosts", [])
            address = request_settings().get("address") or (hosts[0].get("hostname", "") if hosts else "")
            initialized = bool(vpn.get("listen_address") and hosts)
            can_remove_last = b.loopback(vpn)
        except OPERATION_ERRORS:
            vpn, count, page, pages = {}, 0, 1, 1
            entries, enabled_count, address, initialized, can_remove_last = [], 0, "", False, False
    if initialized and entries:
        stats = client_statistics(vpn)
    metrics = vpn.get("metrics")
    metrics_unavailable = bool(entries and isinstance(metrics, dict) and metrics.get("per_client_metrics") and stats is None)
    return render_template("clients.html", clients=entries, address=address, initialized=initialized,
                           enabled_count=enabled_count, can_remove_last=can_remove_last,
                           query=query, status=status, endpoint=b.service_state(b.ENDPOINT_UNIT),
                           count=count, page=page, pages=pages, stats=stats, limit_fields=LIMIT_FIELDS,
                           metrics_unavailable=metrics_unavailable)


@app.get("/monitoring")
def monitoring():
    period = request.args.get("period", "1h")
    if period not in PERIODS:
        abort(400)
    services = {"ttui": b.service_state("ttui.service"), "TrustTunnel": b.service_state(b.ENDPOINT_UNIT),
                "Xray routing": b.service_state(b.ROUTER_UNIT)}
    if acme.enabled():
        services["Caddy"] = b.service_state("caddy.service")
    return render_template("monitoring.html", period=period, periods=PERIODS, samples=history(b.STATE, period),
                           services=services, uptime=host_metrics(b.STATE, sample_cpu=False)["uptime"])


@app.get("/logs")
def logs():
    source = request.args.get("source", "panel")
    period = request.args.get("period", "")
    query = request.args.get("q", "").strip()[:200]
    level = request.args.get("level", "")
    if (source not in service_logs.SOURCES or period and period not in PERIODS
            or level not in ("", "3", "4", "6", "7")):
        abort(400)
    try:
        rows = service_logs.read_logs(source, query, int(level) if level else None,
                                      time.time() - PERIODS[period] if period else None)
    except OPERATION_ERRORS:
        rows = []
        error = "The service journal is unavailable. Check the service and ttui's journal permissions."
    else:
        error = None
    filters = {"source": source, "period": period, "level": level, "q": query}
    if request.args.get("download") == "1":
        if error:
            return Response(error, status=503, mimetype="text/plain")
        text = "\n".join(f"{row['time']} [{row['level']}] {row['message']}" for row in rows)
        return Response(text + "\n" if rows else "", mimetype="text/plain",
                        headers={"Content-Disposition": f'attachment; filename="ttui-{source}.log"'})
    return render_template("logs.html", filters=filters, sources=service_logs.SOURCES,
                           periods=PERIODS, rows=rows, error=error, follow=request.args.get("follow") == "1")


@app.route("/diagnostics", methods=["GET", "POST"])
@action("diagnostics")
def diagnostics():
    rows = system_diagnostics.check() if request.method == "POST" else []
    return render_template("diagnostics.html", rows=rows)


@app.route("/backups", methods=["GET", "POST"])
@action("backups")
def backups():
    if request.method == "POST":
        operation = request.form.get("operation")
        if operation == "create":
            snapshots.create(request.form.getlist("component"), VERSION)
            return saved("backups", "Backup created.")
        if operation == "schedule":
            snapshots.schedule(request.form.get("interval", ""), request.form.getlist("component"))
            return saved("backups", "Backup schedule saved.")
        if operation == "verify":
            snapshots.verify(request.form.get("name", ""))
            return saved("backups", "Backup integrity verified.")
        if operation == "import":
            upload = request.files.get("archive")
            if not upload or not upload.filename:
                raise ValueError("Choose a ttui backup ZIP file.")
            snapshots.import_archive(upload.stream)
            return saved("backups", "Backup imported and verified.")
        if operation == "restore":
            config = request_settings()
            if not check_password_hash(config["password_hash"], request.form.get("current_password", "")):
                raise ValueError("Enter your current administrator password.")
            path = snapshots.restore(request.form.get("name", ""), config, request.remote_addr or "")
            if path is not None:
                session.clear()
                if path == config["path"]:
                    flash("Backup restored. Sign in with the restored credentials.")
                return redirect(path + "/login")
            return saved("backups", "Backup restored.")
        raise ValueError("Unknown backup operation.")
    return render_template("backups.html", archives=snapshots.history(), components=snapshots.COMPONENTS,
                           schedule=snapshots.load_schedule(), intervals=snapshots.INTERVALS)


@app.get("/backups/<name>")
def download_backup(name):
    try:
        path = snapshots.archive_path(name)
    except (ValueError, OSError):
        abort(404)
    return send_file(path, mimetype="application/zip", as_attachment=True, max_age=0)


@app.route("/updates", methods=["GET", "POST"])
@action("updates")
def updates():
    release = None
    if request.method == "POST":
        operation = request.form.get("operation")
        if operation == "check":
            release = updater.latest(VERSION)
        elif operation == "install":
            if not check_password_hash(request_settings()["password_hash"], request.form.get("current_password", "")):
                raise ValueError("Enter your current administrator password.")
            release = updater.latest(VERSION)
            if not release["compatible"]:
                raise ValueError(release["problem"])
            if release["tag"] != request.form.get("tag"):
                raise ValueError("The latest release changed. Check the release notes again before installing.")
            updater.queue(release["tag"])
            return saved("updates", "Update requested. The panel may disconnect briefly while it restarts.")
        else:
            raise ValueError("Unknown update operation.")
    return render_template("updates.html", version=VERSION, release=release, update=updater.status(),
                           installed=updater.installed_components(VERSION), names=updater.COMPONENTS)


@app.post("/clients")
@action("index")
def update_client():
    manager = ClientManager(read_vpn())
    operation = request.form.get("operation", "")
    if not manager.vpn.get("credentials_file") and manager.entries:
        raise ValueError("Select the existing client credentials file in Server settings.")
    names = list(dict.fromkeys(request.form.getlist("selected"))) if operation.startswith("bulk-") else [
        request.form.get("username", "").strip()
    ]
    operation = operation.removeprefix("bulk-")
    if not names:
        raise ValueError("Select at least one client.")
    if len(names) > 1 and operation not in ("enable", "disable", "delete"):
        raise ValueError("Unknown bulk operation.")
    before = tomlkit.dumps(manager.document)
    for name in names:
        manager.change(name, operation, request.form)
    manager.save(before)
    return saved("index", "Clients updated.")


@app.post("/export")
@action("index")
def export():
    name = request.form.get("username", "")
    if not any(entry["username"] == name for entry in b.configured_clients(read_vpn())):
        raise ValueError("Client not found.")
    content = b.export_client(name, request.form)
    fmt = request.form.get("format", "deeplink")
    qr_svg = None
    if fmt == "deeplink":
        try:
            qr_svg = qrcode.make(content, image_factory=SvgPathFillImage).to_string(encoding="unicode")
        except DataOverflowError:
            pass
    return render_template("export.html", username=name, content=content, fmt=fmt, qr_svg=qr_svg)


def render_server(source, version, error=None):
    return render_template("server.html", source=source, revision=version, save_error=error,
                           routed=b.load_routing()["enabled"], launch=b.launch_options(),
                           can_setup=not b.VPN.exists() and not b.HOSTS.exists(),
                           acme_enabled=acme.enabled(),
                           default_endpoint_port=8443 if PUBLIC_HTTPS else 443)


@app.get("/server")
@action("index")
def server():
    _, _, source = server_sources()
    return render_server(source, revision(source))


@app.route("/endpoint", methods=["GET", "POST"])
@action("server")
def endpoint():
    raw = b.read(b.VPN)
    vpn = tomlkit.parse(raw)
    hosts_raw = b.read(b.HOSTS, "")
    routing_raw = b.read(b.ROUTING, "")
    routed = b.load_routing()["enabled"]
    original = (raw, hosts_raw, routing_raw)
    preview = None
    if request.method == "POST":
        check_revision(original)
        endpoint_form.update(vpn, request.form, (80, 443) if PUBLIC_HTTPS else (), routed)
        endpoint_form.validate(vpn, tomlkit.parse(hosts_raw))
        b.check_clients(vpn)
        if vpn.get("rules_file") and not b.related(vpn)[1].is_file():
            raise ValueError("The specified connection filter file does not exist.")
        candidate = tomlkit.dumps(vpn)
        if request.form.get("operation") == "apply":
            if request.form.get("candidate") != revision(candidate) or candidate == raw:
                raise ValueError("Preview the current changes before applying them.")
            snapshots.create(["endpoint", "clients"], VERSION, reason="pre-config")
            b.apply_endpoint({b.VPN: candidate}, vpn)
            return saved("endpoint", "TrustTunnel settings applied. Previous configuration saved in Backups.")
        if request.form.get("operation") != "preview":
            abort(400)
        preview = "".join(unified_diff(raw.splitlines(keepends=True), candidate.splitlines(keepends=True),
                                       fromfile="Current", tofile="Proposed"))
    return render_template("endpoint.html", values=endpoint_form.values(vpn), groups=endpoint_form.FIELDS,
                           protocols=endpoint_form.PROTOCOLS, revision=revision(original), preview=preview,
                           candidate=revision(tomlkit.dumps(vpn)), form_schema=endpoint_form, routed=routed)


@app.route("/filters", methods=["GET", "POST"])
@action("server")
def filters():
    raw = b.read(b.VPN)
    vpn = tomlkit.parse(raw)
    path = b.related(vpn)[1]
    rules = b.read(path, "")
    document = tomlkit.parse(rules)
    rows = endpoint_form.filter_rows(document)
    enabled = bool(vpn.get("rules_file"))
    original = (raw, rules)
    preview = None
    candidate_id = ""
    if request.method == "POST":
        check_revision(original)
        b.check_clients(vpn)
        state = request.form.get("state")
        if state not in ("on", "off"):
            raise ValueError("Select whether connection filtering is enabled.")
        enabled = state == "on"
        changes = {}
        if enabled:
            vpn.setdefault("rules_file", path.relative_to(b.CONFIG).as_posix())
            rows = endpoint_form.update_filters(document, request.form)
            updated = tomlkit.dumps(document)
            if updated != rules or not path.is_file():
                changes[path] = updated
        else:
            vpn.pop("rules_file", None)
        next_vpn = tomlkit.dumps(vpn)
        if next_vpn != raw:
            changes[b.VPN] = next_vpn
        candidate_id = revision([enabled, next_vpn, changes.get(path, rules)])
        if request.form.get("operation") == "apply":
            if request.form.get("candidate") != candidate_id or not changes:
                raise ValueError("Preview the current filters before applying them.")
            snapshots.create(["endpoint", "clients"], VERSION, reason="pre-config")
            b.apply_endpoint(changes, vpn)
            return saved("filters", "Connection filters applied.")
        if request.form.get("operation") != "preview":
            abort(400)
        preview = "".join(line for filename, before, after in (
            ("vpn.toml", raw, next_vpn), (path.name, rules, changes.get(path, rules))
        ) for line in unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                   fromfile=filename, tofile=filename + " (proposed)"))
    return render_template("filters.html", rows=rows, filename=path.relative_to(b.CONFIG).as_posix(), enabled=enabled,
                           revision=revision(original), candidate=candidate_id, preview=preview)


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


@app.post("/setup")
@action("server")
def setup_endpoint():
    if b.VPN.exists() or b.HOSTS.exists():
        raise ValueError("Endpoint configuration already exists. Use the TOML editor to change it.")
    form = request.form
    hostname = tls.hostname(form.get("hostname", ""))
    address = ip_address(form.get("bind", "").strip())
    port = int(form.get("port", ""))
    if not 1 <= port <= 65535:
        raise ValueError("Enter a port from 1 to 65535.")
    if PUBLIC_HTTPS and port in (80, 443):
        raise ValueError("Ports 80 and 443 are reserved for panel HTTPS. Choose another VPN port.")
    username = form.get("username", "").strip()
    if not re.fullmatch(r"[^\s\x00-\x1f:]{1,64}", username):
        raise ValueError("Enter a username of up to 64 characters, with no spaces or colons.")
    password = secrets.token_urlsafe(24)
    bind = f"[{address}]" if address.version == 6 else str(address)
    vpn = tomlkit.item({
        "listen_address": f"{bind}:{port}", "credentials_file": "credentials.toml",
        "allow_private_network_connections": False, "listen_protocols": {"http2": {}},
    })
    if form.get("quic"):
        vpn["listen_protocols"]["quic"] = {}
    credentials, _ = b.related(vpn)
    changes = {credentials: tomlkit.dumps({"client": [{"username": username, "password": password}]})}
    cert, key = (form.get(field, "").strip() for field in ("cert_chain_path", "private_key_path"))
    if email := form.get("acme_email", "").strip():
        if cert or key or not form.get("acme_terms"):
            raise ValueError("Choose ACME as the only certificate source and accept the ACME terms.")
        pair, _ = acme.issue(hostname, email)
        cert, key = pair.values()
    elif cert or key:
        tls.existing_pair(cert, key, hostname)
    else:
        cert, key = "endpoint-cert.pem", "endpoint-key.pem"
        for path in (b.CONFIG / cert, b.CONFIG / key):
            changes[path] = b""
    if any(path.exists() or path.is_symlink() for path in changes):
        raise ValueError("Setup would replace an existing file. Use the TOML editor to reuse it.")
    if b.CONFIG / cert in changes:
        with TemporaryDirectory(dir=b.STATE) as directory:
            outputs = [Path(directory) / name for name in (cert, key)]
            b.command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365",
                       "-subj", f"/CN={hostname}", "-addext", f"subjectAltName=DNS:{hostname}",
                       "-out", str(outputs[0]), "-keyout", str(outputs[1])])
            for name, output in zip((cert, key), outputs):
                changes[b.CONFIG / name] = output.read_bytes()
    changes[b.HOSTS] = tomlkit.dumps({"main_hosts": [
        {"hostname": hostname, "cert_chain_path": cert, "private_key_path": key},
    ]})
    changes[b.VPN] = tomlkit.dumps(vpn)
    b.apply_endpoint(changes, vpn)
    return saved("index", "TrustTunnel is running. Open the first client's actions to export a connection.")


@app.get("/tls")
def tls_hosts():
    with b.LOCK:
        try:
            raw = b.read(b.HOSTS, "")
            hosts = host_groups(raw)
            history = json.loads(b.read(b.STATE / "tls-history.json", "[]"))
            configured = b.VPN.is_file()
        except OPERATION_ERRORS as error:
            flash(str(error), "error")
            return redirect(url_for("server"))
    certificate_info = {}
    for records in hosts.values():
        for record in records:
            path = record.get("cert_chain_path", "")
            if isinstance(path, str) and path not in certificate_info:
                certificate_info[path] = tls.certificate_status(path)
    return render_template("tls.html", hosts=hosts, host_types=HOST_TYPES, revision=revision(raw),
                           certificate_info=certificate_info, history=history, configured=configured,
                           acme_enabled=acme.enabled())


@app.post("/tls")
@action("tls_hosts")
def update_tls_host():
    raw = b.read(b.HOSTS, "")
    check_revision(raw)
    hosts = tomlkit.parse(raw)
    form = request.form
    operation = form.get("operation")
    source = form.get("source")
    target = form.get("group")
    if operation not in ("create", "edit", "delete"):
        raise ValueError("Unknown TLS operation.")
    if operation != "delete" and target not in HOST_TYPES:
        raise ValueError("Unknown host type.")
    record = {}
    if operation != "create":
        index = form.get("index", type=int)
        records = hosts.get(source, []) if source in HOST_TYPES else []
        if index is None or not isinstance(records, list) or not 0 <= index < len(records):
            raise ValueError("TLS host not found.")
        record = records.pop(index)
    changes = {}
    details = {}
    if operation == "delete" and not hosts.get("main_hosts"):
        raise ValueError("Keep at least one VPN TLS host.")
    if operation != "delete":
        name = tls.hostname(form.get("hostname", ""))
        if target not in hosts:
            hosts[target] = tomlkit.aot()
        records = hosts[target]
        if not isinstance(records, list):
            raise ValueError("Fix the TLS host table in the advanced editor first.")
        if any(host.get("hostname", "").casefold() == name for host in records):
            raise ValueError("This hostname already exists in the selected group.")
        cert_upload, key_upload = (request.files.get(key) for key in ("certificate", "private_key"))
        if email := form.get("acme_email", "").strip():
            if cert_upload or key_upload or not form.get("acme_terms"):
                raise ValueError("Choose ACME instead of an upload and accept the ACME terms.")
            paths, details = acme.issue(name, email)
        elif cert_upload or key_upload:
            paths, changes, details = tls.uploaded_pair(cert_upload, key_upload, name)
        else:
            paths = {key: form.get(key, "").strip() for key in ("cert_chain_path", "private_key_path")}
            details = tls.existing_pair(*paths.values(), name)
        record.update(hostname=name, **paths)
        if operation == "edit" and source == target:
            records.insert(index, record)
        else:
            records.append(record)
        if not hosts.get("main_hosts"):
            raise ValueError("Keep at least one VPN TLS host.")
    history_file = b.STATE / "tls-history.json"
    history = json.loads(b.read(history_file, "[]"))
    history.insert(0, {"operation": operation, "hostname": record["hostname"],
                       "at": datetime.now(timezone.utc).isoformat(timespec="seconds"), **details})
    changes[history_file] = json.dumps(history[:50], ensure_ascii=False, indent=2) + "\n"
    changes[b.HOSTS] = tomlkit.dumps(hosts)
    b.apply_endpoint(changes, read_vpn())
    return saved("tls_hosts", "TLS hosts updated.")


def render_routing(source, version, error=None):
    geofiles = []
    for path in sorted(b.GEO.glob("*.dat")):
        if path.is_file() and not path.is_symlink():
            info = path.stat()
            geofiles.append({"name": path.name, "size": info.st_size,
                            "updated": datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(timespec="minutes")})
    return render_template("routing.html", source=source, revision=version, save_error=error,
                           geofiles=geofiles,
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
        spec = json.loads(source)
        if request.form.get("operation") == "validate":
            b.validate_xray(compile_routing(spec)[0])
            flash("Xray accepted the proposed configuration.")
            return render_routing(source, request.form["revision"])
        b.apply_routing(spec)
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
    expected = request.form.get("sha256", "").strip().lower()
    if expected:
        if not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise ValueError("Enter a 64-character SHA-256 checksum.")
        digest = hashlib.sha256()
        for chunk in iter(lambda: upload.stream.read(128 * 1024), b""):
            digest.update(chunk)
        if digest.hexdigest() != expected:
            raise ValueError("The geodata file does not match its SHA-256 checksum.")
        upload.stream.seek(0)
    b.replace_geofile(upload.filename, upload.stream)
    return saved("routing", "Geodata file saved.")


@app.get("/settings")
def panel_settings():
    return render_template("settings.html", config=request_settings(), version=VERSION, https_required=PUBLIC_HTTPS)


def clean_path(value):
    if value == "/":
        return ""
    if not re.fullmatch(r"(?:/[A-Za-z0-9_-]+)+", value):
        raise ValueError("The path must start with / and contain only letters A-Z, digits, underscores, hyphens, and slash separators.")
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
        raise ValueError("Enter a username of up to 64 characters and a new password of 12-256 characters.")
    if not check_password_hash(config["password_hash"], form.get("current_password", "")):
        raise ValueError("Enter the current password.")
    old_path = config["path"]
    secure = PUBLIC_HTTPS or form.get("secure_cookie") == "on"
    if "ip_allowlist" in form:
        value = form["ip_allowlist"]
        if len(value) > 4096:
            raise ValueError("The IP allowlist is too long.")
        networks = auth.normalize_networks(re.split(r"[\s,]+", value.strip()) if value.strip() else [])
        if not auth.address_allowed(networks, request.remote_addr or ""):
            raise ValueError("Include your current IP address in the allowlist or leave the allowlist empty.")
        config["ip_allowlist"] = networks
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
    mode.add_argument("--verify-panel-http", action="store_true")
    mode.add_argument("--reset-login", action="store_true")
    mode.add_argument("--run-endpoint", action="store_true")
    mode.add_argument("--routing-enabled", action="store_true")
    mode.add_argument("--renew-certificates", action="store_true")
    mode.add_argument("--sample-metrics", action="store_true")
    mode.add_argument("--scheduled-backup", action="store_true")
    parser.add_argument("--path")
    parser.add_argument("--username")
    parser.add_argument("--clear-totp", action="store_true")
    parser.add_argument("--clear-allowlist", action="store_true")
    args = parser.parse_args()
    if (args.clear_totp or args.clear_allowlist) and not args.reset_login:
        parser.error("--clear-totp and --clear-allowlist require --reset-login")
    os.umask(0o077)
    if args.sample_metrics:
        collect_sample(b.STATE)
        return
    if args.scheduled_backup:
        with b.configuration_change():
            snapshots.run_scheduled(VERSION)
        return
    if args.renew_certificates:
        with b.configuration_change():
            acme.renew()
        return
    if args.panel_info:
        config = settings()
        print(f"Panel path: {config['path'] or '/'}")
        print(f"Administrator username: {config['username']}")
        return
    if args.verify_panel_http:
        verify_panel_http()
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
                          password_hash=generate_password_hash(password), secure_cookie=config.get("secure_cookie", False))
            if args.clear_totp:
                config.pop("totp_secret", None)
            if args.clear_allowlist:
                config.pop("ip_allowlist", None)
            b.write_json(SETTINGS, config)
            print(f"ttui {path or '/'} | {config['username']} | {password}")
        return
    app.secret_key = settings()["secret"]
    app.logger.setLevel(logging.INFO)
    app.logger.propagate = False
    host, port = panel_bind()
    proxy = {"trusted_proxy": "127.0.0.1",
             "trusted_proxy_count": 1, "clear_untrusted_proxy_headers": True,
             "trusted_proxy_headers": {"x-forwarded-for", "x-forwarded-proto"}} if PUBLIC_HTTPS else {}
    serve(app, host=host, port=port,
          threads=4, max_request_body_size=app.config["MAX_CONTENT_LENGTH"], **proxy)


if __name__ == "__main__":
    main()
