"""FastAPI backend + dashboard. Start with run.bat (binds to 127.0.0.1 only)."""
import json
import os
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

import platform

import html
import webbrowser

from . import __version__, apikey, autostart, backup, config, control, errors, db, detector, ingest, intel, monitor, oauth_gmail, providers, reports, secrets_store, settings, splunk
from . import health as health_checks  # NOT 'health': the /api/health route function below is named health()

STATIC = Path(__file__).parent / "static"
_fails = defaultdict(deque)


get_api_key = apikey.get_api_key  # re-exported for compatibility


@asynccontextmanager
async def lifespan(app):
    db.init()
    n = db.purge()
    db.add_event("startup", f"EmailShield API started; retention purge removed {n} message(s)")
    print(f"\n  EmailShield dashboard: http://{config.HOST}:{config.PORT}\n  API key (paste into dashboard): {get_api_key()}\n")
    yield


app = FastAPI(title="EmailShield", docs_url=None, redoc_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def auth(request: Request, x_api_key: str = Header(default="")):
    client = request.client.host if request.client else "unknown"
    q, t = _fails[client], time.monotonic()
    while q and t - q[0] > 60:
        q.popleft()
    if len(q) >= 10:
        raise HTTPException(429, "Too many failed attempts; wait a minute")
    if not secrets.compare_digest(x_api_key.encode("utf-8", "ignore"), get_api_key().encode()):
        q.append(t)
        db.add_audit("anonymous", "auth_failed", client)
        raise HTTPException(401, "Invalid or missing API key")
    return "analyst"


async def read_limited(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > config.MAX_EML_BYTES:
        raise HTTPException(413, "File too large")
    buf = bytearray()
    async for chunk in request.stream():
        buf.extend(chunk)
        if len(buf) > config.MAX_EML_BYTES:
            raise HTTPException(413, "File too large")
    return bytes(buf)


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/config")
def public_config(actor: str = Depends(auth)):
    return {"ti_enabled": config.TI_ENABLED, "ti_providers": [p.name for p in intel.default_providers()],
            "retention_days": config.RETENTION_DAYS, "max_upload_mb": config.MAX_EML_BYTES // (1024 * 1024),
            "thresholds": config.THRESHOLDS, "statuses": config.STATUSES, "version": __version__,
            "platform": f"{platform.system()} {platform.release()}", "python": platform.python_version(),
            "data_dir": str(config.DATA_DIR), "bind": f"{config.HOST}:{config.PORT}",
            "remote_access": config.HOST not in ("127.0.0.1", "::1", "localhost")}


@app.post("/api/analyze")
async def analyze(request: Request, filename: str = "upload.eml", actor: str = Depends(auth)):
    if not filename.lower().endswith(".eml"):
        raise HTTPException(400, "Only .eml files are accepted")
    result = ingest.ingest_bytes(await read_limited(request), filename)
    db.add_audit(actor, "analyze", f"{os.path.basename(filename)[:100]} ok={result['ok']}")
    return JSONResponse(result, status_code=200 if result["ok"] else 422)


@app.get("/api/stats")
def stats(actor: str = Depends(auth)):
    return db.stats()


@app.get("/api/messages")
def messages(q: str = "", category: str = "", status: str = "", account: str = None, actor: str = Depends(auth)):
    return db.list_messages(q[:200], category, status, account_id=account)


@app.get("/api/messages/{mid}")
def message(mid: int, actor: str = Depends(auth)):
    m = db.get_message(mid)
    if not m:
        raise HTTPException(404, "Not found")
    return m


@app.patch("/api/messages/{mid}")
async def patch(mid: int, request: Request, actor: str = Depends(auth)):
    try:
        body = json.loads((await read_limited(request)) or b"{}")
        if not isinstance(body, dict):
            raise ValueError("JSON object expected")
        m = db.update_message(mid, body.get("status"), body.get("notes"), actor)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if not m:
        raise HTTPException(404, "Not found")
    db.add_audit(actor, "update", f"#{mid} status={body.get('status')}")
    return m


@app.get("/api/messages/{mid}/related")
def related(mid: int, cross_account: bool = False, actor: str = Depends(auth)):
    """Same mailbox only by default (account isolation); cross_account=true is an explicit, audited choice."""
    if cross_account:
        db.add_audit(actor, "cross_account_correlation", f"#{mid}")
    return db.find_related(mid, cross_account)


@app.post("/api/messages/{mid}/enrich")
def enrich(mid: int, actor: str = Depends(auth)):
    if not db.get_message(mid):
        raise HTTPException(404, "Not found")
    db.add_audit(actor, "enrich", f"#{mid}")
    return intel.enrich(mid)


@app.get("/api/messages/{mid}/report")
def report(mid: int, format: str = "json", actor: str = Depends(auth)):
    if format not in ("json", "txt", "html"):
        raise HTTPException(400, "format must be json, txt or html")
    rep = reports.build_report(mid)
    if not rep:
        raise HTTPException(404, "Not found")
    db.add_audit(actor, "report", f"#{mid} {format}")
    body, mime = {"json": (json.dumps(rep, indent=2), "application/json"),
                  "txt": (reports.to_text(rep), "text/plain"),
                  "html": (reports.to_html(rep), "text/html")}[format]
    return Response(body, media_type=mime, headers={"Content-Disposition": f'attachment; filename="{rep["report_id"]}.{format}"'})


@app.get("/api/events")
def events(actor: str = Depends(auth)):
    return db.list_events()


@app.get("/api/audit")
def audit(actor: str = Depends(auth)):
    return db.list_audit()


@app.get("/api/monitoring")
def monitoring(actor: str = Depends(auth)):
    return monitor.overview()


async def body_json(request):
    try:
        data = json.loads((await read_limited(request)) or b"{}")
    except ValueError:
        raise HTTPException(400, "Invalid JSON")
    if not isinstance(data, dict):
        raise HTTPException(400, "JSON object expected")
    return data


def get_acct(aid):
    a = db.get_account(aid)
    if not a:
        raise HTTPException(404, "Account not found")
    return a


# ---------- mailbox connection workflow ----------
@app.get("/api/connectors/gmail")
def gmail_status(actor: str = Depends(auth)):
    return {"credentials_configured": bool(secrets_store.get("gmail_client_id") and secrets_store.get("gmail_client_secret")),
            "redirect_uri": f"http://{config.HOST if config.HOST in ('127.0.0.1', 'localhost') else '127.0.0.1'}:{config.PORT}/oauth/gmail/callback",
            "scope": providers.GMAIL_SCOPE, "push_notifications": "not implemented (polling with history sync is used)"}


@app.put("/api/connectors/gmail/credentials")
async def gmail_credentials(request: Request, actor: str = Depends(auth)):
    """Paste the contents of the OAuth 'Desktop app' client JSON. Write-only: stored in the secret store, never returned."""
    data = await body_json(request)
    try:
        c = json.loads(data.get("client_secret_json", ""))
        c = c.get("installed") or c.get("web") or c
        cid, sec = c["client_id"], c["client_secret"]
        if not (isinstance(cid, str) and isinstance(sec, str) and cid and sec):
            raise ValueError
    except (ValueError, KeyError, TypeError, AttributeError):
        raise HTTPException(400, "That is not a valid Google OAuth client JSON (needs client_id and client_secret).")
    secrets_store.set("gmail_client_id", cid)
    secrets_store.set("gmail_client_secret", sec)
    db.add_audit(actor, "gmail_credentials_saved")
    return {"credentials_configured": True}


@app.post("/api/connectors/gmail/connect")
async def gmail_connect(request: Request, actor: str = Depends(auth)):
    cid = secrets_store.get("gmail_client_id")
    if not (cid and secrets_store.get("gmail_client_secret")):
        raise HTTPException(409, "Save your Google OAuth client credentials first.")
    redirect = gmail_status(actor)["redirect_uri"]
    url = oauth_gmail.start(cid, redirect)
    opened = False
    if config.HOST in ("127.0.0.1", "localhost", "::1") and (await body_json(request)).get("open_browser"):
        try:
            opened = webbrowser.open(url)
        except Exception:
            opened = False
    db.add_audit(actor, "gmail_connect_started")
    return {"auth_url": url, "browser_opened": opened}


@app.get("/oauth/gmail/callback")
def gmail_callback(state: str = "", code: str = "", error: str = "", error_description: str = ""):
    """Google redirects the browser here. No API key is possible, so the one-time PKCE `state` is the credential."""
    def page(title, msg, ok):
        body = (f"<!doctype html><meta charset='utf-8'><title>{html.escape(title)}</title><link rel='stylesheet' href='/static/style.css'>"
                f"<main><h2>{html.escape(title)}</h2><p>{html.escape(msg)}</p><p><a href='/#monitoring'>Return to EmailShield</a></p></main>")
        return Response(body, media_type="text/html", status_code=200 if ok else 400)
    try:
        if error:
            db.add_audit("oauth-callback", "gmail_authorization_error", error[:60])  # the code only; never the free-text description
            raise oauth_gmail.OAuthError(oauth_gmail.explain_error(error, error_description))
        tokens = oauth_gmail.finish(state, code, secrets_store.get("gmail_client_id"), secrets_store.get("gmail_client_secret"))
        email = oauth_gmail.fetch_email(tokens["access_token"])
    except oauth_gmail.OAuthError as e:
        db.add_audit("oauth-callback", "gmail_connect_failed", str(e)[:150])
        return page("Could not connect the mailbox", str(e), False)
    aid = f"gmail:{email}"
    secrets_store.set(f"gmail_refresh_token:{aid}", tokens["refresh_token"])
    db.upsert_account(aid, "gmail", email, "connected", monitoring_enabled=None)
    db.set_account(aid, status="connected", last_error=None, consecutive_failures=0)
    db.add_audit("oauth-callback", "gmail_connected", aid)
    return page("Mailbox connected", "Return to EmailShield and switch monitoring on when you are ready. Nothing is scanned until you do.", True)


@app.post("/api/connectors/folder")
async def add_folder(request: Request, actor: str = Depends(auth)):
    """A local-folder 'mailbox' (drop .eml files in a directory): useful for demos and testing without any provider account."""
    data = await body_json(request)
    path = str(data.get("path") or config.INBOX_DIR)
    from pathlib import Path
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    if not p.is_dir():
        raise HTTPException(400, "Not a folder")
    a = db.upsert_account("folder:default", "folder", f"Local folder: {p.name}", "connected", config_={"path": str(p)})
    db.add_audit(actor, "folder_account_added")
    return a


@app.get("/api/accounts")
def accounts(actor: str = Depends(auth)):
    return monitor.overview()["accounts"]


@app.post("/api/accounts/{aid:path}/monitoring")
async def set_monitoring(aid: str, request: Request, actor: str = Depends(auth)):
    a, data = get_acct(aid), await body_json(request)
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        raise HTTPException(400, "enabled must be true or false")
    if enabled and a["status"] in ("auth_required", "disconnected"):
        raise HTTPException(409, "Reconnect this mailbox before enabling monitoring.")
    db.upsert_account(aid, a["provider"], a["display"], a["status"], monitoring_enabled=enabled)
    db.add_audit(actor, "monitoring_enabled" if enabled else "monitoring_disabled", aid)
    return monitor.overview()["accounts"]


@app.post("/api/accounts/{aid:path}/sync")
def sync_now(aid: str, actor: str = Depends(auth)):
    a = get_acct(aid)
    if not a["monitoring_enabled"]:
        raise HTTPException(409, "Monitoring is off for this mailbox.")
    db.set_account(aid, sync_requested_at=db.now())
    db.add_audit(actor, "manual_sync_requested", aid)
    return {"requested": True, "worker": monitor.overview()["indicators"]["worker"]}


@app.post("/api/accounts/{aid:path}/disconnect")
async def disconnect(aid: str, request: Request, actor: str = Depends(auth)):
    a, data = get_acct(aid), await body_json(request)
    if data.get("confirm") is not True:
        raise HTTPException(400, "Confirmation required: send {\"confirm\": true}.")
    revoked = False
    if a["provider"] == "gmail":
        revoked = providers.GmailProvider(account_id=aid).disconnect()["revoked"]
    cancelled = db.cancel_account_jobs(aid)
    db.upsert_account(aid, a["provider"], a["display"], "disconnected", monitoring_enabled=False)
    db.add_audit(actor, "account_disconnected", f"{aid} revoked={revoked} cancelled_jobs={cancelled}")
    return {"disconnected": True, "token_revoked_at_provider": revoked, "cancelled_jobs": cancelled,
            "note": "Scan history is kept. Remove EmailShield in your Google account permissions if revocation could not be confirmed."}


# ---------- queue, alerts, re-scan ----------
@app.get("/api/jobs")
def jobs(state: str = "", actor: str = Depends(auth)):
    if state and state not in db.JOB_STATES:
        raise HTTPException(400, "Unknown state")
    return db.list_jobs(state or None)


@app.post("/api/jobs/retry")
async def retry_jobs(request: Request, actor: str = Depends(auth)):
    data = await body_json(request)
    ids = data.get("ids")
    if ids is not None and not (isinstance(ids, list) and all(isinstance(i, int) for i in ids)):
        raise HTTPException(400, "ids must be a list of job ids")
    done = db.retry_jobs(ids, force=bool(data.get("force")))
    db.add_audit(actor, "jobs_retried", f"{len(done)} job(s)")
    return {"retried": done}


@app.get("/api/alerts")
def alerts(severity: str = None, status: str = None, account: str = None, actor: str = Depends(auth)):
    if severity not in (None, "high", "medium", "low") or status not in (None, *db.ALERT_STATUSES):
        raise HTTPException(400, "Unknown filter value")
    return {"alerts": db.list_alerts(account_id=account, severity=severity, status=status), "counts": db.alert_counts()}


@app.patch("/api/alerts/{alert_id}")
async def alert_status(alert_id: int, request: Request, actor: str = Depends(auth)):
    data = await body_json(request)
    try:
        r = db.set_alert_status(alert_id, data.get("status"), actor)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if not r:
        raise HTTPException(404, "Alert not found")
    db.add_audit(actor, "alert_status_changed", f"ALR-{alert_id:05d} {r['previous']} -> {r['status']}")
    return r


@app.post("/api/rescan")
async def rescan(request: Request, actor: str = Depends(auth)):
    """Explicit, audited re-scan of mailbox messages that were last scanned by an older engine/ruleset version."""
    data = await body_json(request)
    if data.get("confirm") is not True:
        raise HTTPException(400, "Confirmation required: send {\"confirm\": true}.")
    eng = detector.ruleset_version()
    queued = 0
    for m in db.list_messages(limit=1000):
        full = db.get_message(m["id"])
        if full["external_id"] and full["ruleset_version"] != eng:
            queued += db.queue_rescan(full["source"], full["account_id"] or "", full["external_id"], eng)
    db.add_audit(actor, "rescan_requested", f"{queued} job(s) for ruleset {eng}")
    return {"queued": queued, "ruleset": eng}


# ---------- auto-start (Windows, explicit opt-in) ----------
@app.get("/api/autostart")
def autostart_status(actor: str = Depends(auth)):
    return {"supported": autostart.supported(), "enabled": autostart.is_enabled()}


@app.put("/api/autostart")
async def autostart_set(request: Request, actor: str = Depends(auth)):
    data = await body_json(request)
    if not autostart.supported():
        raise HTTPException(409, "Start-with-Windows is only available on Windows.")
    if not isinstance(data.get("enabled"), bool):
        raise HTTPException(400, "enabled must be true or false")
    (autostart.enable if data["enabled"] else autostart.disable)()
    db.add_audit(actor, "autostart_enabled" if data["enabled"] else "autostart_disabled")
    return {"supported": True, "enabled": autostart.is_enabled()}


@app.get("/api/settings")
def get_settings(actor: str = Depends(auth)):
    s = settings.load()
    s["splunk"]["token_configured"] = secrets_store.has(splunk.TOKEN_NAME)
    return s


@app.put("/api/settings/{section}")
async def put_settings(section: str, request: Request, actor: str = Depends(auth)):
    try:
        body = json.loads((await read_limited(request)) or b"{}")
        if not isinstance(body, dict):
            raise ValueError("JSON object expected")
        token = body.pop("token", None) if section == "splunk" else None
        clear = body.pop("clear_token", False) if section == "splunk" else False
        s = settings.update(section, body)
        if token:  # write-only: never echoed back, never logged
            if not isinstance(token, str) or len(token) > 200:
                raise ValueError("Invalid token")
            secrets_store.set(splunk.TOKEN_NAME, token.strip())
        elif clear:
            secrets_store.delete(splunk.TOKEN_NAME)
    except ValueError as e:
        raise HTTPException(400, str(e))
    db.add_audit(actor, "settings_update", f"{section}: {sorted(body)}{' +token' if token else ''}")
    s["splunk"]["token_configured"] = secrets_store.has(splunk.TOKEN_NAME)
    return s


@app.get("/api/integrations/splunk")
def splunk_status(actor: str = Depends(auth)):
    return splunk.get_status()


@app.post("/api/integrations/splunk/test")
def splunk_test(actor: str = Depends(auth)):
    db.add_audit(actor, "splunk_test")
    return splunk.test_connection()


# ---------- engine lifecycle ----------
@app.get("/api/engine")
def engine_info(actor: str = Depends(auth)):
    from . import server
    info = server.read_instance() or {}
    started = info.get("started_at")
    up = None
    if started:
        from datetime import datetime, timezone
        up = (datetime.now(timezone.utc) - datetime.fromisoformat(started)).total_seconds()
    return {"pid": os.getpid(), "version": __version__, "port": config.PORT, "mode": info.get("mode", "unknown"),
            "started_at": started, "uptime_seconds": up,
            "note": "Closing the EmailShield window does not stop monitoring. Use Stop engine to stop it."}


@app.post("/api/engine/stop")
async def engine_stop(request: Request, actor: str = Depends(auth)):
    """Stops the whole backend (monitoring included) after answering. Monitoring resumes from its checkpoints at the next start."""
    data = await body_json(request)
    if data.get("confirm") is not True:
        raise HTTPException(400, "Confirmation required: send {\"confirm\": true}.")
    db.add_audit(actor, "engine_stop_requested")
    import threading
    threading.Timer(0.5, control.STOP.set).start()
    return {"stopping": True, "note": "Monitoring stops. Pending work is kept and resumes at the next start."}


# ---------- health, connection test, exports, backups ----------
@app.get("/api/health/detail")
def health_detail(actor: str = Depends(auth)):
    return health_checks.run_checks()


@app.post("/api/accounts/{aid:path}/validate")
def validate_account(aid: str, actor: str = Depends(auth)):
    """Test the connection now (read-only call). Returns a plain result; never exposes tokens."""
    a = get_acct(aid)
    if a["provider"] != "gmail":
        return {"ok": True, "detail": "Local folder mailbox: nothing to authenticate."}
    try:
        r = providers.GmailProvider(account_id=aid).validate()
        return {"ok": True, "detail": f"Connected as {r['email']}."}
    except Exception as e:
        c = errors.classify(e)
        if c.category == "auth_required":
            db.set_account(aid, status="auth_required", last_error=str(e), last_error_at=db.now(), last_error_category=c.category)
        return {"ok": False, "category": c.category, "detail": str(e)[:300], "needs_reconnect": c.category == "auth_required"}


@app.post("/api/exports/retry")
def retry_exports(actor: str = Depends(auth)):
    n = db.retry_exports()
    db.add_audit(actor, "exports_retried", f"{n} event(s)")
    return {"requeued": n}


@app.get("/api/backups")
def backups(actor: str = Depends(auth)):
    return {"backups": backup.list_backups(), "folder": str(backup.backup_dir()),
            "note": "Backups hold scan history and are not encrypted. Restore is done with EmailShield stopped: EmailShield.exe --stop, then python -m emailshield.backup restore FILE."}


@app.post("/api/backups")
def create_backup(actor: str = Depends(auth)):
    r = backup.create(keep=settings.load()["backup"]["keep"])
    db.add_audit(actor, "backup_created", os.path.basename(r["file"]))
    return {"file": os.path.basename(r["file"]), "sha256": r["sha256"], "bytes": r["bytes"]}
