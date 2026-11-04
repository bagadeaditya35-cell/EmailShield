"""Optional Splunk HTTP Event Collector (HEC) integration. Disabled by default.
Privacy defaults: no body, no recipients, no subject, no full URLs, no attachment content. Token via secrets_store."""
import hashlib
import json
import socket
import time
from functools import partial

from . import __version__, config, db, net, secrets_store, settings

TOKEN_NAME = "splunk_hec_token"
RANK = {"Low risk": 0, "Suspicious": 1, "High risk": 2}


class SplunkError(Exception):
    pass


def _endpoint(url):
    return url.rstrip("/") + "/services/collector/event"


def build_alert_event(msg, cfg=None, alert=None):
    cfg = cfg or settings.load()["splunk"]
    a, p = msg["analysis"], msg["parsed"]
    from . import attack
    ev = {
        "event_type": "emailshield_alert", "emailshield_version": __version__, "synthetic": False,
        "case_ref": msg["case_ref"], "message_id": msg["id"], "analyzed_at": msg["analyzed_at"],
        "category": a["category"], "score": a["score"], "status": msg["status"],
        "sender_address": p["from_addr"], "sender_domain": p["from_domain"], "reply_to_domain": p["reply_to_domain"],
        "auth": p["auth"],
        "findings": [{"id": f["id"], "title": f["title"], "points": f["points"]} for f in a["findings"] if f["points"] > 0],
        "attack_techniques": [m["technique_id"] for m in attack.map_findings(a["findings"])],
        "url_domains": [i["value"] for i in a["indicators"] if i["type"] == "url_domain"],
        "attachment_sha256": [i["value"] for i in a["indicators"] if i["type"] == "attachment_sha256"],
        "attachment_count": len(p["attachments"]),
        "message_sha256": p["raw_sha256"],
        "provider": msg.get("source"), "scan_status": "completed", "severity": (alert or {}).get("severity"),
        "alert_id": (alert or {}).get("alert_ref"),
        "message_ref": hashlib.sha256(f"{msg.get('source')}:{msg.get('account_id')}:{msg.get('external_id') or msg['raw_sha256']}".encode()).hexdigest()[:20],
        "engine_version": a.get("engine", {}).get("version"), "ruleset_version": a.get("engine", {}).get("ruleset"),
    }
    if cfg.get("include_urls"):
        ev["urls"] = [u["url"] for u in p["urls"]][:20]
    if cfg.get("include_subject"):
        ev["subject"] = p["subject"]
    return ev


class HEC:
    def __init__(self, url, token, index="", sourcetype="emailshield:alert", verify_tls=True, http=None,
                 sleep=None, retries=3, timeout=10):
        self.url, self.token, self.index, self.sourcetype = url, token, index, sourcetype
        self.http = http or partial(net.request, verify=verify_tls)
        self.sleep, self.retries, self.timeout = sleep or time.sleep, retries, timeout

    def health(self):
        st, _, _ = self.http("GET", self.url.rstrip("/") + "/services/collector/health", {}, None, self.timeout)
        return st == 200

    def send(self, event, sourcetype=None):
        payload = {"time": time.time(), "host": socket.gethostname(), "source": "emailshield",
                   "sourcetype": sourcetype or self.sourcetype, "event": event}
        if self.index:
            payload["index"] = self.index
        body = json.dumps(payload).encode()
        headers = {"Authorization": f"Splunk {self.token}", "Content-Type": "application/json"}
        last = "unknown error"
        for attempt in range(self.retries):  # bounded retries
            try:
                st, _, resp = self.http("POST", _endpoint(self.url), headers, body, self.timeout)
            except net.ConnectionProblem as e:
                last = f"connection problem: {e}"
            else:
                if st == 200:
                    return True
                if st in (401, 403):
                    raise SplunkError("Splunk rejected the token (HTTP %d). Check the HEC token and that HEC is enabled." % st)
                if st == 400:
                    raise SplunkError("Splunk rejected the event or index (HTTP 400): " + resp[:120].decode("utf-8", "ignore"))
                last = f"HTTP {st}"
            if attempt < self.retries - 1:
                self.sleep(min(2 ** attempt, 8))
        raise SplunkError(f"Splunk unreachable after {self.retries} attempts ({last})")


def _client(http=None, sleep=None):
    cfg = settings.load()["splunk"]
    token = secrets_store.get(TOKEN_NAME)
    if not cfg["url"] or not token:
        raise SplunkError("Splunk URL or token is not configured.")
    return HEC(cfg["url"], token, cfg["index"], cfg["sourcetype"], cfg["verify_tls"], http, sleep), cfg


def _status(**kw):
    s = db.get_kv("splunk") or {"sent": 0, "failed": 0, "last_success": None, "last_error": None, "last_error_at": None}
    s.update(kw)
    db.set_kv("splunk", s)


def get_status():
    cfg = settings.load()["splunk"]
    s = db.get_kv("splunk") or {"sent": 0, "failed": 0, "last_success": None, "last_error": None, "last_error_at": None}
    return {**s, "enabled": cfg["enabled"], "url": cfg["url"], "index": cfg["index"], "sourcetype": cfg["sourcetype"],
            "dropped": s.get("dropped", 0), "last_latency_ms": s.get("last_latency_ms"), "avg_latency_ms": s.get("avg_latency_ms"),
            "oldest_pending_age_seconds": db.oldest_pending_export_age(), "verify_tls": cfg["verify_tls"], "min_category": cfg["min_category"], "include_urls": cfg["include_urls"],
            "include_subject": cfg["include_subject"], "token_configured": secrets_store.has(TOKEN_NAME),
            "token_storage": secrets_store.backend()}


def test_connection(http=None, sleep=None):
    """Health check + one clearly synthetic event. Never raises; returns a result dict."""
    try:
        hec, _ = _client(http, sleep)
        healthy = hec.health()
        hec.send({"event_type": "emailshield_test", "synthetic": True, "message": "EmailShield connection test",
                  "emailshield_version": __version__}, sourcetype="emailshield:test")
        _status(last_success=db.now())
        return {"ok": True, "health_endpoint": healthy, "detail": "Synthetic test event accepted."}
    except (SplunkError, net.ConnectionProblem) as e:
        _status(last_error=str(e)[:200], last_error_at=db.now())
        return {"ok": False, "detail": str(e)[:300]}


def forward_alert(message_id, http=None, sleep=None):
    """Called after ingest. Never raises. Local analysis must not depend on Splunk."""
    try:
        cfg = settings.load()["splunk"]
        if not cfg["enabled"]:
            return {"sent": False, "reason": "disabled"}
        msg = db.get_message(message_id)
        if not msg or RANK[msg["category"]] < RANK[cfg["min_category"]]:
            return {"sent": False, "reason": "below threshold"}
        hec, _ = _client(http, sleep)
        hec.send(build_alert_event(msg, cfg))
        s = db.get_kv("splunk") or {}
        _status(sent=s.get("sent", 0) + 1, last_success=db.now())
        return {"sent": True}
    except Exception as e:
        s = db.get_kv("splunk") or {}
        _status(failed=s.get("failed", 0) + 1, last_error=str(e)[:200], last_error_at=db.now())
        db.add_event("splunk_error", str(e)[:200])
        return {"sent": False, "reason": str(e)[:200]}


# ---------- durable outbox: scanning never waits for Splunk ----------
MAX_EXPORT_ATTEMPTS = 5


def enqueue_export(message_id, alert_id, alert_changed=True):
    """Queue a sanitized alert event. Only if export is enabled and configured; deduplicated per alert+severity+engine."""
    cfg = settings.load()["splunk"]
    if not cfg["enabled"] or not alert_id or not alert_changed:
        return False
    msg = db.get_message(message_id)
    if not msg or RANK[msg["category"]] < RANK[cfg["min_category"]]:
        return False
    alert = next((a for a in db.list_alerts(500) if a["id"] == alert_id), None)
    ev = build_alert_event(msg, cfg, alert)
    key = f"{alert_id}:{ev['severity']}:{ev['engine_version']}:{ev['ruleset_version']}"
    if db.pending_export_count() >= config.MAX_OUTBOX:  # bounded queue: never grow without limit, and never drop silently
        st = db.get_kv("splunk") or {}
        _status(dropped=st.get("dropped", 0) + 1, last_error=f"Export queue full ({config.MAX_OUTBOX}); newest alert not queued", last_error_at=db.now())
        db.add_event("splunk_error", f"export queue full ({config.MAX_OUTBOX}): alert {alert_id} not exported")
        return False
    return db.enqueue_export(key, alert_id, message_id, "emailshield_alert", ev)


def deliver_pending(http=None, limit=20, rng=None):
    """Send queued events. Each failure schedules a bounded, jittered retry; permanent errors are kept as 'failed'.
    Returns counts. Never raises. 'sent' is recorded only after Splunk answered HTTP 200."""
    import random
    from . import errors
    rng = rng or random.random
    out = {"sent": 0, "retry": 0, "failed": 0}
    items = db.due_exports(limit)
    if not items:
        return out
    try:
        hec, _ = _client(http, lambda s: None)
        hec.retries = 1  # one attempt per cycle; the outbox schedules the retries
    except SplunkError as e:
        for it in items:
            db.update_export(it["id"], "failed", it["attempts"], str(e))
        _status(last_error=str(e)[:200], last_error_at=db.now(), failed=(db.get_kv("splunk") or {}).get("failed", 0) + len(items))
        out["failed"] = len(items)
        return out
    for it in items:
        attempts = it["attempts"] + 1
        try:
            t0 = time.perf_counter()
            hec.send(json.loads(it["payload"]))
            ms = (time.perf_counter() - t0) * 1000
            db.update_export(it["id"], "sent", attempts)
            st = db.get_kv("splunk") or {}
            n = st.get("sent", 0) + 1
            _status(sent=n, last_success=db.now(), last_latency_ms=round(ms, 1), avg_latency_ms=round(((st.get("avg_latency_ms") or 0) * (n - 1) + ms) / n, 1))
            out["sent"] += 1
        except SplunkError as e:
            msg = str(e)
            permanent = "rejected" in msg  # token/index/event rejected: retrying will not help until the config is fixed
            st = db.get_kv("splunk") or {}
            _status(failed=st.get("failed", 0) + 1, last_error=msg[:200], last_error_at=db.now())
            if permanent or attempts >= MAX_EXPORT_ATTEMPTS:
                db.update_export(it["id"], "failed", attempts, msg)
                out["failed"] += 1
            else:
                db.update_export(it["id"], "retry_scheduled", attempts, msg, delay=errors.backoff(attempts, 30, 900, rng=rng))
                out["retry"] += 1
        except Exception as e:  # never let an export problem stop the worker
            db.update_export(it["id"], "retry_scheduled", attempts, str(e), delay=errors.backoff(attempts, 30, 900, rng=rng))
            out["retry"] += 1
    return out
