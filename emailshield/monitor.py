"""Monitoring status model. Keeps the separate facts separate so the dashboard can never show a misleading
'protected' light: backend up, worker alive, mailbox connected, monitoring enabled, last sync, last scan."""
from . import db, splunk


def account_state(acct, worker_health):
    if not acct["monitoring_enabled"] or acct["status"] == "disconnected":
        return "disabled"
    if acct["status"] == "auth_required":
        return "authentication_required"
    if acct["status"] == "connecting":
        return "connecting"
    if worker_health == "stopping":
        return "stopping"
    if worker_health != "healthy":
        return "error"  # enabled but nothing is actually watching the mailbox
    if acct["status"] == "error":
        return "error"
    if not acct["initial_sync_done"]:
        return "synchronizing"
    if acct["consecutive_failures"] > 0:
        return "degraded"
    return "monitoring"


LABELS = {
    "disabled": "Monitoring is off", "connecting": "Connecting", "synchronizing": "Initial synchronization in progress",
    "monitoring": "Monitoring active", "degraded": "Degraded: recent errors, retrying",
    "authentication_required": "Authentication required: reconnect the mailbox", "error": "Error: monitoring is not working", "stopping": "Stopping",
}


def overview():
    m = db.monitoring()
    wh = "stopping" if (m["worker"] or {}).get("state") == "stopping" else m["health"]
    accounts = []
    for a in db.list_accounts():
        st = account_state(a, wh)
        accounts.append({k: a[k] for k in ("id", "provider", "display", "status", "monitoring_enabled", "initial_sync_done", "last_sync_at",
                                           "last_scan_at", "last_error", "last_error_at", "last_error_category", "consecutive_failures")}
                        | {"state": st, "state_label": LABELS[st], "jobs": db.job_counts(a["id"])})
    active = [a for a in accounts if a["monitoring_enabled"] and a["status"] != "disconnected"]
    if not active:
        level, label = "off", "Monitoring is off. No mailbox is being watched."
    elif any(a["state"] in ("authentication_required", "error") for a in active):
        level, label = "error", next(a["state_label"] for a in active if a["state"] in ("authentication_required", "error"))
    elif any(a["state"] in ("degraded", "synchronizing", "connecting", "stopping") for a in active):
        level, label = "warn", next(a["state_label"] for a in active if a["state"] != "monitoring")
    else:
        level, label = "ok", "Monitoring active while EmailShield and its worker keep running. It stops when the app closes, the PC sleeps or goes offline."
    errs = [e for e in db.list_events(50) if e["type"] in ("error", "splunk_error", "ti_error")][:10]
    st = db.stats()
    return {
        "overall": {"level": level, "label": label},
        "indicators": {"backend": "ok", "worker": wh, "mailboxes_connected": sum(a["status"] == "connected" for a in accounts),
                       "monitoring_enabled": len(active),
                       "last_sync": max([a["last_sync_at"] for a in accounts if a["last_sync_at"]], default=None),
                       "last_scan": max([a["last_scan_at"] for a in accounts if a["last_scan_at"]], default=None)},
        "health": wh, "worker": m["worker"], "heartbeat_age_seconds": m["heartbeat_age_seconds"], "accounts": accounts, "jobs": db.job_counts(),
        "total_processed": st["total"], "alerts": db.alert_counts(), "recent_errors": errs,
        "splunk": {**splunk.get_status(), "outbox": db.export_counts()},
    }
