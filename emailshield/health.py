"""Health checks shown on the dashboard and usable from the command line. Each check returns ok / warn / fail with a plain explanation."""
import os
import sqlite3
import sys

from . import config, db, diskcheck, migrations, monitor, secrets_store


def _c(name, status, detail):
    return {"name": name, "status": status, "detail": detail}


def integrity():
    try:
        with db.db() as c:
            r = c.execute("PRAGMA quick_check").fetchone()[0]
        return (True, "ok") if r == "ok" else (False, r)
    except sqlite3.DatabaseError as e:
        return False, f"{type(e).__name__}: {e}"


def run_checks():
    out = []
    ok, detail = integrity()
    out.append(_c("Database integrity", "ok" if ok else "fail", "quick_check passed" if ok else f"DAMAGED: {detail}. Stop EmailShield and restore a backup."))
    try:
        with db.db() as c:
            v = migrations.current_version(c)
        out.append(_c("Database schema", "ok" if v == migrations.LATEST else "warn", f"version {v} (latest {migrations.LATEST})"))
    except Exception as e:
        out.append(_c("Database schema", "fail", f"{type(e).__name__}"))
    free = diskcheck.free_mb()
    out.append(_c("Free disk space", "fail" if free < config.MIN_FREE_MB else "warn" if free < 3 * config.MIN_FREE_MB else "ok",
                  f"{free:.0f} MB free (monitoring pauses below {config.MIN_FREE_MB} MB)"))
    if sys.platform.startswith("win"):
        out.append(_c("Data folder permissions", "ok", f"{config.DATA_DIR} lives in your user profile (inherits your account's private ACL; not independently verified)"))
    else:
        mode = config.DATA_DIR.stat().st_mode & 0o777 if config.DATA_DIR.exists() else 0o700
        out.append(_c("Data folder permissions", "ok" if mode & 0o077 == 0 else "warn", f"mode {oct(mode)}" + ("" if mode & 0o077 == 0 else " (others can read; run chmod 700)")))
    be = secrets_store.backend()
    out.append(_c("Secret storage", "ok" if ("keyring" in be or "DPAPI" in be) else "warn", be))
    o = monitor.overview()
    wh = o["indicators"]["worker"]
    out.append(_c("Monitoring worker", "ok" if wh == "healthy" else "warn" if wh in ("not_running", "stopped") and o["overall"]["level"] == "off" else "fail" if o["overall"]["level"] != "off" else "warn", f"{wh.replace('_', ' ')}"))
    jc = o["jobs"]
    out.append(_c("Failed jobs", "warn" if jc["failed"] else "ok", f"{jc['failed']} failed job(s) kept for investigation" if jc["failed"] else "none"))
    ex = o["splunk"]["outbox"]
    out.append(_c("Splunk export queue", "warn" if ex["failed"] or ex["retry_scheduled"] else "ok", f"pending {ex['pending']}, retrying {ex['retry_scheduled']}, failed {ex['failed']}" if o["splunk"]["enabled"] else "export is off"))
    lf = config.DATA_DIR / "worker.log"
    out.append(_c("Log size", "ok", f"worker.log {lf.stat().st_size // 1024} KB (rotates at 1 MB, 3 files kept)" if lf.exists() else "no log yet"))
    rank = {"ok": 0, "warn": 1, "fail": 2}
    return {"overall": max((c["status"] for c in out), key=rank.get), "checks": out}
