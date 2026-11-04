"""SQLite storage: messages, indicators, case history, events, audit, jobs, worker status, TI cache/results.
The schema is created/migrated lazily the first time a database path is opened."""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from . import config, migrations, paths, redact

COMMON_DOMAINS = {"gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "live.com", "icloud.com"}
CAVEAT = "Shared indicators suggest messages may be related; they are NOT proof of a common attacker."
_ready = set()


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def after(seconds):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat(timespec="seconds")


@contextmanager
def db(immediate=False):
    """Open the database (creating/migrating it on first use). immediate=True takes the write lock up front,
    which is what makes queue claims atomic across processes."""
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(config.DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA journal_mode=WAL")
    try:
        if str(config.DB_PATH) not in _ready:
            if migrations.needs_backup(c):  # never migrate the only copy of user data
                ver = migrations.current_version(c)
                migrations.snapshot(c, str(config.DB_PATH) + f".pre-migration-v{ver}-{datetime.now(timezone.utc):%Y%m%d%H%M%S}.bak")
            migrations.apply(c)
            _ready.add(str(config.DB_PATH))
            paths.harden_data_dir(config.DB_PATH.parent)
        if immediate:
            c.execute("BEGIN IMMEDIATE")
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def init():
    with db():
        pass


# ---------- events / audit / case history ----------
def add_event(type_, detail):
    with db() as c:
        c.execute("INSERT INTO events(ts,type,detail) VALUES(?,?,?)", (now(), type_, redact.redact(detail)[:1000]))


def add_audit(actor, action, detail=""):
    with db() as c:
        c.execute("INSERT INTO audit(ts,actor,action,detail) VALUES(?,?,?,?)", (now(), actor, action, redact.redact(detail)[:1000]))


def list_events(limit=50):
    with db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))]


def list_audit(limit=100):
    with db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]


def _case_event(c, mid, actor, action, detail=""):
    c.execute("INSERT INTO case_events(message_id,ts,actor,action,detail) VALUES(?,?,?,?,?)",
              (mid, now(), actor, action, str(detail)[:1000]))


# ---------- messages ----------
def save_analysis(filename, parsed, analysis, source="upload", account_id="", external_id=""):
    """Returns (message_id, is_duplicate)."""
    parsed = {**parsed, "text": parsed["text"][:5000]}
    blob = json.dumps({"parsed": parsed, "analysis": analysis})
    eng = analysis.get("engine", {})
    try:
        with db() as c:
            cur = c.execute(
                "INSERT INTO messages(raw_sha256,filename,source,subject,sender,analyzed_at,score,category,analysis_json,updated_at,"
                "account_id,external_id,engine_version,ruleset_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (parsed["raw_sha256"], filename, source, parsed["subject"], parsed["from_addr"], now(),
                 analysis["score"], analysis["category"], blob, now(), account_id or "", external_id,
                 eng.get("version"), eng.get("ruleset")))
            mid = cur.lastrowid
            c.executemany("INSERT INTO indicators VALUES(?,?,?)", [(mid, i["type"], i["value"]) for i in analysis["indicators"]])
            _case_event(c, mid, source, "created", f"{analysis['category']} score {analysis['score']}")
        return mid, False
    except sqlite3.IntegrityError:
        with db() as c:
            row = c.execute("SELECT id FROM messages WHERE raw_sha256=? AND account_id=?", (parsed["raw_sha256"], account_id or "")).fetchone()
        return row["id"], True


def update_analysis(mid, parsed, analysis, actor="rescan"):
    """Explicit re-scan of an existing message with the current engine. Old->new result is recorded in the case history."""
    parsed = {**parsed, "text": parsed["text"][:5000]}
    eng = analysis.get("engine", {})
    with db() as c:
        old = c.execute("SELECT score, category, engine_version FROM messages WHERE id=?", (mid,)).fetchone()
        if not old:
            return False
        c.execute("UPDATE messages SET analysis_json=?, score=?, category=?, engine_version=?, ruleset_version=?, updated_at=? WHERE id=?",
                  (json.dumps({"parsed": parsed, "analysis": analysis}), analysis["score"], analysis["category"],
                   eng.get("version"), eng.get("ruleset"), now(), mid))
        c.execute("DELETE FROM indicators WHERE message_id=?", (mid,))
        c.executemany("INSERT INTO indicators VALUES(?,?,?)", [(mid, i["type"], i["value"]) for i in analysis["indicators"]])
        _case_event(c, mid, actor, "rescanned", f"{old['category']} {old['score']} -> {analysis['category']} {analysis['score']} (engine {old['engine_version']} -> {eng.get('version')})")
    return True


def _row(r, full=False):
    d = {k: r[k] for k in r.keys() if k != "analysis_json"}
    d["case_ref"] = f"INV-{r['id']:05d}"
    if full:
        d.update(json.loads(r["analysis_json"]))
    return d


def get_message(mid):
    with db() as c:
        r = c.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
        if not r:
            return None
        d = _row(r, True)
        from . import attack
        d["attack"] = attack.map_findings(d["analysis"].get("findings", []))
        d["history"] = [dict(x) for x in c.execute("SELECT ts,actor,action,detail FROM case_events WHERE message_id=? ORDER BY id", (mid,))]
        d["intel"] = [dict(x) for x in c.execute(
            "SELECT provider,indicator_type,indicator,verdict,detail,fetched_at,from_cache FROM ti_results WHERE message_id=? ORDER BY rowid", (mid,))]
    return d


def list_messages(q="", category="", status="", limit=200, account_id=None):
    sql, args = "SELECT * FROM messages WHERE 1=1", []
    if account_id is not None:
        sql += " AND account_id=?"
        args.append(account_id)
    if q:
        sql += " AND (subject LIKE ? OR sender LIKE ? OR filename LIKE ?)"
        args += [f"%{q}%"] * 3
    if category:
        sql += " AND category=?"
        args.append(category)
    if status:
        sql += " AND status=?"
        args.append(status)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(min(int(limit), 1000))
    with db() as c:
        return [_row(r) for r in c.execute(sql, args).fetchall()]


def update_message(mid, status=None, notes=None, actor="analyst"):
    if status is not None and status not in config.STATUSES:
        raise ValueError("Invalid status")
    if notes is not None and not isinstance(notes, str):
        raise ValueError("Notes must be text")
    with db() as c:
        cur = c.execute("SELECT status, notes FROM messages WHERE id=?", (mid,)).fetchone()
        if not cur:
            return None
        if status is not None and status != cur["status"]:
            c.execute("UPDATE messages SET status=?, updated_at=? WHERE id=?", (status, now(), mid))
            _case_event(c, mid, actor, "status_changed", f"{cur['status']} -> {status}")
        if notes is not None and notes != cur["notes"]:
            c.execute("UPDATE messages SET notes=?, updated_at=? WHERE id=?", (notes[:5000], now(), mid))
            _case_event(c, mid, actor, "notes_updated", f"{len(notes[:5000])} characters")
    return get_message(mid)


def stats():
    with db() as c:
        total = c.execute("SELECT COUNT(*) n FROM messages").fetchone()["n"]
        cats = {r["category"]: r["n"] for r in c.execute("SELECT category, COUNT(*) n FROM messages GROUP BY category")}
        sts = {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) n FROM messages GROUP BY status")}
        errs = c.execute("SELECT COUNT(*) n FROM events WHERE type='error'").fetchone()["n"]
    return {"total": total, "low": cats.get("Low risk", 0), "suspicious": cats.get("Suspicious", 0),
            "high": cats.get("High risk", 0), "by_status": sts, "errors": errs}


def find_related(mid, cross_account=False):
    """Messages sharing indicators. By default only within the SAME mailbox (account isolation); other mailboxes are
    included only when explicitly requested."""
    with db() as c:
        rows = c.execute(
            "SELECT i2.message_id oid, i1.type t, i1.value v FROM indicators i1 JOIN indicators i2 "
            "ON i1.type=i2.type AND i1.value=i2.value AND i2.message_id!=i1.message_id "
            "JOIN messages m1 ON m1.id=i1.message_id JOIN messages m2 ON m2.id=i2.message_id "
            "WHERE i1.message_id=? AND (?=1 OR m2.account_id=m1.account_id)", (mid, int(bool(cross_account)))).fetchall()
        grouped = {}
        for r in rows:
            if r["t"] in ("url_domain", "sender_domain", "reply_to_domain") and r["v"] in COMMON_DOMAINS:
                continue
            grouped.setdefault(r["oid"], set()).add((r["t"], r["v"]))
        out = []
        for oid, reasons in grouped.items():
            m = c.execute("SELECT id,subject,sender,score,category,account_id FROM messages WHERE id=?", (oid,)).fetchone()
            out.append({**dict(m), "case_ref": f"INV-{m['id']:05d}",
                        "reasons": [f"Shares {t.replace('_', ' ')}: {v}" for t, v in sorted(reasons)]})
    return {"related": sorted(out, key=lambda x: -len(x["reasons"])), "caveat": CAVEAT, "scope": "all mailboxes" if cross_account else "same mailbox only"}


def purge_all(message_days, log_days):
    """Retention: scans (and their alerts/indicators/history) older than message_days; events, audit rows, finished jobs and
    delivered exports older than log_days. Returns what was removed. Nothing newer is touched."""
    cut_m = (datetime.now(timezone.utc) - timedelta(days=message_days)).isoformat(timespec="seconds")
    cut_l = (datetime.now(timezone.utc) - timedelta(days=log_days)).isoformat(timespec="seconds")
    with db() as c:
        r = {"messages": c.execute("DELETE FROM messages WHERE analyzed_at < ?", (cut_m,)).rowcount,
             "events": c.execute("DELETE FROM events WHERE ts < ?", (cut_l,)).rowcount,
             "audit": c.execute("DELETE FROM audit WHERE ts < ?", (cut_l,)).rowcount,
             "jobs": c.execute("DELETE FROM jobs WHERE state IN ('completed','cancelled') AND updated_at < ?", (cut_l,)).rowcount,
             "exports": c.execute("DELETE FROM exports WHERE state='sent' AND sent_at < ?", (cut_l,)).rowcount}
    return r


def oldest_pending_export_age():
    with db() as c:
        r = c.execute("SELECT MIN(created_at) m FROM exports WHERE state IN ('pending','retry_scheduled')").fetchone()["m"]
    return None if not r else (datetime.now(timezone.utc) - datetime.fromisoformat(r)).total_seconds()


def pending_export_count():
    with db() as c:
        return c.execute("SELECT COUNT(*) n FROM exports WHERE state IN ('pending','retry_scheduled')").fetchone()["n"]


def purge(days=None):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days if days is not None else config.RETENTION_DAYS)).isoformat(timespec="seconds")
    with db() as c:
        return c.execute("DELETE FROM messages WHERE analyzed_at < ?", (cutoff,)).rowcount


# ---------- jobs (persistent, leased queue) ----------
JOB_STATES = ("pending", "processing", "completed", "retry_scheduled", "failed", "cancelled")
RETRY_ELIGIBLE = ("network", "provider_error", "rate_limit", "database", "io", "unknown", "auth_required", "config", "retries_exhausted", "interrupted")


def _clean(text, n=300):
    return redact.redact(text)[:n] if text else None


def _enqueue(c, provider, account_id, ref, engine_version="", delay=0):
    if not engine_version and c.execute(
            "SELECT 1 FROM messages WHERE source=? AND COALESCE(account_id,'')=? AND external_id=?", (provider, account_id, ref)).fetchone():
        return False  # already scanned: routine sync never re-queues it (re-scans must be explicit)
    cur = c.execute(
        "INSERT OR IGNORE INTO jobs(provider,account_id,external_id,engine_version,state,next_attempt_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
        (provider, account_id, ref, engine_version, "pending", now() if not delay else after(delay), now(), now()))
    return cur.rowcount == 1


def enqueue_job(provider, ref, account_id="", engine_version=""):
    with db() as c:
        return _enqueue(c, provider, account_id, ref, engine_version)


def claim_jobs(provider, account_id, owner, limit=10, lease_seconds=300):
    """Atomically take due jobs (also reclaims jobs whose lease expired because a worker died).
    A reclaimed job counts as one attempt, so a message that keeps crashing the worker ends up dead-lettered."""
    with db(immediate=True) as c:
        t = now()
        ids = [r["id"] for r in c.execute(
            "SELECT id FROM jobs WHERE provider=? AND account_id=? AND ((state IN ('pending','retry_scheduled') AND next_attempt_at<=?) "
            "OR (state='processing' AND (lease_expires_at IS NULL OR lease_expires_at<=?))) ORDER BY id LIMIT ?",
            (provider, account_id, t, t, limit))]
        for i in ids:
            c.execute("UPDATE jobs SET attempts=attempts+(state='processing' AND in_flight=1), in_flight=0, state='processing', lease_owner=?, lease_expires_at=?, "
                      "last_attempt_at=?, updated_at=? WHERE id=?", (owner, after(lease_seconds), t, t, i))
        return [dict(r) for r in c.execute(f"SELECT * FROM jobs WHERE id IN ({','.join('?' * len(ids))}) ORDER BY id", ids)] if ids else []


def mark_in_flight(jid, owner):
    """Called right before the risky work starts. Only the job that was actually being processed when a worker dies is charged
    an attempt, so innocent jobs that merely shared its batch are never penalised."""
    with db() as c:
        c.execute("UPDATE jobs SET in_flight=1 WHERE id=? AND lease_owner=? AND state='processing'", (jid, owner))


def _owned(c, jid, owner):
    return c.execute("SELECT 1 FROM jobs WHERE id=? AND lease_owner=? AND state='processing'", (jid, owner)).fetchone() is not None


def complete_job(jid, owner, scan_id=None):
    with db() as c:
        if not _owned(c, jid, owner):
            return False  # lease lost: another worker took over; do not overwrite its state
        c.execute("UPDATE jobs SET in_flight=0, state='completed', completed_at=?, scan_id=?, lease_owner=NULL, lease_expires_at=NULL, "
                  "error_category=NULL, last_error=NULL, updated_at=? WHERE id=?", (now(), scan_id, now(), jid))
        return True


def schedule_retry(jid, owner, delay, category, error, count_attempt=True):
    with db() as c:
        if not _owned(c, jid, owner):
            return False
        c.execute(f"UPDATE jobs SET in_flight=0, state='retry_scheduled', attempts=attempts+{1 if count_attempt else 0}, next_attempt_at=?, error_category=?, last_error=?, "
                  "lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE id=?", (after(delay), category, _clean(error), now(), jid))
        return True


def dead_letter(jid, owner, category, error):
    """Permanently failed: kept for investigation, never silently dropped."""
    with db() as c:
        if not _owned(c, jid, owner):
            return False
        c.execute("UPDATE jobs SET in_flight=0, state='failed', attempts=attempts+1, error_category=?, last_error=?, dead_lettered_at=?, "
                  "lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE id=?", (category, _clean(error), now(), now(), jid))
        return True


def release_job(jid, owner, category=None, error=None):
    """Give a job back without counting an attempt (shutdown, auth pause)."""
    with db() as c:
        c.execute("UPDATE jobs SET in_flight=0, state='pending', next_attempt_at=?, lease_owner=NULL, lease_expires_at=NULL, error_category=?, last_error=?, updated_at=? "
                  "WHERE id=? AND lease_owner=? AND state='processing'", (now(), category, _clean(error), now(), jid, owner))


def release_owner(owner):
    with db() as c:
        return c.execute("UPDATE jobs SET in_flight=0, state='pending', next_attempt_at=?, lease_owner=NULL, lease_expires_at=NULL, updated_at=? "
                         "WHERE lease_owner=? AND state='processing'", (now(), now(), owner)).rowcount


def reset_stuck_jobs(provider=None):
    """Startup recovery: reclaim jobs whose lease is missing or expired. Live leases of other workers are left alone."""
    with db(immediate=True) as c:
        t = now()
        return c.execute("UPDATE jobs SET state='pending', attempts=attempts+in_flight, error_category=CASE WHEN in_flight=1 THEN 'interrupted' ELSE error_category END, in_flight=0, next_attempt_at=?, "
                         "lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE state='processing' AND "
                         "(lease_expires_at IS NULL OR lease_expires_at<=?)" + (" AND provider=?" if provider else ""),
                         (t, t, t) + ((provider,) if provider else "")).rowcount


def cancel_account_jobs(account_id):
    with db() as c:
        return c.execute("UPDATE jobs SET state='cancelled', lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE account_id=? "
                         "AND state IN ('pending','retry_scheduled','processing')", (now(), account_id)).rowcount


def retry_jobs(ids=None, force=False):
    """Put dead-lettered jobs back in the queue. Without force, only categories where a retry can plausibly help."""
    with db() as c:
        sql = "SELECT id, error_category FROM jobs WHERE state='failed'"
        args = []
        if ids:
            sql += f" AND id IN ({','.join('?' * len(ids))})"
            args = list(ids)
        rows = [r for r in c.execute(sql, args) if force or (r["error_category"] or "unknown") in RETRY_ELIGIBLE]
        for r in rows:
            c.execute("UPDATE jobs SET state='pending', attempts=0, next_attempt_at=?, dead_lettered_at=NULL, lease_owner=NULL, "
                      "lease_expires_at=NULL, updated_at=? WHERE id=?", (now(), now(), r["id"]))
        return [r["id"] for r in rows]


def job_counts(account_id=None):
    with db() as c:
        q, a = "SELECT state, COUNT(*) n FROM jobs", []
        if account_id is not None:
            q, a = q + " WHERE account_id=?", [account_id]
        counts = {r["state"]: r["n"] for r in c.execute(q + " GROUP BY state", a)}
    return {k: counts.get(k, 0) for k in JOB_STATES}


def list_jobs(state=None, limit=100, account_id=None):
    with db() as c:
        q, a = "SELECT * FROM jobs WHERE 1=1", []
        if state:
            q, a = q + " AND state=?", a + [state]
        if account_id is not None:
            q, a = q + " AND account_id=?", a + [account_id]
        return [dict(r) for r in c.execute(q + " ORDER BY id DESC LIMIT ?", a + [min(int(limit), 500)])]


def get_job(jid):
    with db() as c:
        r = c.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
    return dict(r) if r else None


# ---------- accounts ----------
ACCOUNT_FIELDS = {"display", "status", "monitoring_enabled", "initial_sync_done", "last_sync_at", "last_scan_at", "last_error",
                  "last_error_at", "last_error_category", "consecutive_failures", "sync_requested_at", "provider"}


def upsert_account(aid, provider, display="", status="connected", monitoring_enabled=None, config_=None):
    with db() as c:
        if c.execute("SELECT 1 FROM accounts WHERE id=?", (aid,)).fetchone():
            c.execute("UPDATE accounts SET display=COALESCE(NULLIF(?,''),display), status=? WHERE id=?", (display, status, aid))
        else:
            c.execute("INSERT INTO accounts(id,provider,display,status,monitoring_enabled,config,created_at) VALUES(?,?,?,?,?,?,?)",
                      (aid, provider, display, status, int(bool(monitoring_enabled)), json.dumps(config_ or {}), now()))
        if monitoring_enabled is not None:
            c.execute("UPDATE accounts SET monitoring_enabled=? WHERE id=?", (int(bool(monitoring_enabled)), aid))
    return get_account(aid)


def _acct(r):
    d = dict(r)
    d["sync_state"], d["config"] = json.loads(d["sync_state"] or "{}"), json.loads(d["config"] or "{}")
    d["monitoring_enabled"], d["initial_sync_done"] = bool(d["monitoring_enabled"]), bool(d["initial_sync_done"])
    return d


def get_account(aid):
    with db() as c:
        r = c.execute("SELECT * FROM accounts WHERE id=?", (aid,)).fetchone()
    return _acct(r) if r else None


def list_accounts():
    with db() as c:
        return [_acct(r) for r in c.execute("SELECT * FROM accounts ORDER BY created_at")]


def set_account(aid, **fields):
    bad = set(fields) - ACCOUNT_FIELDS
    if bad:
        raise ValueError(f"Unknown account fields: {sorted(bad)}")
    if "last_error" in fields:
        fields["last_error"] = _clean(fields["last_error"])
    if not fields:
        return
    with db() as c:
        c.execute(f"UPDATE accounts SET {', '.join(f'{k}=?' for k in fields)} WHERE id=?", [*fields.values(), aid])


def record_sync(aid, provider, refs, new_state, engine_version="", capacity=None):
    return record_sync_ex(aid, provider, refs, new_state, engine_version, capacity)[0]


def record_sync_ex(aid, provider, refs, new_state, engine_version="", capacity=None):
    """Queue newly discovered messages AND advance the sync checkpoint in ONE transaction.
    If the process dies before commit, nothing advances and the messages are simply rediscovered later (idempotent)."""
    with db() as c:
        new, truncated = 0, False
        for r in dict.fromkeys(refs):
            if capacity is not None and new >= capacity:
                truncated = True  # backpressure: leave the rest for later; the checkpoint must NOT advance past them
                break
            new += _enqueue(c, provider, aid, r, engine_version)
        if truncated:
            c.execute("UPDATE accounts SET last_sync_at=?, consecutive_failures=0 WHERE id=?", (now(), aid))
        else:
            c.execute("UPDATE accounts SET sync_state=?, last_sync_at=?, consecutive_failures=0 WHERE id=?", (json.dumps(new_state), now(), aid))
    return new, truncated


def queue_rescan(provider, account_id, ref, engine_version):
    with db() as c:
        return _enqueue(c, provider, account_id, ref, engine_version)


# ---------- alerts ----------
SEVERITY = {"High risk": "high", "Suspicious": "medium"}


def upsert_alert(mid, category, score, title, engine_version):
    """One alert per message. Routine syncs never create duplicates; a re-scan updates it. Returns (alert_id, created, changed)."""
    sev = SEVERITY.get(category)
    with db() as c:
        row = c.execute("SELECT id, severity FROM alerts WHERE message_id=?", (mid,)).fetchone()
        if not row:
            if not sev:
                return None, False, False
            cur = c.execute("INSERT INTO alerts(message_id,severity,score,title,engine_version,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                            (mid, sev, score, title[:200], engine_version, now(), now()))
            _case_event(c, mid, "engine", "alert_created", f"{sev} (score {score})")
            return cur.lastrowid, True, True
        new_sev = sev or "low"
        changed = new_sev != row["severity"]
        c.execute("UPDATE alerts SET severity=?, score=?, engine_version=?, updated_at=? WHERE id=?", (new_sev, score, engine_version, now(), row["id"]))
        if changed:
            _case_event(c, mid, "engine", "alert_updated", f"{row['severity']} -> {new_sev}")
        return row["id"], False, changed


ALERT_STATUSES = ("open", "acknowledged", "closed")


def set_alert_status(alert_id, status, actor="analyst"):
    if status not in ALERT_STATUSES:
        raise ValueError("Invalid alert status")
    with db() as c:
        row = c.execute("SELECT message_id, status FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not row:
            return None
        if row["status"] != status:
            c.execute("UPDATE alerts SET status=?, updated_at=? WHERE id=?", (status, now(), alert_id))
            _case_event(c, row["message_id"], actor, "alert_status_changed", f"{row['status']} -> {status}")
    return {"id": alert_id, "status": status, "previous": row["status"]}


def list_alerts(limit=50, account_id=None, severity=None, status=None):
    with db() as c:
        q, a = "SELECT a.*, m.subject, m.account_id FROM alerts a JOIN messages m ON m.id=a.message_id WHERE 1=1", []
        for col, val in (("m.account_id", account_id), ("a.severity", severity), ("a.status", status)):
            if val is not None:
                q, a = q + f" AND {col}=?", a + [val]
        return [{**dict(r), "alert_ref": f"ALR-{r['id']:05d}", "case_ref": f"INV-{r['message_id']:05d}"} for r in c.execute(q + " ORDER BY a.id DESC LIMIT ?", a + [limit])]


def alert_counts():
    with db() as c:
        counts = {r["severity"]: r["n"] for r in c.execute("SELECT severity, COUNT(*) n FROM alerts GROUP BY severity")}
    return {k: counts.get(k, 0) for k in ("high", "medium", "low")}


# ---------- export outbox (Splunk) ----------
def enqueue_export(dedupe_key, alert_id, message_id, event_type, payload):
    with db() as c:
        return c.execute("INSERT OR IGNORE INTO exports(dedupe_key,alert_id,message_id,event_type,payload,next_attempt_at,created_at) VALUES(?,?,?,?,?,?,?)",
                         (dedupe_key, alert_id, message_id, event_type, json.dumps(payload), now(), now())).rowcount == 1


def due_exports(limit=20):
    with db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM exports WHERE state IN ('pending','retry_scheduled') AND next_attempt_at<=? ORDER BY id LIMIT ?", (now(), limit))]


def update_export(eid, state, attempts=None, error=None, delay=None):
    with db() as c:
        c.execute("UPDATE exports SET state=?, attempts=COALESCE(?,attempts), last_error=?, next_attempt_at=COALESCE(?,next_attempt_at), "
                  "sent_at=CASE WHEN ?='sent' THEN ? ELSE sent_at END WHERE id=?",
                  (state, attempts, _clean(error), after(delay) if delay is not None else None, state, now(), eid))


def export_counts():
    with db() as c:
        counts = {r["state"]: r["n"] for r in c.execute("SELECT state, COUNT(*) n FROM exports GROUP BY state")}
    return {k: counts.get(k, 0) for k in ("pending", "retry_scheduled", "sent", "failed")}


def retry_exports():
    with db() as c:
        return c.execute("UPDATE exports SET state='pending', attempts=0, next_attempt_at=? WHERE state='failed'", (now(),)).rowcount


# ---------- key/value (worker status) ----------
def set_kv(key, value):
    with db() as c:
        c.execute("INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))


def get_kv(key):
    with db() as c:
        r = c.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
    return json.loads(r["value"]) if r else None


def monitoring():
    w = get_kv("worker")
    health, age = "not_running", None
    if w:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(w["heartbeat"])).total_seconds()
        health = "stopped" if w.get("state") == "stopped" else ("healthy" if age <= max(3 * w.get("interval", 60), 30) else "stale")
    return {"worker": w, "health": health, "heartbeat_age_seconds": age, "jobs": job_counts()}


# ---------- threat intel ----------
def ti_cache_get(provider, indicator, ttl):
    import time
    with db() as c:
        r = c.execute("SELECT result_json, fetched_at FROM ti_cache WHERE provider=? AND indicator=?", (provider, indicator)).fetchone()
    if r and time.time() - r["fetched_at"] <= ttl:
        return json.loads(r["result_json"])
    return None


def ti_cache_put(provider, indicator, result):
    import time
    with db() as c:
        c.execute("INSERT OR REPLACE INTO ti_cache VALUES(?,?,?,?)", (provider, indicator, json.dumps(result), time.time()))


def ti_result_save(mid, provider, itype, indicator, verdict, detail, from_cache):
    with db() as c:
        c.execute("INSERT INTO ti_results VALUES(?,?,?,?,?,?,?,?)", (mid, provider, itype, indicator, verdict, detail, now(), int(from_cache)))
        _case_event(c, mid, provider, "intel_lookup", f"{itype}: {verdict}")
