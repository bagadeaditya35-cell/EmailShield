"""Monitoring worker. One Worker per mailbox account; MonitorService runs all enabled accounts in ONE background loop.
Run standalone:  python -m emailshield.worker --provider folder|gmail [--interval 60] [--once]
Guarantees: jobs are persisted before processing; claims are atomic and leased (a crashed worker's jobs are reclaimed);
errors are classified (retry with jittered backoff / pause for user / dead-letter); a bad email never stops the loop;
shutdown hands unfinished jobs back. It is read-only and alert-oriented: it never sends, deletes, moves or quarantines mail."""
import argparse
import json
import logging
import logging.handlers
import os
import random
import signal
import threading
import time
import uuid
from pathlib import Path

from . import config, db, diskcheck, errors, ingest, net, providers, redact, settings, splunk
from .providers import ChangeSet

log = logging.getLogger("emailshield.worker")


class JsonFormatter(logging.Formatter):
    def format(self, r):
        return json.dumps({"ts": self.formatTime(r, "%Y-%m-%dT%H:%M:%S"), "level": r.levelname, "msg": redact.redact(r.getMessage())})


def setup_logging():
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    h = logging.handlers.RotatingFileHandler(config.DATA_DIR / "worker.log", maxBytes=1_000_000, backupCount=3)
    s = logging.StreamHandler()
    for x in (h, s):
        x.setFormatter(JsonFormatter())
        x.addFilter(redact.RedactFilter())
        log.addHandler(x)
    log.setLevel(logging.INFO)


class Worker:
    def __init__(self, provider, interval=None, max_attempts=None, backoff_base=30, backoff_cap=900, batch=None,
                 lease_seconds=300, rng=random.random, account_id=None, manage_status=True, deliver_exports=True, max_queue=None):
        mon = settings.load()["monitoring"]
        self.provider = provider
        self.account_id = account_id or getattr(provider, "account_id", None) or provider.name
        self.interval = interval or config.WORKER_INTERVAL
        self.max_attempts = max_attempts or mon["max_attempts"]
        self.batch, self.lease_seconds, self.max_queue = batch or mon["batch_size"], lease_seconds, max_queue or mon["max_queue"]
        self.backoff_base, self.backoff_cap, self.rng = backoff_base, backoff_cap, rng
        self.manage_status, self.deliver_exports = manage_status, deliver_exports
        self.owner = f"{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self.stop_event = threading.Event()
        self._blocked_until, self._streak = 0.0, 0

    # ----- status -----
    def _status(self, **kw):
        if not self.manage_status:
            return
        s = db.get_kv("worker") or {}
        s.update(kw)
        s.update(heartbeat=db.now(), provider=self.provider.name, interval=self.interval, pid=os.getpid())
        db.set_kv("worker", s)

    def _account(self):
        return db.get_account(self.account_id)

    def _record_failure(self, state, exc, cat, wait=0.0, account_status=None):
        self._blocked_until = time.monotonic() + wait
        fields = {"last_error": str(exc), "last_error_at": db.now(), "last_error_category": cat}
        a = self._account()
        if a:
            fields["consecutive_failures"] = a["consecutive_failures"] + 1
            if account_status:
                fields["status"] = account_status
            db.set_account(self.account_id, **fields)
        self._status(state=state, last_error=redact.redact(exc)[:300], last_error_at=db.now())
        db.add_event("error", f"{self.account_id} {state}: {cat}: {redact.redact(exc)[:200]}")
        log.warning("%s %s (%s); next attempt in %.0fs", self.account_id, state, cat, wait)

    def start(self):
        db.init()
        if self._account() is None:  # legacy standalone use: an explicitly started worker means 'monitor this'
            db.upsert_account(self.account_id, self.provider.name, self.provider.name, "connected", monitoring_enabled=True)
        n = db.reset_stuck_jobs(self.provider.name)
        self._status(state="starting", started_at=db.now(), recovered_jobs=n)
        log.info("worker started account=%s interval=%s recovered_jobs=%s", self.account_id, self.interval, n)

    # ----- discovery -----
    def _discover(self, acct):
        state = acct["sync_state"] if acct else {}
        if hasattr(self.provider, "discover"):
            return self.provider.discover(state)
        return ChangeSet(self.provider.list_new(), dict(state))

    def poll(self):
        acct = self._account()
        if acct and (not acct["monitoring_enabled"] or acct["status"] == "disconnected"):
            return "disabled"
        if acct and acct["status"] == "auth_required":
            return "auth_error"
        if time.monotonic() < self._blocked_until:
            return "backoff"
        if diskcheck.low():  # pause instead of risking a half-written database
            self._record_failure("error", errors.ConfigError(f"Low disk space (< {config.MIN_FREE_MB} MB free). Monitoring paused until space is freed."), "disk_full", self.interval * 2)
            return "low_disk"
        jc = db.job_counts(self.account_id)
        outstanding = jc["pending"] + jc["retry_scheduled"]
        if outstanding >= self.max_queue:  # backpressure: stop discovering until the queue drains (nothing is lost; the checkpoint stays put)
            self._status(state="connected", queue_full=True)
            db.set_account(self.account_id, last_error=f"Queue is full ({outstanding} waiting); discovery paused until it drains", last_error_at=db.now(), last_error_category="backpressure")
            return "queue_full"
        try:
            cs = self._discover(acct)
        except Exception as e:
            c = errors.classify(e)
            if c.category == "auth_required":
                self._record_failure("auth_error", e, c.category, self.interval * 10, "auth_required")
                return "auth_error"
            if c.category == "rate_limit":
                self._record_failure("rate_limited", e, c.category, min(c.retry_after, 3600))
                return "rate_limited"
            if c.retryable:
                self._streak += 1
                self._record_failure("disconnected", e, c.category, errors.backoff(self._streak, self.backoff_base, self.backoff_cap, rng=self.rng))
                return "disconnected"
            self._record_failure("error", e, c.category, self.interval * 10, "error")
            return "error"
        self._streak = 0
        new, truncated = db.record_sync_ex(self.account_id, self.provider.name, cs.refs, cs.state, capacity=self.max_queue - outstanding)
        if acct and (acct["status"] in ("error", "connecting") or acct["last_error_category"] in ("backpressure", "disk_full")):
            db.set_account(self.account_id, status="connected", last_error=None, last_error_category=None)
        if truncated:
            db.set_account(self.account_id, last_error="Queue limit reached during discovery; remaining messages will be picked up as the queue drains", last_error_at=db.now(), last_error_category="backpressure")
        self._status(state="connected", last_sync=db.now(), last_found=len(cs.refs), last_new=new)
        if new:
            log.info("%s: queued %s new message(s)%s", self.account_id, new, " (initial sync)" if cs.initial else "")
        return "ok"

    # ----- processing -----
    def _fail(self, job, exc):
        c = errors.classify(exc)
        err = f"{type(exc).__name__}: {exc}"
        if c.needs_user:  # pause the account and keep the job; the user must act (reconnect / fix config)
            db.release_job(job["id"], self.owner, c.category, err)
            self._record_failure("auth_error" if c.category == "auth_required" else "error", exc, c.category, self.interval * 10,
                                 "auth_required" if c.category == "auth_required" else "error")
            return "pause"
        if not c.retryable:
            db.dead_letter(job["id"], self.owner, c.category, err)
            db.add_event("error", f"job {job['id']} dead-lettered ({c.category})")
            return "dead"
        attempts = job["attempts"] + (0 if c.category == "rate_limit" else 1)
        if c.category != "rate_limit" and attempts >= self.max_attempts:
            db.dead_letter(job["id"], self.owner, c.category, f"retries exhausted: {err}")
            db.add_event("error", f"job {job['id']} dead-lettered after {attempts} attempts ({c.category})")
            return "dead"
        delay = errors.backoff(attempts, self.backoff_base, self.backoff_cap, c.retry_after, self.rng)
        db.schedule_retry(job["id"], self.owner, delay, c.category, err, count_attempt=c.category != "rate_limit")
        a = self._account()
        if a:
            db.set_account(self.account_id, last_error=err, last_error_at=db.now(), last_error_category=c.category,
                           consecutive_failures=a["consecutive_failures"] + 1)
        return "retry"

    def process(self):
        done = 0
        jobs = db.claim_jobs(self.provider.name, self.account_id, self.owner, self.batch, self.lease_seconds)
        for i, job in enumerate(jobs):
            if self.stop_event.is_set():
                for rest in jobs[i:]:
                    db.release_job(rest["id"], self.owner)
                break
            if job["attempts"] >= self.max_attempts:  # poison pill: it keeps killing the worker
                db.dead_letter(job["id"], self.owner, "interrupted", "Job was interrupted repeatedly (worker crashed while processing it)")
                continue
            db.mark_in_flight(job["id"], self.owner)
            try:
                raw = self.provider.fetch_raw(job["external_id"])
                if raw is None:
                    db.dead_letter(job["id"], self.owner, "not_found", "message no longer available")
                    continue
                res = ingest.ingest_bytes(raw, f"{self.provider.name}-{job['external_id'][:40]}.eml", self.provider.name,
                                          self.account_id, job["external_id"], rescan=bool(job["engine_version"]))
                if not res["ok"]:
                    db.dead_letter(job["id"], self.owner, "malformed", res["error"])
                    continue
            except Exception as e:  # one bad message must never stop the worker
                if self._fail(job, e) == "pause":
                    for rest in jobs[i + 1:]:
                        db.release_job(rest["id"], self.owner)
                    break
                continue
            if db.complete_job(job["id"], self.owner, res["id"]):
                done += 1
                db.set_account(self.account_id, last_scan_at=db.now(), consecutive_failures=0)
        acct = self._account()
        if acct and not acct["initial_sync_done"] and db.job_counts(self.account_id)["pending"] == 0 and acct["last_sync_at"]:
            db.set_account(self.account_id, initial_sync_done=1)
        return done

    def step(self):
        result = self.poll()
        processed = self.process() if result in ("ok", "backoff", "queue_full") else 0
        if self.deliver_exports:
            splunk.deliver_pending()
        c = db.job_counts()
        if result == "ok":
            self._status(state="connected", last_processed=processed, queue=c)
        else:
            self._status(queue=c)
        return {"poll": result, "processed": processed, "jobs": c}

    def _wait(self):
        end = time.monotonic() + self.interval
        while not self.stop_event.is_set() and time.monotonic() < end:
            self.stop_event.wait(min(1.0, max(0.0, end - time.monotonic())))
            a = self._account()
            if a and a["sync_requested_at"]:  # "Sync now" pressed in the dashboard
                db.set_account(self.account_id, sync_requested_at=None)
                self._blocked_until = 0.0
                return

    def run(self):
        self.start()
        try:
            while not self.stop_event.is_set():
                try:
                    self.step()
                except Exception as e:  # never let one bad cycle kill the service
                    self._record_failure("error", e, errors.classify(e).category, self.backoff_base)
                self._wait()
        finally:
            released = db.release_owner(self.owner)
            self._status(state="stopped", stopped_at=db.now())
            log.info("worker stopped cleanly (released %s unfinished job(s))", released)


class MonitorService:
    """Runs every enabled mailbox in its OWN thread, so a slow, hung or rate-limited account never delays the others.
    Accounts enabled/disabled/disconnected in the dashboard take effect within a second, with no restart. The dashboard is
    not needed for any of this to keep running. step() runs one synchronous pass over all accounts (tests, --once)."""

    def __init__(self, connector_factory=None, interval=None, **worker_kw):
        self.factory, self.worker_kw = connector_factory, worker_kw
        self.interval = interval or settings.load()["monitoring"]["poll_seconds"]
        self.stop_event = threading.Event()
        self.workers, self.threads = {}, {}
        self._last_beat = self._last_purge_check = 0.0

    def _connector(self, acct):
        mon = settings.load()["monitoring"]
        if self.factory:
            return self.factory(acct)
        if acct["provider"] == "gmail":
            return providers.GmailProvider(account_id=acct["id"], query=f"in:inbox newer_than:{mon['initial_days']}d",
                                           reconcile_seconds=mon["reconcile_minutes"] * 60)
        if acct["provider"] == "folder":
            return providers.FolderProvider(Path(acct["config"]["path"]) if acct["config"].get("path") else None)
        raise errors.ConfigError(f"Unsupported provider: {acct['provider']}")

    def _sync_workers(self, start_threads=False):
        wanted = {a["id"]: a for a in db.list_accounts() if a["monitoring_enabled"] and a["status"] != "disconnected"}
        for aid in list(self.workers):
            dead = start_threads and aid in self.threads and not self.threads[aid].is_alive() and not self.workers[aid].stop_event.is_set()
            if aid not in wanted or dead:
                self.workers.pop(aid).stop_event.set()
                t = self.threads.pop(aid, None)
                if t and aid not in wanted:
                    t.join(5)
        for aid, a in wanted.items():
            if aid in self.workers:
                continue
            try:
                w = Worker(self._connector(a), interval=self.interval, account_id=aid, manage_status=False, deliver_exports=False, **self.worker_kw)
                self.workers[aid] = w
                if start_threads:
                    t = threading.Thread(target=w.run, name=f"emailshield-{aid}", daemon=True)
                    self.threads[aid] = t
                    t.start()
                else:
                    w.start()
            except Exception as e:
                db.set_account(aid, status="error", last_error=str(e), last_error_at=db.now(), last_error_category=errors.classify(e).category)

    def _status(self, **kw):
        s = db.get_kv("worker") or {}
        s.update(kw)
        s.update(heartbeat=db.now(), provider="monitor", interval=self.interval, pid=os.getpid())
        db.set_kv("worker", s)

    def _maybe_purge(self, now_ts=None, every=6 * 3600):
        """Retention runs while the service runs (not only at startup)."""
        now_ts = time.time() if now_ts is None else now_ts
        last = (db.get_kv("last_purge") or 0)
        if now_ts - last < every:
            return None
        pv = settings.load()["privacy"]
        r = db.purge_all(pv["retention_days"], pv["log_retention_days"])
        db.set_kv("last_purge", now_ts)
        if any(r.values()):
            db.add_event("retention", f"purged {r}")
        return r

    def _maybe_backup(self, now_ts=None, every=24 * 3600):
        """One verified backup per day while the service runs (kept: the newest N)."""
        from . import backup
        cfg = settings.load()["backup"]
        now_ts = time.time() if now_ts is None else now_ts
        if not cfg["enabled"] or now_ts - (db.get_kv("last_backup") or 0) < every:
            return None
        r = backup.create(keep=cfg["keep"])
        db.set_kv("last_backup", now_ts)
        db.add_event("backup", f"created {Path(r['file']).name}")
        return r

    def step(self):
        self._sync_workers()
        out = {}
        for aid, w in list(self.workers.items()):
            try:
                out[aid] = w.step()
            except Exception as e:
                db.add_event("error", f"{aid}: {type(e).__name__}: {redact.redact(e)[:200]}")
        ex = splunk.deliver_pending()
        self._status(state="running", accounts=len(self.workers), exports=ex, queue=db.job_counts())
        return out

    def start(self):
        db.init()
        self._status(state="starting", started_at=db.now())

    def run(self):
        self.start()
        try:
            while not self.stop_event.is_set():
                try:
                    self._sync_workers(start_threads=True)
                    t = time.monotonic()
                    if t - self._last_beat >= 5:
                        self._last_beat = t
                        ex = splunk.deliver_pending()
                        self._status(state="running", accounts=len(self.workers), alive=sum(th.is_alive() for th in self.threads.values()), exports=ex, queue=db.job_counts())
                    if t - self._last_purge_check >= 600:
                        self._last_purge_check = t
                        self._maybe_purge()
                        self._maybe_backup()
                except Exception as e:
                    self._status(state="error", last_error=redact.redact(e)[:300], last_error_at=db.now())
                    db.add_event("error", f"monitor: {type(e).__name__}: {redact.redact(e)[:200]}")
                self.stop_event.wait(1.0)
        finally:
            self._status(state="stopping")
            for w in self.workers.values():
                w.stop_event.set()
            for t in self.threads.values():
                t.join(10)
            for w in self.workers.values():
                db.release_owner(w.owner)
            self._status(state="stopped", stopped_at=db.now())
            log.info("monitor service stopped cleanly")


def main(argv=None):
    ap = argparse.ArgumentParser(description="EmailShield monitoring worker")
    ap.add_argument("--provider", choices=["folder", "gmail"], default="folder")
    ap.add_argument("--inbox", help="folder to watch (folder provider)")
    ap.add_argument("--interval", type=int, default=config.WORKER_INTERVAL)
    ap.add_argument("--once", action="store_true", help="run a single cycle and exit")
    ap.add_argument("--service", action="store_true", help="run all accounts enabled in the dashboard (MonitorService)")
    a = ap.parse_args(argv)
    setup_logging()
    if a.service:
        w = MonitorService(interval=a.interval)
    else:
        prov = providers.FolderProvider(Path(a.inbox) if a.inbox else None) if a.provider == "folder" else providers.GmailProvider()
        w = Worker(prov, interval=max(a.interval, 30) if a.provider == "gmail" else a.interval)
    if a.once:
        w.start()
        print(json.dumps(w.step()))
        if isinstance(w, Worker):
            w._status(state="stopped")
        return 0
    for sig in (signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGBREAK", signal.SIGTERM)):
        signal.signal(sig, lambda *_: w.stop_event.set())
    w.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
