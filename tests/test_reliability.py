import sqlite3
import threading
import time

import pytest

from emailshield import config, db, diskcheck, errors, health, ingest, monitor, settings, splunk
from emailshield.worker import MonitorService, Worker
from tests.conftest import sample
from tests.helpers import Mailbox
from tests.test_splunk import OK, FakeHTTP, configure


def until(cond, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


class Blocking(Mailbox):
    """A mailbox whose fetch hangs until released (models a stuck network call)."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.gate, self.entered = threading.Event(), threading.Event()

    def fetch_raw(self, ref):
        self.entered.set()
        self.gate.wait(30)
        return super().fetch_raw(ref)


def test_a_hung_mailbox_does_not_delay_other_mailboxes():
    slow = Blocking({"s1": sample("01_benign_newsletter")}, "acct:slow")
    fast = Mailbox({"f1": sample("02_paypal_lookalike")}, "acct:fast")
    boxes = {"acct:slow": slow, "acct:fast": fast}
    for a in boxes:
        db.upsert_account(a, "fake", a, monitoring_enabled=True)
    svc = MonitorService(connector_factory=lambda acct: boxes[acct["id"]], interval=1, backoff_base=0)
    t = threading.Thread(target=svc.run)
    t.start()
    try:
        assert slow.entered.wait(10)  # the slow account is stuck inside its fetch...
        assert until(lambda: db.job_counts("acct:fast")["completed"] == 1)  # ...and the other one was still scanned
        assert db.job_counts("acct:slow")["processing"] == 1
    finally:
        slow.gate.set()
        svc.stop_event.set()
        t.join(15)
    assert not t.is_alive() and db.monitoring()["worker"]["state"] == "stopped"
    assert db.job_counts()["processing"] == 0  # nothing left claimed after shutdown


def test_disabling_and_reenabling_an_account_starts_and_stops_only_its_thread():
    boxes = {a: Mailbox({}, a) for a in ("acct:a", "acct:b")}
    for a in boxes:
        db.upsert_account(a, "fake", a, monitoring_enabled=True)
    svc = MonitorService(connector_factory=lambda acct: boxes[acct["id"]], interval=1)
    t = threading.Thread(target=svc.run)
    t.start()
    try:
        assert until(lambda: len(svc.threads) == 2 and all(x.is_alive() for x in svc.threads.values()))
        db.set_account("acct:a", monitoring_enabled=0)
        assert until(lambda: "acct:a" not in svc.threads and svc.threads["acct:b"].is_alive())
        db.set_account("acct:a", monitoring_enabled=1)
        assert until(lambda: "acct:a" in svc.threads and svc.threads["acct:a"].is_alive())
    finally:
        svc.stop_event.set()
        t.join(15)
    assert not t.is_alive()


def test_backpressure_bounds_the_queue_and_never_loses_messages():
    msgs = {f"m{i}": sample("01_benign_newsletter") + f"X-N: {i}\r\n".encode() for i in range(10)}
    mb = Mailbox(msgs, "acct:q")
    db.upsert_account("acct:q", "fake", "q", monitoring_enabled=True)
    w = Worker(mb, interval=1, backoff_base=0, deliver_exports=False, account_id="acct:q", max_queue=4, batch=2)
    w.start()
    peak = 0
    for _ in range(12):
        w.poll()
        jc = db.job_counts("acct:q")
        peak = max(peak, jc["pending"] + jc["retry_scheduled"])
        w.process()
        if db.job_counts("acct:q")["completed"] == 10:
            break
    assert peak <= 4  # the waiting queue never exceeded its limit
    assert db.job_counts("acct:q")["completed"] == 10 and db.stats()["total"] == 10  # and every message was eventually scanned


def test_backpressure_does_not_advance_the_checkpoint_past_unqueued_messages():
    db.upsert_account("acct:c", "fake", "c")
    n = db.record_sync("acct:c", "fake", ["a", "b", "c", "d"], {"history_id": "99"}, capacity=2)
    assert n == 2 and db.get_account("acct:c")["sync_state"] == {}  # NOT advanced: c and d will be rediscovered
    assert db.record_sync("acct:c", "fake", ["a", "b", "c", "d"], {"history_id": "99"}, capacity=5) == 2  # a,b already queued
    assert db.get_account("acct:c")["sync_state"] == {"history_id": "99"}


def test_low_disk_pauses_monitoring_without_losing_work(monkeypatch):
    mb = Mailbox({"m1": sample("01_benign_newsletter")}, "acct:d")
    db.upsert_account("acct:d", "fake", "d", monitoring_enabled=True)
    w = Worker(mb, interval=1, backoff_base=0, deliver_exports=False, account_id="acct:d")
    w.start()
    monkeypatch.setattr(diskcheck, "free_mb", lambda path=None: 5.0)
    assert w.step() == {"poll": "low_disk", "processed": 0, "jobs": db.job_counts()}
    assert db.stats()["total"] == 0 and db.get_account("acct:d")["last_error_category"] == "disk_full"
    monkeypatch.setattr(diskcheck, "free_mb", lambda path=None: 5000.0)
    w._blocked_until = 0
    assert w.step()["processed"] == 1 and db.get_account("acct:d")["last_error_category"] is None  # resumes and clears the warning


def test_disk_full_errors_from_sqlite_are_classified_as_retryable():
    c = errors.classify(sqlite3.OperationalError("database or disk is full"))
    assert c.category == "disk_full" and c.retryable


def test_health_checks_report_real_state_and_detect_a_damaged_database(tmp_path, monkeypatch):
    h = health.run_checks()
    names = {c["name"]: c for c in h["checks"]}
    assert names["Database integrity"]["status"] == "ok" and names["Database schema"]["status"] == "ok" and names["Free disk space"]["status"] == "ok"
    p = tmp_path / "bad.db"
    p.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100 + b"garbage" * 500)
    monkeypatch.setattr(config, "DB_PATH", p)
    ok, detail = health.integrity()
    assert ok is False and detail


def test_health_flags_an_enabled_mailbox_with_no_worker_as_a_failure():
    db.upsert_account("acct:x", "fake", "x", monitoring_enabled=True)
    names = {c["name"]: c for c in health.run_checks()["checks"]}
    assert names["Monitoring worker"]["status"] == "fail"


def test_retention_removes_only_old_records_and_audit_is_kept_longer():
    ingest.ingest_bytes(sample("02_paypal_lookalike"), "old.eml")
    ingest.ingest_bytes(sample("04_invoice_exe"), "new.eml")
    db.add_audit("analyst", "something", "x")
    c = sqlite3.connect(config.DB_PATH)
    c.execute("UPDATE messages SET analyzed_at='2020-01-01T00:00:00+00:00' WHERE filename='old.eml'")
    c.execute("UPDATE audit SET ts='2020-01-01T00:00:00+00:00'")
    c.commit()
    r = db.purge_all(message_days=90, log_days=365)
    assert r["messages"] == 1 and r["audit"] == 1 and db.stats()["total"] == 1 and len(db.list_alerts()) == 1  # alert of the purged scan went with it
    assert db.purge_all(90, 365) == {k: 0 for k in r}


def test_periodic_purge_runs_in_the_service_not_only_at_startup():
    svc = MonitorService(connector_factory=lambda a: Mailbox({}, a["id"]), interval=1)
    assert svc._maybe_purge(now_ts=1_000_000, every=3600) is not None
    assert svc._maybe_purge(now_ts=1_000_100, every=3600) is None  # not due yet
    assert svc._maybe_purge(now_ts=1_005_000, every=3600) is not None


def test_data_minimisation_defaults_store_no_body_and_no_recipients_but_can_be_enabled():
    r = ingest.ingest_bytes(sample("02_paypal_lookalike"), "a.eml")
    p = db.get_message(r["id"])["parsed"]
    assert p["text"] == "" and p["to"] == "" and p["subject"] and p["urls"]  # indicators/evidence kept, content not
    settings.update("privacy", {"store_body_chars": 40, "store_recipients": True})
    r2 = ingest.ingest_bytes(sample("04_invoice_exe"), "b.eml")
    p2 = db.get_message(r2["id"])["parsed"]
    assert 0 < len(p2["text"]) <= 40 and p2["to"] == "student@example.org"
    with pytest.raises(ValueError):
        settings.update("privacy", {"store_body_chars": 999999})


def test_alert_status_changes_are_validated_audited_in_case_history_and_filterable():
    a = ingest.ingest_bytes(sample("02_paypal_lookalike"), "a.eml", "gmail", "acct:1", "m1")
    ingest.ingest_bytes(sample("04_invoice_exe"), "b.eml", "gmail", "acct:2", "m2")
    aid = a["alert_id"]
    assert db.set_alert_status(aid, "acknowledged")["previous"] == "open"
    with pytest.raises(ValueError):
        db.set_alert_status(aid, "deleted")
    assert db.set_alert_status(99999, "closed") is None
    assert "alert_status_changed" in [h["action"] for h in db.get_message(a["id"])["history"]]
    assert [x["id"] for x in db.list_alerts(status="acknowledged")] == [aid]
    assert len(db.list_alerts(severity="medium")) == 1 and len(db.list_alerts(account_id="acct:2")) == 1 and len(db.list_alerts()) == 2


def test_splunk_latency_is_measured_and_outbox_is_bounded_and_visible(monkeypatch):
    configure()
    settings.update("splunk", {"enabled": True})
    ingest.ingest_bytes(sample("02_paypal_lookalike"), "a.eml")
    splunk.deliver_pending(http=FakeHTTP(OK))
    st = splunk.get_status()
    assert st["last_latency_ms"] is not None and st["avg_latency_ms"] is not None and st["sent"] == 1
    monkeypatch.setattr(config, "MAX_OUTBOX", 1)
    ingest.ingest_bytes(sample("03_sbi_ip_link"), "b.eml")  # queued (1 pending)
    ingest.ingest_bytes(sample("04_invoice_exe"), "c.eml")  # outbox full: refused loudly, not silently
    assert db.export_counts()["pending"] == 1 and splunk.get_status()["dropped"] == 1
    assert any("queue full" in e["detail"] for e in db.list_events())
    assert db.stats()["total"] == 3  # scanning itself is unaffected
