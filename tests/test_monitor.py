import sqlite3

from emailshield import config, db, monitor, net, settings, splunk
from emailshield.worker import MonitorService, Worker
from tests.conftest import sample
from tests.helpers import Mailbox
from tests.test_splunk import OK, TOKEN, FakeHTTP, configure


class Crash(BaseException):
    """Simulates the worker process dying (not an ordinary Exception)."""


def mk(mailbox, **kw):
    kw.setdefault("backoff_base", 0)
    kw.setdefault("rng", lambda: 0.0)
    w = Worker(mailbox, interval=1, deliver_exports=False, **kw)
    w.start()
    return w


def job(ref="m1"):
    return next(j for j in db.list_jobs() if j["external_id"] == ref)


def test_end_to_end_synthetic_message_to_scan_alert_and_sanitized_splunk_event():
    configure(); settings.update("splunk", {"enabled": True})
    mb = Mailbox({"m1": sample("02_paypal_lookalike")})
    w = mk(mb)
    assert w.step() == {"poll": "ok", "processed": 1, "jobs": {**db.job_counts()}}
    j = job()
    assert j["state"] == "completed" and j["scan_id"] and j["completed_at"] and j["account_id"] == "fake:acct"
    msg = db.get_message(j["scan_id"])
    assert msg["external_id"] == "m1" and msg["account_id"] == "fake:acct" and msg["engine_version"] and msg["ruleset_version"]
    assert db.alert_counts()["high"] == 1 and db.export_counts()["pending"] == 1
    fake = FakeHTTP(OK)
    assert splunk.deliver_pending(http=fake) == {"sent": 1, "retry": 0, "failed": 0}
    ev = __import__("json").loads(fake.calls[0]["body"])["event"]
    assert ev["provider"] == "fake" and ev["severity"] == "high" and ev["alert_id"].startswith("ALR-") and ev["scan_status"] == "completed"
    assert "T1566.002" in ev["attack_techniques"] and ev["findings"] and ev["engine_version"]
    blob = fake.calls[0]["body"].decode()
    for forbidden in ("confirm your password", "student@example.org", "paypa1.com/secure/login", "m1\""):
        assert forbidden not in blob
    assert db.export_counts()["sent"] == 1


def test_duplicate_messages_and_repeated_syncs_create_one_scan_and_one_alert():
    raw = sample("02_paypal_lookalike")
    w = mk(Mailbox({"m1": raw, "m2": raw}))  # same content under two provider ids
    for _ in range(3):
        w.step()
    assert db.stats()["total"] == 1 and len(db.list_alerts()) == 1 and db.job_counts()["completed"] == 2


def test_auth_problem_pauses_the_account_keeps_the_job_and_resumes_after_reconnect():
    mb = Mailbox({"m1": sample("01_benign_newsletter")})
    mb.fetch_errors["m1"] = [net.AuthError("token revoked")]
    w = mk(mb)
    assert w.step()["processed"] == 0
    j, a = job(), db.get_account("fake:acct")
    assert j["state"] == "pending" and j["attempts"] == 0 and j["error_category"] == "auth_required"  # not lost, not dead-lettered
    assert a["status"] == "auth_required" and monitor.overview()["accounts"][0]["state"] == "authentication_required"
    assert w.step()["poll"] == "auth_error" and mb.fetch_log == ["m1"]  # paused: no hammering the provider
    db.set_account("fake:acct", status="connected")  # user reconnected
    w._blocked_until = 0
    assert w.step()["processed"] == 1 and job()["state"] == "completed"


def test_rate_limit_honours_provider_guidance_without_burning_attempts():
    mb = Mailbox({"m1": sample("01_benign_newsletter")})
    mb.fetch_errors["m1"] = [net.RateLimited(120)]
    mk(mb).step()
    j = job()
    assert j["state"] == "retry_scheduled" and j["attempts"] == 0 and j["next_attempt_at"] > db.after(100) and j["error_category"] == "rate_limit"


def test_retries_exhaust_into_dead_letter_then_manual_retry_succeeds():
    mb = Mailbox({"m1": sample("01_benign_newsletter")})
    mb.fetch_errors["m1"] = [net.ConnectionProblem("offline")] * 10
    w = mk(mb, max_attempts=2)
    for _ in range(4):
        w.step()
    j = job()
    assert j["state"] == "failed" and j["attempts"] == 2 and j["error_category"] == "network" and j["dead_lettered_at"] and "retries exhausted" in j["last_error"]
    assert db.stats()["total"] == 0  # the failed email is preserved as a failed job, not silently dropped
    mb.fetch_errors["m1"] = []
    assert db.retry_jobs() == [j["id"]]
    w.step()
    assert job()["state"] == "completed" and db.stats()["total"] == 1


def test_one_malformed_email_does_not_stop_the_worker():
    w = mk(Mailbox({"bad": b"   ", "ok": sample("01_benign_newsletter")}))
    assert w.step()["processed"] == 1
    assert job("bad")["state"] == "failed" and job("bad")["error_category"] == "malformed" and job("ok")["state"] == "completed"


def test_unexpected_exception_in_one_job_is_contained():
    mb = Mailbox({"a": sample("01_benign_newsletter"), "b": sample("02_paypal_lookalike")})
    mb.fetch_errors["a"] = [RuntimeError("parser exploded")]
    w = mk(mb)
    assert w.step()["processed"] == 1 and job("b")["state"] == "completed" and job("a")["state"] == "retry_scheduled"


def test_worker_crash_is_recovered_by_the_next_worker():
    mb = Mailbox({"m1": sample("01_benign_newsletter")})
    mb.fetch_errors["m1"] = [Crash()]
    try:
        mk(mb, lease_seconds=-1).step()
    except Crash:
        pass
    assert job()["state"] == "processing" and db.stats()["total"] == 0  # died mid-job
    w2 = mk(mb)  # "restart": reclaims the orphaned job
    assert w2.step()["processed"] == 1 and job()["state"] == "completed" and job()["attempts"] == 1 and db.stats()["total"] == 1


def test_poison_message_that_keeps_crashing_the_worker_is_dead_lettered():
    mb = Mailbox({"poison": sample("01_benign_newsletter"), "good": sample("02_paypal_lookalike")})
    mb.fetch_errors["poison"] = [Crash(), Crash(), Crash(), Crash()]
    for _ in range(4):
        try:
            mk(mb, max_attempts=3, lease_seconds=-1).step()
        except Crash:
            pass
    assert job("poison")["state"] == "failed" and job("poison")["error_category"] == "interrupted" and job("good")["state"] == "completed"


def test_graceful_shutdown_hands_unfinished_jobs_back():
    class StopAfterFirst(Mailbox):
        def fetch_raw(self, ref):
            raw = super().fetch_raw(ref)
            w.stop_event.set()
            return raw
    mb = StopAfterFirst({f"m{i}": sample("01_benign_newsletter") + f"X-N: {i}\r\n".encode() for i in range(4)})
    w = mk(mb)
    w.step()
    c = db.job_counts()
    assert c["completed"] == 1 and c["pending"] == 3 and c["processing"] == 0  # nothing stuck, nothing lost


def test_pending_work_resumes_after_restart():
    mb = Mailbox({"m1": sample("01_benign_newsletter")})
    mk(mb).poll()  # discovered and queued, never processed (app closed)
    assert job()["state"] == "pending"
    db._ready.clear()
    assert mk(mb).step()["processed"] == 1 and job()["state"] == "completed"


def test_initial_sync_flag_and_monitoring_states():
    assert monitor.overview()["overall"]["level"] == "off"
    db.upsert_account("fake:acct", "fake", "box", monitoring_enabled=False)
    assert monitor.overview()["accounts"][0]["state"] == "disabled"
    db.set_account("fake:acct", monitoring_enabled=1)
    o = monitor.overview()
    assert o["accounts"][0]["state"] == "error" and o["overall"]["level"] == "error" and "not working" in o["overall"]["label"]  # enabled, nobody watching
    mb = Mailbox({"m1": sample("01_benign_newsletter")})
    w = Worker(mb, interval=1, backoff_base=0, account_id="fake:acct")
    w.start()
    w.poll()
    assert monitor.overview()["accounts"][0]["state"] == "synchronizing"
    w.process()
    o = monitor.overview()
    assert o["accounts"][0]["state"] == "monitoring" and o["overall"]["level"] == "ok" and o["indicators"]["last_scan"] and o["indicators"]["last_sync"]
    db.set_account("fake:acct", consecutive_failures=2)
    assert monitor.overview()["accounts"][0]["state"] == "degraded"
    db.set_account("fake:acct", consecutive_failures=0, status="auth_required")
    assert monitor.overview()["overall"]["level"] == "error"
    db.set_account("fake:acct", status="connecting")
    assert monitor.overview()["accounts"][0]["state"] == "connecting"


def test_status_is_never_green_when_the_worker_stopped_or_went_stale():
    db.upsert_account("fake:acct", "fake", "box", monitoring_enabled=True)
    db.set_account("fake:acct", initial_sync_done=1)
    w = Worker(Mailbox(), interval=1, account_id="fake:acct")
    w.start()
    w.step()
    assert monitor.overview()["overall"]["level"] == "ok"
    w.stop_event.set()
    w._status(state="stopped")
    assert monitor.overview()["overall"]["level"] == "error" and monitor.overview()["indicators"]["worker"] == "stopped"
    s = db.get_kv("worker")
    s.update(state="connected", heartbeat="2000-01-01T00:00:00+00:00")
    db.set_kv("worker", s)
    o = monitor.overview()
    assert o["indicators"]["worker"] == "stale" and o["overall"]["level"] == "error"
    assert "24/7" not in str(o)


def test_monitor_service_runs_enabled_accounts_and_reacts_to_dashboard_changes():
    boxes = {"fake:a": Mailbox({"a1": sample("01_benign_newsletter")}, "fake:a"), "fake:b": Mailbox({"b1": sample("02_paypal_lookalike")}, "fake:b")}
    db.upsert_account("fake:a", "fake", "A", monitoring_enabled=True)
    db.upsert_account("fake:b", "fake", "B", monitoring_enabled=True)
    svc = MonitorService(connector_factory=lambda acct: boxes[acct["id"]], interval=1)
    svc.start()
    out = svc.step()
    assert set(out) == {"fake:a", "fake:b"} and db.stats()["total"] == 2 and db.get_kv("worker")["state"] == "running"
    db.set_account("fake:b", monitoring_enabled=0)  # user switches B off in the dashboard: no restart needed
    boxes["fake:a"].messages["a2"] = sample("04_invoice_exe")
    assert set(svc.step()) == {"fake:a"} and db.stats()["total"] == 3
    db.set_account("fake:a", status="disconnected")
    assert svc.step() == {}


def test_a_monitor_service_with_a_broken_account_keeps_serving_others():
    db.upsert_account("fake:ok", "fake", "ok", monitoring_enabled=True)
    db.upsert_account("fake:bad", "fake", "bad", monitoring_enabled=True)

    def factory(acct):
        if acct["id"] == "fake:bad":
            raise ValueError("bad config")
        return Mailbox({"x": sample("01_benign_newsletter")}, acct["id"])
    svc = MonitorService(connector_factory=factory, interval=1)
    svc.start()
    assert "fake:ok" in svc.step() and db.get_account("fake:bad")["status"] == "error"
