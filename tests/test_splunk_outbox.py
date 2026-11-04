import json
import sqlite3

from emailshield import config, db, ingest, net, secrets_store, settings, splunk
from tests.conftest import sample
from tests.test_splunk import OK, TOKEN, FakeHTTP, configure


def force_due():
    c = sqlite3.connect(config.DB_PATH)
    c.execute("UPDATE exports SET next_attempt_at='2000-01-01T00:00:00+00:00' WHERE state='retry_scheduled'")
    c.commit()


def enabled():
    configure()
    settings.update("splunk", {"enabled": True})


def test_export_disabled_by_default_queues_nothing():
    ingest.ingest_bytes(sample("02_paypal_lookalike"), "a.eml")
    assert db.export_counts() == {"pending": 0, "retry_scheduled": 0, "sent": 0, "failed": 0}
    assert splunk.deliver_pending(http=FakeHTTP(OK)) == {"sent": 0, "retry": 0, "failed": 0}


def test_invalid_configuration_fails_clearly_and_scanning_is_unaffected():
    settings.update("splunk", {"enabled": True, "url": "https://splunk.example.org:8088"})  # no token stored
    r = ingest.ingest_bytes(sample("02_paypal_lookalike"), "a.eml")
    assert r["ok"] and db.export_counts()["pending"] == 1
    out = splunk.deliver_pending(http=FakeHTTP(OK))
    assert out["failed"] == 1 and "not configured" in db.list_events(1)[0]["detail"] + str(splunk.get_status()["last_error"])
    assert db.stats()["total"] == 1


def test_authentication_failure_is_permanent_not_retried():
    enabled()
    ingest.ingest_bytes(sample("02_paypal_lookalike"), "a.eml")
    fake = FakeHTTP((401, {}, b"bad token"))
    assert splunk.deliver_pending(http=fake)["failed"] == 1
    assert db.export_counts()["failed"] == 1 and len(fake.calls) == 1
    assert splunk.deliver_pending(http=fake) == {"sent": 0, "retry": 0, "failed": 0} and len(fake.calls) == 1  # no hammering
    assert "token" in splunk.get_status()["last_error"].lower()


def test_outage_schedules_bounded_jittered_retries_then_gives_up_but_keeps_the_event():
    enabled()
    ingest.ingest_bytes(sample("02_paypal_lookalike"), "a.eml")
    fake = FakeHTTP(net.ConnectionProblem("timed out"))
    seen = []
    for _ in range(splunk.MAX_EXPORT_ATTEMPTS):
        seen.append(splunk.deliver_pending(http=fake, rng=lambda: 0.5))
        force_due()
    assert [s["retry"] for s in seen] == [1] * (splunk.MAX_EXPORT_ATTEMPTS - 1) + [0] and seen[-1]["failed"] == 1
    assert len(fake.calls) == splunk.MAX_EXPORT_ATTEMPTS and db.export_counts()["failed"] == 1  # event preserved for manual retry
    assert db.retry_exports() == 1 and db.export_counts()["pending"] == 1


def test_recovers_after_outage_and_counts_as_sent_only_after_http_200():
    enabled()
    ingest.ingest_bytes(sample("02_paypal_lookalike"), "a.eml")
    splunk.deliver_pending(http=FakeHTTP((500, {}, b"")))
    assert db.export_counts()["sent"] == 0 and splunk.get_status()["sent"] == 0  # a 500 is not delivery
    force_due()
    assert splunk.deliver_pending(http=FakeHTTP(OK))["sent"] == 1
    st = splunk.get_status()
    assert db.export_counts()["sent"] == 1 and st["sent"] == 1 and st["last_success"]


def test_events_are_deduplicated_per_alert_severity_and_engine(monkeypatch):
    enabled()
    ingest.ingest_bytes(sample("04_invoice_exe"), "a.eml", "gmail", "a", "m1")
    ingest.ingest_bytes(sample("04_invoice_exe"), "a.eml", "gmail", "a", "m1", rescan=True)  # same verdict again
    ingest.ingest_bytes(sample("04_invoice_exe"), "b.eml", "gmail", "a", "m2")  # routine duplicate in the SAME mailbox
    assert sum(db.export_counts().values()) == 1
    monkeypatch.setitem(config.WEIGHTS, "att_double_ext", 70)
    monkeypatch.setitem(config.GROUP_CAPS, "attachment", 100)
    ingest.ingest_bytes(sample("04_invoice_exe"), "a.eml", "gmail", "a", "m1", rescan=True)  # severity changed: a legitimate new event
    assert sum(db.export_counts().values()) == 2


def test_privacy_preserving_reference_and_required_fields():
    enabled()
    ingest.ingest_bytes(sample("02_paypal_lookalike"), "a.eml", "gmail", "gmail:me@example.org", "18c0ffee1234")
    ev = json.loads(db.due_exports()[0]["payload"])
    for f in ("provider", "message_ref", "score", "severity", "findings", "attack_techniques", "scan_status", "alert_id", "engine_version", "ruleset_version", "category"):
        assert f in ev and ev[f] not in (None, "")
    assert len(ev["message_ref"]) == 20 and "18c0ffee1234" not in json.dumps(ev) and "me@example.org" not in json.dumps(ev)
    assert "subject" not in ev and "urls" not in ev


def test_token_never_leaks_into_events_payloads_or_status():
    enabled()
    ingest.ingest_bytes(sample("02_paypal_lookalike"), "a.eml")
    splunk.deliver_pending(http=FakeHTTP((403, {}, f"denied for Splunk {TOKEN}".encode())))
    dump = json.dumps([db.list_events(), db.list_audit(), splunk.get_status(), [e["payload"] for e in db.due_exports()]]) + str(db.get_kv("splunk"))
    assert TOKEN not in dump


def test_scanning_continues_while_splunk_is_down():
    enabled()
    for n in ("02_paypal_lookalike", "03_sbi_ip_link", "04_invoice_exe"):
        assert ingest.ingest_bytes(sample(n), f"{n}.eml")["ok"]
    splunk.deliver_pending(http=FakeHTTP(net.ConnectionProblem("down")))
    assert db.stats()["total"] == 3 and db.export_counts()["retry_scheduled"] == 3
