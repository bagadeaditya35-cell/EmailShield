import json
import os
import stat
import sys
import time

import pytest

from emailshield import config, db, ingest, net, secrets_store, settings, splunk
from tests.conftest import sample

TOKEN = "11111111-2222-3333-4444-555555555555"


class FakeHTTP:
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def __call__(self, method, url, headers=None, body=None, timeout=10, **kw):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        r = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(r, Exception):
            raise r
        return r


OK = (200, {}, b'{"text":"Success","code":0}')


def configure(**over):
    settings.update("splunk", {"enabled": True, "url": "https://splunk.example.org:8088", **over})
    secrets_store.set(splunk.TOKEN_NAME, TOKEN)


def high_risk_id():
    return ingest.ingest_bytes(sample("02_paypal_lookalike"), "a.eml")["id"]


def test_disabled_by_default_sends_nothing():
    fake = FakeHTTP(OK)
    mid = high_risk_id()
    assert splunk.forward_alert(mid, http=fake)["reason"] == "disabled" and fake.calls == []


def test_alert_event_is_structured_and_privacy_minimal():
    mid = high_risk_id()
    configure()
    fake = FakeHTTP(OK)
    assert splunk.forward_alert(mid, http=fake)["sent"] is True
    call = fake.calls[0]
    assert call["url"].endswith("/services/collector/event") and call["headers"]["Authorization"] == f"Splunk {TOKEN}"
    payload = json.loads(call["body"])
    ev = payload["event"]
    assert payload["sourcetype"] == "emailshield:alert" and ev["category"] == "High risk" and ev["case_ref"].startswith("INV-")
    assert "T1566.002" in ev["attack_techniques"] and ev["findings"] and ev["synthetic"] is False
    blob = call["body"].decode()
    for secret in ("student@example.org", "confirm your password", "verify your account immediately", "http://paypa1.com/secure/login"):
        assert secret not in blob
    assert "urls" not in ev and "subject" not in ev


def test_optional_fields_only_when_opted_in():
    mid = high_risk_id()
    configure(include_urls=True, include_subject=True)
    fake = FakeHTTP(OK)
    splunk.forward_alert(mid, http=fake)
    ev = json.loads(fake.calls[0]["body"])["event"]
    assert ev["urls"] and "subject" in ev


def test_threshold_respected():
    mid = ingest.ingest_bytes(sample("04_invoice_exe"), "b.eml")["id"]  # Suspicious
    configure(min_category="High risk")
    fake = FakeHTTP(OK)
    assert splunk.forward_alert(mid, http=fake)["reason"] == "below threshold" and fake.calls == []


def test_auth_failure_is_not_retried_and_never_raises():
    mid = high_risk_id()
    configure()
    fake = FakeHTTP((403, {}, b"forbidden"))
    out = splunk.forward_alert(mid, http=fake, sleep=lambda s: None)
    assert out["sent"] is False and len(fake.calls) == 1
    st = splunk.get_status()
    assert st["failed"] == 1 and "token" in st["last_error"].lower()
    assert any(e["type"] == "splunk_error" for e in db.list_events())


def test_retries_are_bounded_with_backoff():
    mid = high_risk_id()
    configure()
    sleeps = []
    fake = FakeHTTP((503, {}, b""))
    out = splunk.forward_alert(mid, http=fake, sleep=sleeps.append)
    assert out["sent"] is False and len(fake.calls) == 3 and sleeps == [1, 2]


def test_recovers_after_transient_connection_error():
    mid = high_risk_id()
    configure()
    fake = FakeHTTP(net.ConnectionProblem("down"), OK)
    assert splunk.forward_alert(mid, http=fake, sleep=lambda s: None)["sent"] is True and len(fake.calls) == 2


def test_connection_test_sends_clearly_synthetic_event():
    configure()
    fake = FakeHTTP(OK)
    r = splunk.test_connection(http=fake, sleep=lambda s: None)
    assert r["ok"] is True
    ev = json.loads(fake.calls[-1]["body"])
    assert ev["event"]["synthetic"] is True and ev["sourcetype"] == "emailshield:test"


def test_connection_test_when_not_configured_is_a_clear_error():
    r = splunk.test_connection(http=FakeHTTP(OK))
    assert r["ok"] is False and "not configured" in r["detail"]


def test_token_never_appears_in_status_or_settings():
    configure()
    assert TOKEN not in json.dumps(splunk.get_status()) and TOKEN not in json.dumps(settings.load())
    assert splunk.get_status()["token_configured"] is True


def test_local_analysis_works_when_splunk_is_down(monkeypatch):
    configure()

    def boom(*a, **k):
        raise net.ConnectionProblem("splunk down")
    monkeypatch.setattr(net, "request", boom)
    monkeypatch.setattr(time, "sleep", lambda s: None)
    r = ingest.ingest_bytes(sample("02_paypal_lookalike"), "x.eml")
    assert r["ok"] and db.stats()["total"] == 1  # scanning finished without waiting for Splunk
    assert db.export_counts()["pending"] == 1 and splunk.get_status()["failed"] == 0  # event is queued, not lost
    out = splunk.deliver_pending()  # Splunk is down: scheduled for a bounded retry, never raises
    assert out["retry"] == 1 and db.export_counts()["retry_scheduled"] == 1


def test_secrets_env_overrides_and_file_is_private(monkeypatch):
    monkeypatch.delenv("DEMO_SECRET", raising=False)
    assert secrets_store.get("demo_secret") == ""
    secrets_store.set("demo_secret", "abc")
    assert secrets_store.get("demo_secret") == "abc"
    if not sys.platform.startswith("win"):
        assert stat.S_IMODE(os.stat(config.DATA_DIR / "secrets.json").st_mode) == 0o600
    monkeypatch.setenv("DEMO_SECRET", "from-env")
    assert secrets_store.get("demo_secret") == "from-env"
    monkeypatch.delenv("DEMO_SECRET")
    secrets_store.delete("demo_secret")
    assert not secrets_store.has("demo_secret")


def test_settings_validation():
    for section, bad in (("splunk", {"nope": 1}), ("splunk", {"enabled": "yes"}), ("splunk", {"url": "ftp://x"}),
                         ("splunk", {"min_category": "Low risk"}), ("worker", {"interval": 1}), ("worker", {"provider": "imap"}),
                         ("bogus", {})):
        with pytest.raises(ValueError):
            settings.update(section, bad)
    assert settings.load()["splunk"]["enabled"] is False  # defaults untouched after rejected updates
