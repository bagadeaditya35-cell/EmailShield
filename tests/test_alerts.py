from emailshield import db, ingest
from tests.conftest import sample


def test_alerts_only_for_suspicious_and_high_and_one_per_message():
    benign = ingest.ingest_bytes(sample("01_benign_newsletter"), "a.eml")
    assert benign["alert_id"] is None and db.alert_counts() == {"high": 0, "medium": 0, "low": 0}
    hi = ingest.ingest_bytes(sample("02_paypal_lookalike"), "b.eml")
    mid = ingest.ingest_bytes(sample("04_invoice_exe"), "c.eml")
    assert hi["alert_id"] and mid["alert_id"] and db.alert_counts()["high"] == 1 and db.alert_counts()["medium"] == 1
    again = ingest.ingest_bytes(sample("02_paypal_lookalike"), "b2.eml")  # routine duplicate
    assert again["duplicate"] and again["alert_id"] is None and len(db.list_alerts()) == 2


def test_alert_references_and_case_history():
    r = ingest.ingest_bytes(sample("02_paypal_lookalike"), "b.eml")
    a = db.list_alerts()[0]
    assert a["alert_ref"].startswith("ALR-") and a["case_ref"] == f"INV-{r['id']:05d}" and a["severity"] == "high"
    assert "alert_created" in [h["action"] for h in db.get_message(r["id"])["history"]]


def test_rescan_updates_the_same_alert_and_is_audited_in_history(monkeypatch):
    from emailshield import config
    r = ingest.ingest_bytes(sample("04_invoice_exe"), "c.eml", "gmail", "a", "m1")  # Suspicious
    aid = r["alert_id"]
    monkeypatch.setitem(config.WEIGHTS, "att_double_ext", 70)  # a new engine version judges it worse...
    monkeypatch.setitem(config.GROUP_CAPS, "attachment", 100)  # ...(the group cap would otherwise hold the score under 70)
    again = ingest.ingest_bytes(sample("04_invoice_exe"), "c.eml", "gmail", "a", "m1", rescan=True)
    assert again["rescanned"] and again["alert_id"] == aid and len(db.list_alerts()) == 1
    msg = db.get_message(r["id"])
    assert db.list_alerts()[0]["severity"] == "high" and msg["category"] == "High risk"
    actions = [h["action"] for h in msg["history"]]
    assert "rescanned" in actions and "alert_updated" in actions


def test_every_scan_stores_engine_and_ruleset_version():
    r = ingest.ingest_bytes(sample("01_benign_newsletter"), "a.eml")
    m = db.get_message(r["id"])
    assert m["engine_version"] and len(m["ruleset_version"]) == 12 and m["analysis"]["engine"]["ruleset"] == m["ruleset_version"]


def test_ruleset_fingerprint_changes_when_weights_change(monkeypatch):
    from emailshield import config, detector
    before = detector.ruleset_version()
    monkeypatch.setitem(config.WEIGHTS, "url_http", 99)
    assert detector.ruleset_version() != before
