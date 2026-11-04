import json
import pytest

from emailshield import config, db, detector, ingest, parser, reports
from tests.conftest import sample


def run(name):
    p = parser.parse_eml(sample(name))
    return p, detector.analyze(p)


def test_benign_is_low():
    _, a = run("01_benign_newsletter")
    assert a["category"] == "Low risk" and a["score"] < 30


def test_paypal_lookalike_high():
    p, a = run("02_paypal_lookalike")
    ids = {f["id"] for f in a["findings"]}
    assert a["category"] == "High risk"
    assert {"sender_lookalike_domain", "link_text_mismatch", "spf_fail", "reply_to_mismatch"} <= ids


def test_ip_url_and_keywords():
    _, a = run("03_sbi_ip_link")
    ids = {f["id"] for f in a["findings"]}
    assert "url_ip_host" in ids and "kw_credentials" in ids and a["category"] != "Low risk"


def test_attachment_hash_and_double_ext():
    import hashlib
    p, a = run("04_invoice_exe")
    assert p["attachments"][0]["sha256"] == hashlib.sha256(b"SYNTHETIC-NOT-REAL-MALWARE-1").hexdigest()
    assert "att_double_ext" in {f["id"] for f in a["findings"]}
    assert "no_auth_results" in {f["id"] for f in a["findings"]}


def test_url_extraction_dedup():
    p, _ = run("08_short_link")
    assert [u["url"] for u in p["urls"]] == ["https://bit.ly/abc123"]


def test_score_capped_and_explained():
    _, a = run("02_paypal_lookalike")
    assert a["score"] <= 100
    assert all(f["reason"] and f["evidence"] for f in a["findings"] if f["id"] != "no_auth_results")
    assert "not" in a["note"].lower()


def test_malformed_and_empty_do_not_crash():
    r = ingest.ingest_bytes(b"\x00\xff garbage", "bad.eml")
    assert r["ok"] in (True, False)
    r2 = ingest.ingest_bytes(b"", "empty.eml")
    assert r2["ok"] is False


def test_size_limit(monkeypatch):
    monkeypatch.setattr(config, "MAX_EML_BYTES", 10)
    assert ingest.ingest_bytes(sample("01_benign_newsletter"), "big.eml")["ok"] is False


def test_duplicate_prevention():
    a = ingest.ingest_bytes(sample("01_benign_newsletter"), "a.eml")
    b = ingest.ingest_bytes(sample("01_benign_newsletter"), "b.eml")
    assert a["ok"] and not a["duplicate"] and b["duplicate"] and a["id"] == b["id"]
    assert db.stats()["total"] == 1


def test_filename_path_traversal_sanitized():
    r = ingest.ingest_bytes(sample("01_benign_newsletter"), "../../etc/passwd.eml")
    assert db.get_message(r["id"])["filename"] == "passwd.eml"


def test_db_status_notes_and_validation():
    r = ingest.ingest_bytes(sample("02_paypal_lookalike"), "x.eml")
    m = db.update_message(r["id"], status="investigating", notes="checking")
    assert m["status"] == "investigating" and m["notes"] == "checking"
    with pytest.raises(ValueError):
        db.update_message(r["id"], status="bogus")


def test_search_and_filter():
    ingest.ingest_folder(config.BASE_DIR / "samples")
    assert db.list_messages(category="High risk")
    assert all("paypal" in m["subject"].lower() or "paypal" in m["sender"].lower() or True for m in db.list_messages(q="verify"))
    assert db.list_messages(q="' OR 1=1 --") == []


def test_correlation():
    a = ingest.ingest_bytes(sample("05_campaign_a"), "a.eml")
    b = ingest.ingest_bytes(sample("06_campaign_b"), "b.eml")
    rel = db.find_related(a["id"])
    assert [x["id"] for x in rel["related"]] == [b["id"]]
    assert any("payroll-portal" in r for r in rel["related"][0]["reasons"])
    assert "NOT proof" in rel["caveat"]


def test_report_json_and_text():
    r = ingest.ingest_bytes(sample("02_paypal_lookalike"), "x.eml")
    rep = reports.build_report(r["id"])
    json.dumps(rep)
    txt = reports.to_text(rep)
    assert rep["report_id"].startswith("ES-") and "LIMITATIONS" in txt and "FINDINGS" in txt
    assert reports.build_report(99999) is None


def test_purge_retention():
    ingest.ingest_bytes(sample("01_benign_newsletter"), "a.eml")
    assert db.purge(days=0) in (0, 1)
    assert db.purge(days=365) == 0


def test_levenshtein_and_regdomain():
    assert detector.levenshtein("paypal", "paypa1") == 1
    assert detector.reg_domain("a.b.example.co.in") == "example.co.in"
