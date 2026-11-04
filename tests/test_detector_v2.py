import json

from emailshield import config, detector, ingest, parser, reports
from tests.conftest import sample


def analyze(name, **kw):
    p = parser.parse_eml(sample(name))
    return p, detector.analyze(p, **kw)


def test_malformed_file_is_not_low_risk():
    a = detector.analyze(parser.parse_eml(b"\x00\x01 junk \xff"))
    assert "malformed_headers" in {f["id"] for f in a["findings"]} and a["category"] != "Low risk"


def test_disguised_executable_detected_by_magic_bytes():
    p, a = analyze("10_disguised_exe")
    assert p["attachments"][0]["detected_type"] == "pe"
    assert "att_type_mismatch" in {f["id"] for f in a["findings"]} and a["category"] != "Low risk"


def test_every_finding_is_explained():
    for name in ("02_paypal_lookalike", "03_sbi_ip_link", "04_invoice_exe", "10_disguised_exe"):
        _, a = analyze(name)
        for f in a["findings"]:
            assert f["id"] and f["title"] and f["step"] and f["group"] and "points" in f
            if f["id"] != "no_auth_results":
                assert f["reason"] and f["evidence"]


def test_group_caps_prevent_runaway_scores():
    _, a = analyze("02_paypal_lookalike")
    for g, v in a["group_scores"].items():
        assert v["counted"] <= config.GROUP_CAPS[g]
    _, big = analyze("03_sbi_ip_link", weights={"url_ip_host": 100})
    assert big["group_scores"]["url"]["counted"] == config.GROUP_CAPS["url"] and big["group_scores"]["url"]["capped"]
    assert big["score"] == min(100, sum(v["counted"] for v in big["group_scores"].values()))


def test_thresholds_are_configurable():
    _, a = analyze("08_short_link", thresholds={"suspicious": 5, "high": 50})
    assert a["category"] == "Suspicious"


def test_yara_scanner_hook():
    p = parser.parse_eml(sample("04_invoice_exe"), attachment_scanner=lambda fn, data: ["Demo_Rule"])
    a = detector.analyze(p)
    assert p["attachments"][0]["yara"] == ["Demo_Rule"] and "att_yara_match" in {f["id"] for f in a["findings"]}


def test_failing_scanner_does_not_break_parsing():
    def boom(fn, data):
        raise RuntimeError("x")
    p = parser.parse_eml(sample("04_invoice_exe"), attachment_scanner=boom)
    assert p["parse_errors"] and p["attachments"]


def test_hostile_markup_is_stored_as_text_and_escaped_in_html_report():
    r = ingest.ingest_bytes(sample("11_xss_probe"), "x.eml")
    assert r["ok"]
    rep = reports.build_report(r["id"])
    html = reports.to_html(rep)
    assert "<script>alert" not in html and "&lt;script&gt;" in html
    json.dumps(rep)


def test_report_contains_no_body_or_recipients():
    r = ingest.ingest_bytes(sample("02_paypal_lookalike"), "x.eml")
    rep = reports.build_report(r["id"])
    blob = json.dumps(rep)
    assert "student@example.org" not in blob and "confirm your password" not in blob
