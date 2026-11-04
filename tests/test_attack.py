from emailshield import attack, detector, parser
from tests.conftest import sample


def mapped(name):
    a = detector.analyze(parser.parse_eml(sample(name)))
    return a, {m["technique_id"]: m for m in attack.map_findings(a["findings"])}


def test_benign_email_maps_nothing():
    assert mapped("01_benign_newsletter")[1] == {}


def test_link_phish_maps_link_and_impersonation_only_with_evidence():
    a, m = mapped("02_paypal_lookalike")
    assert {"T1566.002", "T1656"} <= set(m) and "T1566.001" not in m


def test_attachment_techniques():
    _, m = mapped("04_invoice_exe")
    assert {"T1566.001", "T1036.007"} <= set(m)
    _, m2 = mapped("10_disguised_exe")
    assert {"T1566.001", "T1036.008"} <= set(m2)


def test_three_layers_are_separate_and_analyst_layer_is_not_prefilled():
    _, m = mapped("04_invoice_exe")
    for t in m.values():
        assert t["observed"] and t["inference"] and "Not provided" in t["analyst_interpretation"]
        assert "does not establish" in t["confidence_note"]


def test_mapped_rules_are_rules_that_actually_fired():
    a, m = mapped("02_paypal_lookalike")
    fired = {f["id"] for f in a["findings"] if f["points"] > 0}
    for t in m.values():
        assert set(t["rules"]) <= fired


def test_zero_point_findings_never_map():
    assert attack.map_findings([{"id": "att_dangerous", "points": 0, "evidence": ["x"]}]) == []
