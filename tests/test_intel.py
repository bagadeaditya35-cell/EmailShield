import base64
import json

from emailshield import config, db, ingest, intel, net
from tests.conftest import sample


class FakeHTTP:
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def __call__(self, method, url, headers=None, body=None, timeout=10):
        self.calls.append((method, url, body))
        r = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(r, Exception):
            raise r
        return r


def vt_ok(mal=3):
    return 200, {}, json.dumps({"data": {"attributes": {"last_analysis_stats": {"malicious": mal, "suspicious": 0, "harmless": 60}}}}).encode()


def stored(sample_name="03_sbi_ip_link"):
    return ingest.ingest_bytes(sample(sample_name), "x.eml")["id"]


def test_disabled_by_default_makes_no_calls():
    fake = FakeHTTP(vt_ok())
    mid = stored()
    out = intel.enrich(mid, providers=[intel.VirusTotal("k", fake, 0)], enabled=False)
    assert out["enabled"] is False and fake.calls == [] and db.get_message(mid)["intel"] == []


def test_vt_malicious_recorded_with_source_and_timestamp():
    mid = stored()
    intel.enrich(mid, providers=[intel.VirusTotal("k", FakeHTTP(vt_ok()), 0)], enabled=True)
    rec = db.get_message(mid)["intel"][0]
    assert rec["provider"] == "virustotal" and rec["verdict"] == "malicious" and rec["fetched_at"]


def test_not_found_is_not_reported_as_clean():
    mid = stored()
    intel.enrich(mid, providers=[intel.VirusTotal("k", FakeHTTP((404, {}, b"{}")), 0)], enabled=True)
    assert {r["verdict"] for r in db.get_message(mid)["intel"]} == {"not_found"}


def test_rate_limit_stops_provider_and_does_not_raise():
    fake = FakeHTTP((429, {"retry-after": "30"}, b""))
    mid = stored()
    intel.enrich(mid, providers=[intel.VirusTotal("k", fake, 0)], enabled=True)
    assert len(fake.calls) == 1 and "rate limited" in db.get_message(mid)["intel"][0]["detail"]


def test_connection_failure_is_recorded_not_raised():
    mid = stored()
    intel.enrich(mid, providers=[intel.VirusTotal("k", FakeHTTP(net.ConnectionProblem("down")), 0)], enabled=True)
    assert db.get_message(mid)["intel"][0]["verdict"] == "error"
    assert any(e["type"] == "ti_error" for e in db.list_events())


def test_cache_prevents_repeat_lookups():
    mid = stored()
    fake = FakeHTTP(vt_ok())
    prov = intel.VirusTotal("k", fake, 0)
    intel.enrich(mid, providers=[prov], enabled=True)
    n = len(fake.calls)
    intel.enrich(mid, providers=[prov], enabled=True)
    assert len(fake.calls) == n


def test_query_strings_are_stripped_before_sending(monkeypatch):
    assert intel.strip_url("https://x.example/a?token=SECRET#f") == "https://x.example/a"
    fake = FakeHTTP(vt_ok())
    intel.VirusTotal("k", fake, 0).check_url(intel.strip_url("https://x.example/a?token=SECRET"))
    enc = fake.calls[0][1].rsplit("/", 1)[1]
    assert "SECRET" not in base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4)).decode()


def test_safe_browsing_match_and_no_match():
    hit = (200, {}, json.dumps({"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}).encode())
    assert intel.SafeBrowsing("k", FakeHTTP(hit)).check_url("http://a.example")["verdict"] == "malicious"
    assert intel.SafeBrowsing("k", FakeHTTP((200, {}, b"{}"))).check_url("http://a.example")["verdict"] == "no_detections"
    assert intel.SafeBrowsing("k", FakeHTTP((403, {}, b""))).enabled()


def test_no_keys_means_no_providers(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
    assert intel.default_providers() == []


def test_ingest_still_works_when_ti_crashes(monkeypatch):
    monkeypatch.setattr(config, "TI_ENABLED", True)
    monkeypatch.setattr(intel, "default_providers", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert ingest.ingest_bytes(sample("03_sbi_ip_link"), "x.eml")["ok"]
