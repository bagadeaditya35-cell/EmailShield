"""API tests - need fastapi + httpx (pip install -r requirements.txt). Skipped automatically if missing."""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from emailshield import config  # noqa: E402
from tests.conftest import sample  # noqa: E402

H = {"X-API-Key": "testkey"}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("EMAILSHIELD_API_KEY", "testkey")
    from emailshield import app as appmod
    appmod._fails.clear()
    with TestClient(appmod.app) as c:
        yield c


def up(client, name="02_paypal_lookalike", fn="a.eml"):
    return client.post(f"/api/analyze?filename={fn}", content=sample(name), headers=H)


def test_all_api_routes_require_key(client):
    from emailshield import app as appmod

    def fresh():  # the login lockout is intentional, so reset it between requests in this test
        appmod._fails.clear()
        return client
    for path in ("/api/stats", "/api/messages", "/api/events", "/api/audit", "/api/monitoring", "/api/config", "/api/messages/1"):
        assert fresh().get(path).status_code == 401
        assert fresh().get(path, headers={"X-API-Key": "wrong"}).status_code == 401
    assert fresh().post("/api/analyze?filename=a.eml", content=b"x").status_code == 401


def test_login_lockout_after_repeated_failures(client):
    codes = [client.get("/api/stats", headers={"X-API-Key": "bad"}).status_code for _ in range(12)]
    assert codes[0] == 401 and codes[-1] == 429
    assert client.get("/api/stats", headers=H).status_code == 429


def test_analyze_and_dashboard_data(client):
    r = up(client)
    assert r.status_code == 200 and r.json()["category"] == "High risk"
    assert client.get("/api/stats", headers=H).json()["total"] == 1
    mid = r.json()["id"]
    m = client.get(f"/api/messages/{mid}", headers=H).json()
    assert m["case_ref"] == f"INV-{mid:05d}" and m["history"][0]["action"] == "created"
    assert client.get("/api/messages?q=verify", headers=H).json()


def test_duplicate_upload(client):
    assert up(client).json()["duplicate"] is False
    assert up(client, fn="b.eml").json()["duplicate"] is True


def test_upload_validation(client, monkeypatch):
    assert client.post("/api/analyze?filename=a.exe", content=b"x", headers=H).status_code == 400
    assert client.post("/api/analyze?filename=a.eml", content=b"", headers=H).status_code == 422
    monkeypatch.setattr(config, "MAX_EML_BYTES", 100)
    assert up(client).status_code == 413


def test_filename_cannot_traverse(client):
    mid = up(client, fn="../../evil.eml").json()["id"]
    assert client.get(f"/api/messages/{mid}", headers=H).json()["filename"] == "evil.eml"


def test_reports_in_three_formats(client):
    mid = up(client).json()["id"]
    j = client.get(f"/api/messages/{mid}/report", headers=H)
    assert j.json()["report_id"].startswith("ES-") and "attachment" in j.headers["content-disposition"]
    assert "FINDINGS" in client.get(f"/api/messages/{mid}/report?format=txt", headers=H).text
    assert "<h1>EmailShield report" in client.get(f"/api/messages/{mid}/report?format=html", headers=H).text
    assert client.get(f"/api/messages/{mid}/report?format=pdf", headers=H).status_code == 400
    assert client.get("/api/messages/999/report", headers=H).status_code == 404


def test_hostile_email_is_escaped_in_html_report(client):
    mid = up(client, "11_xss_probe").json()["id"]
    html = client.get(f"/api/messages/{mid}/report?format=html", headers=H).text
    assert "<script>alert" not in html and "&lt;script&gt;" in html


def test_case_notes_status_and_history(client):
    mid = up(client).json()["id"]
    r = client.patch(f"/api/messages/{mid}", json={"status": "investigating", "notes": "checking sender"}, headers=H)
    assert r.status_code == 200 and r.json()["status"] == "investigating"
    actions = [h["action"] for h in client.get(f"/api/messages/{mid}", headers=H).json()["history"]]
    assert "status_changed" in actions and "notes_updated" in actions
    assert client.patch(f"/api/messages/{mid}", json={"status": "bogus"}, headers=H).status_code == 400
    assert client.patch(f"/api/messages/{mid}", content=b"[1,2]", headers=H).status_code == 400
    assert client.patch("/api/messages/999", json={"status": "closed"}, headers=H).status_code == 404
    assert any(a["action"] == "update" for a in client.get("/api/audit", headers=H).json())


def test_related_and_monitoring_and_config(client):
    a = up(client, "05_campaign_a").json()["id"]
    up(client, "06_campaign_b")
    rel = client.get(f"/api/messages/{a}/related", headers=H).json()
    assert len(rel["related"]) == 1 and "NOT proof" in rel["caveat"]
    mon = client.get("/api/monitoring", headers=H).json()
    assert mon["health"] == "not_running" and "pending" in mon["jobs"] and mon["overall"]["level"] == "off"
    cfg = client.get("/api/config", headers=H).json()
    assert cfg["ti_enabled"] is False and "new" in cfg["statuses"]
    assert client.post(f"/api/messages/{a}/enrich", headers=H).json()["enabled"] is False


def test_security_headers_and_static_pages(client):
    r = client.get("/")
    assert r.status_code == 200 and "EmailShield" in r.text
    assert "script-src 'self'" in r.headers["content-security-policy"] and r.headers["x-frame-options"] == "DENY"
    js = client.get("/static/app.js")
    assert js.status_code == 200
    import re
    code = re.sub(r"//[^\n]*|/\*.*?\*/", "", js.text, flags=re.S)  # ignore comments
    assert not re.search(r"\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write|\beval\(", code)


def test_settings_and_splunk_token_is_write_only(client):
    tok = "SUPER-SECRET-HEC-TOKEN-123"
    r = client.put("/api/settings/splunk", json={"enabled": False, "url": "https://splunk.example.org:8088", "token": tok}, headers=H)
    assert r.status_code == 200 and tok not in r.text
    assert tok not in client.get("/api/settings", headers=H).text and tok not in client.get("/api/integrations/splunk", headers=H).text
    assert client.get("/api/integrations/splunk", headers=H).json()["token_configured"] is True
    assert tok not in str(client.get("/api/audit", headers=H).json())
    assert client.put("/api/settings/splunk", json={"url": "ftp://x"}, headers=H).status_code == 400
    assert client.put("/api/settings/nope", json={}, headers=H).status_code == 400
    assert client.put("/api/settings/worker", json={"interval": 1}, headers=H).status_code == 400
    assert client.post("/api/integrations/splunk/test", headers=H).json()["ok"] in (True, False)


def test_settings_routes_require_key(client):
    for method, path in (("get", "/api/settings"), ("put", "/api/settings/splunk"), ("get", "/api/integrations/splunk"), ("post", "/api/integrations/splunk/test")):
        assert getattr(client, method)(path).status_code == 401


def test_message_detail_includes_attack_mapping_and_about_info(client):
    mid = up(client).json()["id"]
    assert any(t["technique_id"] == "T1566.002" for t in client.get(f"/api/messages/{mid}", headers=H).json()["attack"])
    cfg = client.get("/api/config", headers=H).json()
    assert cfg["version"] and cfg["remote_access"] is False and cfg["bind"].startswith("127.0.0.1")


NEW_ROUTES = (("get", "/api/accounts"), ("get", "/api/jobs"), ("get", "/api/alerts"), ("get", "/api/connectors/gmail"), ("get", "/api/autostart"),
              ("put", "/api/connectors/gmail/credentials"), ("post", "/api/connectors/gmail/connect"), ("post", "/api/connectors/folder"),
              ("post", "/api/jobs/retry"), ("post", "/api/rescan"), ("put", "/api/autostart"),
              ("post", "/api/accounts/folder:default/monitoring"), ("post", "/api/accounts/folder:default/sync"), ("post", "/api/accounts/folder:default/disconnect"))


def test_all_new_monitoring_routes_require_the_key(client):
    from emailshield import app as appmod
    for method, path in NEW_ROUTES:
        appmod._fails.clear()
        assert getattr(client, method)(path).status_code == 401, path


def test_gmail_credentials_are_validated_and_write_only(client):
    assert client.put("/api/connectors/gmail/credentials", json={"client_secret_json": "nope"}, headers=H).status_code == 400
    good = '{"installed": {"client_id": "abc.apps.example", "client_secret": "TOP-SECRET-VALUE"}}'
    r = client.put("/api/connectors/gmail/credentials", json={"client_secret_json": good}, headers=H)
    assert r.status_code == 200 and "TOP-SECRET-VALUE" not in r.text
    st = client.get("/api/connectors/gmail", headers=H)
    assert st.json()["credentials_configured"] is True and "TOP-SECRET-VALUE" not in st.text and st.json()["scope"].endswith("gmail.readonly")
    assert "TOP-SECRET-VALUE" not in str(client.get("/api/audit", headers=H).json())


def test_connect_needs_credentials_then_returns_a_pkce_url(client):
    assert client.post("/api/connectors/gmail/connect", json={}, headers=H).status_code == 409
    client.put("/api/connectors/gmail/credentials", json={"client_secret_json": '{"installed": {"client_id": "cid", "client_secret": "csec"}}'}, headers=H)
    r = client.post("/api/connectors/gmail/connect", json={}, headers=H).json()
    assert "code_challenge_method=S256" in r["auth_url"] and "gmail.readonly" in r["auth_url"] and "csec" not in r["auth_url"]


def test_oauth_callback_rejects_forged_state_and_escapes_output(client):
    r = client.get("/oauth/gmail/callback?state=forged&code=x")
    assert r.status_code == 400 and "Could not connect" in r.text and "<script>" not in r.text
    r2 = client.get("/oauth/gmail/callback?error=access_denied&state=<script>alert(1)</script>")
    assert r2.status_code == 400 and "<script>alert" not in r2.text
    assert db_accounts(client) == []


def db_accounts(client):
    return client.get("/api/accounts", headers=H).json()


def test_folder_mailbox_workflow_enable_sync_disconnect(client, tmp_path):
    r = client.post("/api/connectors/folder", json={"path": str(tmp_path / "inbox")}, headers=H)
    assert r.status_code == 200 and r.json()["id"] == "folder:default"
    acct = db_accounts(client)[0]
    assert acct["state"] == "disabled" and acct["monitoring_enabled"] is False
    assert client.post("/api/accounts/folder:default/sync", headers=H).status_code == 409  # off: nothing to sync
    assert client.post("/api/accounts/folder:default/monitoring", json={"enabled": "yes"}, headers=H).status_code == 400
    assert client.post("/api/accounts/folder:default/monitoring", json={"enabled": True}, headers=H).status_code == 200
    assert client.post("/api/accounts/folder:default/sync", headers=H).json()["requested"] is True
    assert client.post("/api/accounts/folder:default/disconnect", json={}, headers=H).status_code == 400  # confirmation required
    d = client.post("/api/accounts/folder:default/disconnect", json={"confirm": True}, headers=H).json()
    assert d["disconnected"] is True
    assert db_accounts(client)[0]["status"] == "disconnected"
    assert client.post("/api/accounts/folder:default/monitoring", json={"enabled": True}, headers=H).status_code == 409  # must reconnect first
    assert client.post("/api/accounts/nope/monitoring", json={"enabled": True}, headers=H).status_code == 404
    actions = [a["action"] for a in client.get("/api/audit", headers=H).json()]
    assert {"monitoring_enabled", "manual_sync_requested", "account_disconnected"} <= set(actions)


def test_jobs_alerts_retry_and_rescan_endpoints(client):
    from emailshield import db
    up(client)
    assert client.get("/api/alerts", headers=H).json()["counts"]["high"] == 1
    db.enqueue_job("fake", "m", "a")
    j = db.claim_jobs("fake", "a", "w")[0]
    db.dead_letter(j["id"], "w", "network", "boom")
    assert client.get("/api/jobs?state=failed", headers=H).json()[0]["error_category"] == "network"
    assert client.get("/api/jobs?state=bogus", headers=H).status_code == 400
    assert client.post("/api/jobs/retry", json={"ids": "all"}, headers=H).status_code == 400
    assert client.post("/api/jobs/retry", json={"ids": [j["id"]]}, headers=H).json()["retried"] == [j["id"]]
    assert client.post("/api/rescan", json={}, headers=H).status_code == 400
    assert client.post("/api/rescan", json={"confirm": True}, headers=H).json()["queued"] == 0  # uploads have no mailbox id to re-fetch


def test_autostart_endpoint_refuses_off_windows(client, monkeypatch):
    from emailshield import autostart
    monkeypatch.setattr(autostart, "supported", lambda: False)
    assert client.get("/api/autostart", headers=H).json() == {"supported": False, "enabled": False}
    assert client.put("/api/autostart", json={"enabled": True}, headers=H).status_code == 409


def test_monitoring_settings_are_validated(client):
    assert client.put("/api/settings/monitoring", json={"poll_seconds": 1}, headers=H).status_code == 400
    assert client.put("/api/settings/monitoring", json={"batch_size": 5}, headers=H).json()["monitoring"]["batch_size"] == 5


ADV_ROUTES = (("get", "/api/health/detail"), ("get", "/api/engine"), ("post", "/api/engine/stop"), ("get", "/api/backups"), ("post", "/api/backups"),
              ("post", "/api/exports/retry"), ("patch", "/api/alerts/1"), ("post", "/api/accounts/folder:default/validate"))


def test_advanced_routes_require_the_key(client):
    from emailshield import app as appmod
    for method, path in ADV_ROUTES:
        appmod._fails.clear()
        assert getattr(client, method)(path).status_code == 401, path


def test_engine_info_and_stop_needs_explicit_confirmation(client):
    info = client.get("/api/engine", headers=H).json()
    assert info["version"] and "does not stop monitoring" in info["note"]
    assert client.post("/api/engine/stop", json={}, headers=H).status_code == 400  # never stops without confirm:true
    assert client.post("/api/engine/stop", content=b"[1]", headers=H).status_code == 400


def test_health_detail_reports_checks(client):
    h = client.get("/api/health/detail", headers=H).json()
    assert h["overall"] in ("ok", "warn", "fail") and {c["name"] for c in h["checks"]} >= {"Database integrity", "Free disk space", "Secret storage"}


def test_alert_filters_and_status_changes_are_audited(client):
    up(client)
    a = client.get("/api/alerts", headers=H).json()["alerts"][0]
    assert client.get("/api/alerts?severity=bogus", headers=H).status_code == 400
    assert client.patch(f"/api/alerts/{a['id']}", json={"status": "acknowledged"}, headers=H).json()["previous"] == "open"
    assert client.get("/api/alerts?status=acknowledged", headers=H).json()["alerts"][0]["id"] == a["id"]
    assert client.patch(f"/api/alerts/{a['id']}", json={"status": "deleted"}, headers=H).status_code == 400
    assert client.patch("/api/alerts/99999", json={"status": "closed"}, headers=H).status_code == 404
    assert any(x["action"] == "alert_status_changed" for x in client.get("/api/audit", headers=H).json())


def test_account_scoping_and_cross_account_correlation_is_audited(client):
    mid = up(client, "05_campaign_a").json()["id"]
    up(client, "06_campaign_b")
    assert len(client.get("/api/messages?account=", headers=H).json()) == 2  # both are uploads (no mailbox)
    assert client.get("/api/messages?account=gmail:nobody", headers=H).json() == []
    assert client.get(f"/api/messages/{mid}/related", headers=H).json()["scope"] == "same mailbox only"
    assert client.get(f"/api/messages/{mid}/related?cross_account=true", headers=H).json()["scope"] == "all mailboxes"
    assert any(x["action"] == "cross_account_correlation" for x in client.get("/api/audit", headers=H).json())


def test_backups_can_be_created_listed_and_are_audited(client):
    r = client.post("/api/backups", headers=H).json()
    assert r["file"].endswith(".db") and len(r["sha256"]) == 64
    b = client.get("/api/backups", headers=H).json()
    assert b["backups"][0]["file"] == r["file"] and "not encrypted" in b["note"]
    assert any(x["action"] == "backup_created" for x in client.get("/api/audit", headers=H).json())


def test_oauth_callback_explains_google_errors_without_reflecting_input(client):
    r = client.get("/oauth/gmail/callback?error=access_denied&error_description=<script>alert(1)</script>")
    assert r.status_code == 400 and "Test users" in r.text and "<script>alert" not in r.text
    audit = str(client.get("/api/audit", headers=H).json())
    assert "access_denied" in audit and "alert(1)" not in audit


def test_validate_endpoint_for_folder_mailbox_and_unknown_account(client, tmp_path):
    client.post("/api/connectors/folder", json={"path": str(tmp_path / "in")}, headers=H)
    assert client.post("/api/accounts/folder:default/validate", headers=H).json()["ok"] is True
    assert client.post("/api/accounts/nope/validate", headers=H).status_code == 404


def test_privacy_and_backup_settings_are_validated(client):
    assert client.put("/api/settings/privacy", json={"store_body_chars": 999999}, headers=H).status_code == 400
    assert client.put("/api/settings/privacy", json={"retention_days": 30}, headers=H).json()["privacy"]["retention_days"] == 30
    assert client.put("/api/settings/backup", json={"keep": 0}, headers=H).status_code == 400


def test_advanced_routes_reject_a_wrong_key_too(client):
    from emailshield import app as appmod
    for method, path in ADV_ROUTES:
        appmod._fails.clear()
        assert getattr(client, method)(path, headers={"X-API-Key": "definitely-wrong"}).status_code == 401, path


def test_health_detail_and_backups(client):
    h = client.get("/api/health/detail", headers=H).json()
    assert h["overall"] in ("ok", "warn", "fail") and any(c["name"] == "Database integrity" for c in h["checks"])
    b = client.post("/api/backups", headers=H).json()
    assert len(b["sha256"]) == 64 and client.get("/api/backups", headers=H).json()["backups"][0]["file"] == b["file"]
    assert "not encrypted" in client.get("/api/backups", headers=H).json()["note"]
    assert any(a["action"] == "backup_created" for a in client.get("/api/audit", headers=H).json())


def test_engine_stop_needs_explicit_confirmation(client):
    assert client.post("/api/engine/stop", json={}, headers=H).status_code == 400
    assert client.get("/api/engine", headers=H).json()["version"]


def test_alert_filters_and_status_changes_are_validated_and_audited(client):
    r = up(client).json()
    aid = r["alert_id"]
    assert client.get("/api/alerts?severity=bogus", headers=H).status_code == 400
    assert len(client.get("/api/alerts?severity=high&status=open", headers=H).json()["alerts"]) == 1
    assert client.patch(f"/api/alerts/{aid}", json={"status": "nope"}, headers=H).status_code == 400
    assert client.patch(f"/api/alerts/{aid}", json={"status": "acknowledged"}, headers=H).json()["previous"] == "open"
    assert client.patch("/api/alerts/9999", json={"status": "closed"}, headers=H).status_code == 404
    assert client.get("/api/alerts?status=open", headers=H).json()["alerts"] == []
    assert any(a["action"] == "alert_status_changed" for a in client.get("/api/audit", headers=H).json())


def test_cross_mailbox_correlation_is_off_by_default_and_audited_when_used(client):
    a = up(client, "05_campaign_a").json()["id"]
    up(client, "06_campaign_b", "b.eml")
    assert client.get(f"/api/messages/{a}/related", headers=H).json()["scope"] == "same mailbox only"
    assert client.get(f"/api/messages/{a}/related?cross_account=true", headers=H).json()["scope"] == "all mailboxes"
    assert any(x["action"] == "cross_account_correlation" for x in client.get("/api/audit", headers=H).json())


def test_oauth_callback_explains_google_errors_without_echoing_the_description(client):
    r = client.get("/oauth/gmail/callback?error=access_denied&error_description=%3Cscript%3Ealert(1)%3C/script%3E")
    assert r.status_code == 400 and "Test users" in r.text and "<script>alert" not in r.text
    assert any(a["action"] == "gmail_authorization_error" and a["detail"] == "access_denied" for a in client.get("/api/audit", headers=H).json())


def test_account_filter_on_messages(client):
    up(client)
    assert len(client.get("/api/messages?account=", headers=H).json()) == 1  # uploads have no mailbox
    assert client.get("/api/messages?account=gmail:nobody", headers=H).json() == []


def test_both_health_endpoints_work(client):
    """Regression: /api/health/detail returned HTTP 500 (AttributeError) because a route function named health() shadowed the health module."""
    from emailshield import app as appmod
    r = client.get("/api/health")  # preserved: public liveness probe, unchanged response
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    appmod._fails.clear()
    assert client.get("/api/health/detail").status_code == 401  # detail needs the key
    assert client.get("/api/health/detail", headers={"X-API-Key": "wrong"}).status_code == 401
    d = client.get("/api/health/detail", headers=H)
    assert d.status_code == 200
    body = d.json()
    assert body["overall"] in ("ok", "warn", "fail") and len(body["checks"]) >= 8
    assert all({"name", "status", "detail"} <= set(c) and c["status"] in ("ok", "warn", "fail") for c in body["checks"])
    assert {c["name"] for c in body["checks"]} >= {"Database integrity", "Database schema", "Free disk space", "Secret storage", "Monitoring worker"}
    assert body["overall"] != "fail" or any(c["status"] == "fail" for c in body["checks"])  # overall is derived from the checks, not invented


def test_health_detail_does_not_expose_secrets_or_modify_data(client):
    up(client)
    before = client.get("/api/stats", headers=H).json()
    text = client.get("/api/health/detail", headers=H).text
    assert "api_key" not in text.lower() and "refresh_token" not in text.lower()
    assert client.get("/api/stats", headers=H).json() == before  # read-only: no schema change, no data touched
