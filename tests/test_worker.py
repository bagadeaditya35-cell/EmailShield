import json
import threading

from emailshield import config, db, net, providers
from emailshield.worker import Worker
from tests.conftest import sample


class Scripted:
    """Fake provider: scripted failures, then success."""
    name = "fake"

    def __init__(self, refs=("a",), list_error=None, fetch_errors=(), payload=None):
        self.refs, self.list_error, self.fetch_errors, self.payload = list(refs), list_error, list(fetch_errors), payload
        self.fetches = 0

    def describe(self):
        return {"provider": self.name}

    def list_new(self):
        if self.list_error:
            raise self.list_error
        return self.refs

    def fetch_raw(self, ref):
        self.fetches += 1
        if self.fetch_errors:
            raise self.fetch_errors.pop(0)
        return self.payload if self.payload is not None else sample("01_benign_newsletter")


def worker(p, **kw):
    w = Worker(p, interval=1, backoff_base=0, **kw)
    w.start()
    return w


def test_folder_provider_end_to_end_and_dedupe(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    for n in ("01_benign_newsletter", "02_paypal_lookalike"):
        (inbox / f"{n}.eml").write_bytes(sample(n))
    w = worker(providers.FolderProvider(inbox))
    assert w.step()["processed"] == 2 and db.stats()["total"] == 2
    again = w.step()
    assert again["processed"] == 0 and db.job_counts()["completed"] == 2
    (inbox / "copy.eml").write_bytes(sample("01_benign_newsletter"))  # same content, new file
    w.step()
    assert db.stats()["total"] == 2


def test_transient_failures_are_retried_then_succeed():
    p = Scripted(fetch_errors=[net.ConnectionProblem("x"), net.ConnectionProblem("y")])
    w = worker(p)
    for _ in range(4):
        w.step()
    assert db.job_counts()["completed"] == 1 and db.stats()["total"] == 1 and p.fetches == 3


def test_job_fails_permanently_after_max_attempts():
    w = worker(Scripted(fetch_errors=[net.ConnectionProblem("x")] * 10), max_attempts=2)
    for _ in range(4):
        w.step()
    c = db.job_counts()
    assert c["failed"] == 1 and c["pending"] == 0 and c["retry_scheduled"] == 0
    assert any(e["type"] == "error" for e in db.list_events())


def test_unparseable_message_fails_without_retry_loop():
    p = Scripted(payload=b"   ")
    w = worker(p)
    w.step()
    w.step()
    assert db.job_counts()["failed"] == 1 and p.fetches == 1


def test_restart_recovery_requeues_stuck_jobs():
    db.enqueue_job("fake", "a", "fake")
    job = db.claim_jobs("fake", "fake", "crashed-worker", lease_seconds=-1)[0]  # claimed, then the worker "died": lease already expired
    assert job["state"] == "processing"
    w = Worker(Scripted(), interval=1, backoff_base=0)
    w.start()
    assert db.monitoring()["worker"]["recovered_jobs"] == 1
    assert w.step()["processed"] == 1


def test_provider_errors_set_visible_status_and_never_crash():
    for n, (exc, state) in enumerate(((net.AuthError("revoked"), "auth_error"), (net.ConnectionProblem("down"), "disconnected"), (net.RateLimited(0), "rate_limited"))):
        w = worker(Scripted(list_error=exc), account_id=f"fake{n}")  # separate accounts: a revoked account stays paused by design
        w.step()
        mon = db.monitoring()["worker"]
        assert mon["state"] == state and mon["last_error"]


def test_health_reporting_and_last_sync():
    assert db.monitoring()["health"] == "not_running"
    w = worker(Scripted())
    w.step()
    m = db.monitoring()
    assert m["health"] == "healthy" and m["worker"]["last_sync"] and m["jobs"]["completed"] == 1


def test_graceful_shutdown():
    w = Worker(Scripted(), interval=1, backoff_base=0)
    t = threading.Thread(target=w.run)
    t.start()
    w.stop_event.set()
    t.join(timeout=10)
    assert not t.is_alive() and db.monitoring()["worker"]["state"] == "stopped" and db.monitoring()["health"] == "stopped"


def test_folder_provider_rejects_path_traversal(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        providers.FolderProvider(tmp_path).fetch_raw("../secret|1")


# ---------- Gmail provider against a fake HTTP layer ----------
class FakeGmail:
    def __init__(self, raw, script=()):
        self.raw, self.script, self.calls = raw, list(script), []

    def __call__(self, method, url, headers=None, body=None, timeout=10):
        self.calls.append(url)
        if self.script:
            r = self.script.pop(0)
            if r is not None:
                return r
        if "oauth2.googleapis.com" in url:
            return 200, {}, json.dumps({"access_token": "AT", "expires_in": 3600}).encode()
        if "/messages?" in url and "pageToken" not in url:
            return 200, {}, json.dumps({"messages": [{"id": "m1"}], "nextPageToken": "p2"}).encode()
        if "pageToken=p2" in url:
            return 200, {}, json.dumps({"messages": [{"id": "m2"}]}).encode()
        import base64
        return 200, {}, json.dumps({"raw": base64.urlsafe_b64encode(self.raw).decode().rstrip("=")}).encode()


def gmail(tmp_path, http):
    (tmp_path / "client_secret.json").write_text(json.dumps({"installed": {"client_id": "cid", "client_secret": "cs"}}))
    (tmp_path / "gmail_token.json").write_text(json.dumps({"refresh_token": "rt"}))
    return providers.GmailProvider(http=http, client_file=tmp_path / "client_secret.json", token_file=tmp_path / "gmail_token.json")


def test_gmail_lists_pages_and_fetches_raw(tmp_path):
    raw = sample("02_paypal_lookalike")
    g = gmail(tmp_path, FakeGmail(raw))
    assert g.list_new() == ["m1", "m2"] and g.fetch_raw("m1") == raw
    assert g.describe()["scope"].endswith("gmail.readonly")


def test_gmail_end_to_end_through_worker(tmp_path):
    w = worker(gmail(tmp_path, FakeGmail(sample("02_paypal_lookalike"))))
    w.step()
    assert db.stats()["total"] == 1 and db.stats()["high"] == 1 and db.job_counts()["completed"] == 2


def test_gmail_refreshes_token_after_401(tmp_path):
    g = gmail(tmp_path, FakeGmail(b"x", script=[None, (401, {}, b"{}")]))
    assert g.list_new() == ["m1", "m2"]


def test_gmail_error_mapping(tmp_path):
    import pytest
    with pytest.raises(net.RateLimited):
        gmail(tmp_path, FakeGmail(b"x", script=[None, (429, {"retry-after": "7"}, b"")])).list_new()
    with pytest.raises(net.RateLimited):
        gmail(tmp_path, FakeGmail(b"x", script=[None, (403, {}, b"userRateLimitExceeded")])).list_new()
    with pytest.raises(net.ConnectionProblem):
        gmail(tmp_path, FakeGmail(b"x", script=[None, (503, {}, b"")])).list_new()
    with pytest.raises(net.AuthError):
        gmail(tmp_path, FakeGmail(b"x", script=[(400, {}, b"invalid_grant")])).list_new()


def test_gmail_not_configured_is_auth_error(tmp_path):
    import pytest
    with pytest.raises(net.AuthError):
        providers.GmailProvider(http=FakeGmail(b""), client_file=tmp_path / "no.json", token_file=tmp_path / "no2.json").list_new()
