import base64
import hashlib
import json
from urllib.parse import parse_qs, urlparse

import pytest

from emailshield import net, oauth_gmail, providers, secrets_store
from tests.conftest import sample
from tests.helpers import FakeGmail


def gmail(http, **kw):
    secrets_store.set("gmail_client_id", "cid.apps.example")
    secrets_store.set("gmail_client_secret", "csecret-value-123")
    secrets_store.set("gmail_refresh_token:gmail:t@example.org", "1//refresh-token-abcdefghijklmnop")
    return providers.GmailProvider(http=http, account_id="gmail:t@example.org", **kw)


def test_first_sync_reads_checkpoint_then_lists_recent_messages():
    srv = FakeGmail({"m1": b"x", "m2": b"y"})
    cs = gmail(srv).discover({})
    assert sorted(cs.refs) == ["m1", "m2"] and cs.initial and cs.reconciled and cs.state["history_id"] == "100"
    # the checkpoint is read BEFORE the listing, so mail arriving during the listing is never skipped
    paths = [u for _, u in srv.calls if "/profile" in u or "/messages?" in u]
    assert paths[0].endswith("/profile")


def test_incremental_sync_uses_history_and_deduplicates_notifications():
    srv = FakeGmail({"m1": b"x", "m2": b"y", "m3": b"z"})
    g = gmail(srv)
    state = g.discover({}).state
    srv.history, srv.history_id = [("101", ["m3"]), ("102", ["m3", "m2"])], "102"  # duplicate change signals
    before = len(srv.calls)
    cs = g.discover(state)
    assert sorted(cs.refs) == ["m2", "m3"] and not cs.initial and not cs.reconciled and cs.state["history_id"] == "102"
    assert not any("/messages?" in u for _, u in srv.calls[before:])  # no listing: cheap incremental call only


def test_discover_does_not_mutate_the_checkpoint_it_is_given():
    srv = FakeGmail({"m1": b"x"})
    g = gmail(srv)
    state = {"history_id": "50", "last_reconcile": g.clock()}
    srv.history, srv.history_id = [("60", ["m1"])], "60"
    g.discover(state)
    assert state["history_id"] == "50"  # advancing is the caller's job, committed together with the jobs


def test_expired_history_triggers_a_full_resync():
    srv = FakeGmail({"m1": b"x", "m9": b"y"})
    srv.history_expired, srv.history_id = True, "900"
    cs = gmail(srv).discover({"history_id": "1", "last_reconcile": 10 ** 12})
    assert cs.reconciled and sorted(cs.refs) == ["m1", "m9"] and cs.state["history_id"] == "900"


def test_periodic_reconciliation_catches_a_missed_notification():
    srv = FakeGmail({"m1": b"x", "missed": b"y"})
    g = gmail(srv, reconcile_seconds=60)
    state = {"history_id": "100", "last_reconcile": g.clock() - 3600}
    cs = g.discover(state)  # history says nothing, but the periodic listing finds the message
    assert "missed" in cs.refs and cs.reconciled and cs.state["last_reconcile"] >= g.clock() - 5


def test_fetch_returns_exact_bytes_and_none_for_deleted_message():
    raw = sample("02_paypal_lookalike")
    g = gmail(FakeGmail({"m1": raw}))
    assert g.fetch_raw("m1") == raw and g.fetch_raw("gone") is None


def test_revoked_authorization_is_an_auth_error():
    srv = FakeGmail()
    srv.token_status = 400
    with pytest.raises(net.AuthError):
        gmail(srv).discover({})


def test_rate_limit_and_server_errors_are_typed():
    srv = FakeGmail({"m": b"x"})
    srv.statuses = [429]
    with pytest.raises(net.RateLimited) as e:
        gmail(srv).discover({})
    assert e.value.retry_after == 7
    srv2 = FakeGmail({"m": b"x"})
    srv2.statuses = [503]
    with pytest.raises(net.ConnectionProblem):
        gmail(srv2).discover({})


def test_not_connected_gives_clear_error_and_never_asks_for_a_password():
    with pytest.raises(net.AuthError) as e:
        providers.GmailProvider(http=FakeGmail(), account_id="gmail:nobody").discover({})
    assert "Connect the mailbox" in str(e.value) and "password" not in str(e.value).lower()


def test_validate_and_scope_is_read_only():
    g = gmail(FakeGmail())
    assert g.validate()["email"] == "test@example.org"
    assert g.describe()["scope"].endswith("gmail.readonly") and providers.GMAIL_SCOPE.endswith("gmail.readonly")


def test_disconnect_revokes_at_google_and_deletes_the_stored_token():
    srv = FakeGmail()
    g = gmail(srv)
    assert secrets_store.has("gmail_refresh_token:gmail:t@example.org")
    assert g.disconnect() == {"revoked": True} and srv.revoked
    assert not secrets_store.has("gmail_refresh_token:gmail:t@example.org")
    with pytest.raises(net.AuthError):
        g.validate()


# ---------------- OAuth (authorization code + PKCE) ----------------
def token_http(status=200, refresh=True):
    seen = {}

    def http(method, url, headers=None, body=None, timeout=10, **kw):
        seen["body"] = parse_qs(body.decode())
        data = {"access_token": "ya29.abc", "expires_in": 3600}
        if refresh:
            data["refresh_token"] = "1//refresh"
        return status, {}, json.dumps(data).encode()
    http.seen = seen
    return http


def test_oauth_url_uses_readonly_scope_pkce_and_state():
    url = oauth_gmail.start("cid", "http://127.0.0.1:8731/oauth/gmail/callback")
    q = parse_qs(urlparse(url).query)
    assert q["scope"] == [providers.GMAIL_SCOPE] and q["code_challenge_method"] == ["S256"] and q["access_type"] == ["offline"]
    assert q["state"][0] and "client_secret" not in url


def test_oauth_finish_verifies_pkce_and_state_is_single_use():
    url = oauth_gmail.start("cid", "http://127.0.0.1:8731/cb")
    q = parse_qs(urlparse(url).query)
    http = token_http()
    tokens = oauth_gmail.finish(q["state"][0], "code123", "cid", "csec", http)
    assert tokens["refresh_token"] == "1//refresh"
    verifier = http.seen["body"]["code_verifier"][0]
    assert base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=") == q["code_challenge"][0]
    with pytest.raises(oauth_gmail.OAuthError):  # replaying the same callback must fail
        oauth_gmail.finish(q["state"][0], "code123", "cid", "csec", http)


def test_oauth_rejects_forged_expired_denied_and_tokenless():
    http = token_http()
    with pytest.raises(oauth_gmail.OAuthError):
        oauth_gmail.finish("forged-state", "code", "cid", "csec", http)
    t = [1000.0]
    q = parse_qs(urlparse(oauth_gmail.start("cid", "http://127.0.0.1/cb", clock=lambda: t[0])).query)
    t[0] += oauth_gmail.STATE_TTL + 1
    with pytest.raises(oauth_gmail.OAuthError):
        oauth_gmail.finish(q["state"][0], "code", "cid", "csec", http, clock=lambda: t[0])
    q2 = parse_qs(urlparse(oauth_gmail.start("cid", "http://127.0.0.1/cb")).query)
    with pytest.raises(oauth_gmail.OAuthError):
        oauth_gmail.finish(q2["state"][0], "", "cid", "csec", http)  # user pressed Cancel
    q3 = parse_qs(urlparse(oauth_gmail.start("cid", "http://127.0.0.1/cb")).query)
    with pytest.raises(oauth_gmail.OAuthError):
        oauth_gmail.finish(q3["state"][0], "code", "cid", "csec", token_http(refresh=False))
