from emailshield import db, secrets_store, uninstall
from tests.helpers import FakeGmail


def test_forget_all_revokes_every_gmail_account_and_removes_all_secrets():
    for aid in ("gmail:a@example.org", "gmail:b@example.org"):
        db.upsert_account(aid, "gmail", aid)
        secrets_store.set(f"gmail_refresh_token:{aid}", "1//refresh-token-abcdefghijklmnop")
    db.upsert_account("folder:default", "folder", "demo")
    for n in uninstall.SECRET_NAMES:
        secrets_store.set(n, "some-secret-value-123")
    srv = FakeGmail()
    out = uninstall.forget_all(http=srv)
    assert len(out) == 2 and all(r["revoked_at_google"] and r["local_token_removed"] for r in out) and len(srv.revoked) == 2
    assert not any(secrets_store.has(n) for n in uninstall.SECRET_NAMES)
    assert not secrets_store.has("gmail_refresh_token:gmail:a@example.org") and not secrets_store.has("gmail_refresh_token:gmail:b@example.org")


def test_forget_all_removes_local_secrets_even_when_google_is_unreachable():
    from emailshield import net
    db.upsert_account("gmail:a@example.org", "gmail", "a")
    secrets_store.set("gmail_refresh_token:gmail:a@example.org", "1//refresh-token-abcdefghijklmnop")
    secrets_store.set("gmail_client_secret", "csecret-value-123")

    def offline(*a, **k):
        raise net.ConnectionProblem("offline")
    out = uninstall.forget_all(http=offline)
    assert out[0]["revoked_at_google"] is False  # honest: revocation could not be confirmed
    assert not secrets_store.has("gmail_refresh_token:gmail:a@example.org") and not secrets_store.has("gmail_client_secret")


def test_forget_all_works_with_no_database_and_no_accounts():
    assert uninstall.forget_all(http=FakeGmail()) == []
