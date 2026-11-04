import json
import sqlite3
from urllib.parse import parse_qs

import pytest

from emailshield import config, db, migrations, net, providers, secrets_store, ingest
from emailshield.worker import Worker
from tests.conftest import sample
from tests.helpers import FakeGmail, Mailbox


def run_account(aid, messages):
    mb = Mailbox(messages, aid)
    db.upsert_account(aid, "fake", aid, monitoring_enabled=True)
    w = Worker(mb, interval=1, backoff_base=0, deliver_exports=False, account_id=aid)
    w.start()
    w.step()
    return mb


def test_the_same_email_in_two_mailboxes_stays_two_separate_records():
    raw = sample("02_paypal_lookalike")
    run_account("acct:A", {"a1": raw})
    run_account("acct:B", {"b1": raw})
    a, b = db.list_messages(account_id="acct:A"), db.list_messages(account_id="acct:B")
    assert len(a) == 1 and len(b) == 1 and a[0]["id"] != b[0]["id"]
    assert db.get_message(a[0]["id"])["external_id"] == "a1" and db.get_message(b[0]["id"])["external_id"] == "b1"
    assert len(db.list_alerts(account_id="acct:A")) == 1 and len(db.list_alerts(account_id="acct:B")) == 1
    assert {j["account_id"] for j in db.list_jobs(account_id="acct:A")} == {"acct:A"}


def test_dedupe_still_works_inside_one_mailbox():
    raw = sample("02_paypal_lookalike")
    run_account("acct:A", {"a1": raw, "a2": raw})
    assert len(db.list_messages(account_id="acct:A")) == 1 and db.job_counts("acct:A")["completed"] == 2


def test_related_messages_do_not_cross_mailboxes_unless_asked():
    run_account("acct:A", {"a1": sample("05_campaign_a")})
    run_account("acct:B", {"b1": sample("06_campaign_b")})
    a = db.list_messages(account_id="acct:A")[0]["id"]
    assert db.find_related(a)["related"] == [] and db.find_related(a)["scope"] == "same mailbox only"
    wide = db.find_related(a, cross_account=True)
    assert len(wide["related"]) == 1 and wide["scope"] == "all mailboxes" and wide["related"][0]["account_id"] == "acct:B"


def test_queue_claims_never_cross_accounts():
    db.enqueue_job("fake", "x", "acct:A")
    db.enqueue_job("fake", "y", "acct:B")
    got = db.claim_jobs("fake", "acct:A", "w")
    assert [j["external_id"] for j in got] == ["x"] and db.claim_jobs("fake", "acct:A", "w") == []
    assert [j["external_id"] for j in db.claim_jobs("fake", "acct:B", "w2")] == ["y"]


def test_one_failing_account_does_not_stop_another():
    from emailshield import net as n
    bad = Mailbox({"b1": sample("01_benign_newsletter")}, "acct:bad")
    bad.fetch_errors["b1"] = [n.AuthError("revoked")]
    good = Mailbox({"g1": sample("02_paypal_lookalike")}, "acct:good")
    for mb in (bad, good):
        db.upsert_account(mb.account_id, "fake", mb.account_id, monitoring_enabled=True)
    wb = Worker(bad, interval=1, backoff_base=0, deliver_exports=False, account_id="acct:bad"); wb.start()
    wg = Worker(good, interval=1, backoff_base=0, deliver_exports=False, account_id="acct:good"); wg.start()
    wb.step(); wg.step()
    assert db.get_account("acct:bad")["status"] == "auth_required"
    assert db.get_account("acct:good")["status"] == "connected" and db.job_counts("acct:good")["completed"] == 1


def test_each_mailbox_uses_only_its_own_stored_credentials():
    secrets_store.set("gmail_client_id", "cid"); secrets_store.set("gmail_client_secret", "csec-secret-123")
    secrets_store.set("gmail_refresh_token:gmail:a@example.org", "1//token-for-account-A-abcdefghijkl")
    secrets_store.set("gmail_refresh_token:gmail:b@example.org", "1//token-for-account-B-abcdefghijkl")
    used = []

    def http(method, url, headers=None, body=None, timeout=10, **kw):
        if "oauth2.googleapis.com/token" in url:
            used.append(parse_qs(body.decode())["refresh_token"][0])
            return 200, {}, json.dumps({"access_token": "ya29.x", "expires_in": 3600}).encode()
        return 200, {}, json.dumps({"emailAddress": "x", "historyId": "1"}).encode()
    providers.GmailProvider(http=http, account_id="gmail:a@example.org").validate()
    providers.GmailProvider(http=http, account_id="gmail:b@example.org").validate()
    assert used == ["1//token-for-account-A-abcdefghijkl", "1//token-for-account-B-abcdefghijkl"]
    providers.GmailProvider(http=FakeGmail(), account_id="gmail:a@example.org").disconnect()
    assert not secrets_store.has("gmail_refresh_token:gmail:a@example.org") and secrets_store.has("gmail_refresh_token:gmail:b@example.org")


# ---------------- migration v3 ----------------
def v2_database(path):
    c = sqlite3.connect(path)
    for stmt in migrations.V1.split(";"):
        if stmt.strip():
            c.execute(stmt)
    for stmt in migrations.V2:
        c.execute(stmt)
    c.execute("INSERT INTO kv VALUES('schema_version','2')")
    blob = json.dumps({"parsed": {"subject": "s"}, "analysis": {"score": 40, "findings": []}})
    for i, acct in enumerate((None, "gmail:a@example.org")):
        c.execute("INSERT INTO messages(raw_sha256,filename,source,subject,sender,analyzed_at,score,category,analysis_json,account_id,external_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                  (f"hash{i}", "f.eml", "gmail", f"subject {i}", "x@y.example", "2026-01-01T00:00:00+00:00", 40, "Suspicious", blob, acct, f"ext{i}"))
        c.execute("INSERT INTO indicators VALUES(?,?,?)", (i + 1, "url_domain", "evil.example"))
        c.execute("INSERT INTO case_events(message_id,ts,actor,action,detail) VALUES(?,?,?,?,?)", (i + 1, "t", "a", "created", "x"))
        c.execute("INSERT INTO alerts(message_id,severity,score,title,created_at,updated_at) VALUES(?,?,?,?,?,?)", (i + 1, "medium", 40, "t", "t", "t"))
    c.commit()
    c.close()


def test_v3_upgrade_keeps_ids_links_and_creates_a_verified_backup(tmp_path, monkeypatch):
    p = tmp_path / "v2.db"
    v2_database(p)
    monkeypatch.setattr(config, "DB_PATH", p)
    db.init()
    c = sqlite3.connect(p)
    assert json.loads(c.execute("SELECT value FROM kv WHERE key='schema_version'").fetchone()[0]) == migrations.LATEST
    assert c.execute("SELECT id, account_id FROM messages ORDER BY id").fetchall() == [(1, ""), (2, "gmail:a@example.org")]  # ids kept, NULL -> ''
    assert c.execute("SELECT COUNT(*) FROM indicators").fetchone()[0] == 2 and c.execute("SELECT COUNT(*) FROM case_events").fetchone()[0] == 2
    assert c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 2 and c.execute("PRAGMA foreign_key_check").fetchall() == []
    backups = list(tmp_path.glob("v2.db.pre-migration-v2-*.bak"))
    assert len(backups) == 1 and sqlite3.connect(backups[0]).execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 2
    c.execute("INSERT INTO messages(raw_sha256,account_id) VALUES('hash0','gmail:b@example.org')")  # same hash, other mailbox: now allowed
    with pytest.raises(sqlite3.IntegrityError):
        c.execute("INSERT INTO messages(raw_sha256,account_id) VALUES('hash0','')")  # same hash, same mailbox: still unique


def test_deleting_the_old_table_does_not_cascade_away_child_rows(tmp_path, monkeypatch):
    p = tmp_path / "v2.db"
    v2_database(p)
    monkeypatch.setattr(config, "DB_PATH", p)
    db.init()
    assert db.get_message(1)["history"] and db.get_message(2)["history"] and len(db.list_alerts()) == 2


def test_failed_migration_leaves_the_original_database_intact(tmp_path, monkeypatch):
    p = tmp_path / "v2.db"
    v2_database(p)
    monkeypatch.setattr(config, "DB_PATH", p)
    monkeypatch.setitem(migrations.MIGRATIONS, 3, migrations.V3[:2] + ["THIS IS NOT SQL"])
    with pytest.raises(sqlite3.Error):
        db.init()
    c = sqlite3.connect(p)
    assert json.loads(c.execute("SELECT value FROM kv WHERE key='schema_version'").fetchone()[0]) == 2  # rolled back, still version 2
    assert c.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 2 and c.execute("SELECT name FROM sqlite_master WHERE name='messages_v3'").fetchone() is None
    assert len(list(tmp_path.glob("*.bak"))) == 1  # and a backup was taken before the attempt


def test_fresh_database_creates_no_backup(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "new.db")
    db.init()
    assert list(tmp_path.glob("*.bak")) == []
