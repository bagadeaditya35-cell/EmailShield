import base64
import json
import os
import sqlite3
import sys

import pytest

from emailshield import backup, config, db, ingest, migrations, oauth_gmail, secrets_store, server, settings
from emailshield.worker import MonitorService
from tests.conftest import sample
from tests.helpers import Mailbox


def fake_dpapi():
    """Reversible stand-in for Windows DPAPI (real DPAPI is untested outside Windows)."""
    return (lambda b: b"PROT" + base64.b64encode(b[::-1]), lambda b: base64.b64decode(b[4:])[::-1])


# ---------------- secrets ----------------
def test_secrets_are_encrypted_in_the_file_when_os_protection_exists(monkeypatch):
    monkeypatch.setattr(secrets_store, "_get_protector", fake_dpapi)
    secrets_store.set("api", "very-secret-value-123")
    raw = (config.DATA_DIR / "secrets.json").read_text()
    assert "very-secret-value-123" not in raw and "dpapi1:" in raw
    assert secrets_store.get("api") == "very-secret-value-123" and secrets_store.has("api")
    assert "DPAPI" in secrets_store.backend()


def test_protected_secret_is_unreadable_without_the_protector_instead_of_crashing(monkeypatch):
    monkeypatch.setattr(secrets_store, "_get_protector", fake_dpapi)
    secrets_store.set("api", "very-secret-value-123")
    monkeypatch.setattr(secrets_store, "_get_protector", lambda: None)  # e.g. file copied to another machine/user
    assert secrets_store.get("api") == "" and not secrets_store.has("api")


def test_legacy_plain_values_remain_readable_and_environment_wins(monkeypatch):
    (config.DATA_DIR / "secrets.json").write_text(json.dumps({"old": "plain-legacy-value"}))
    monkeypatch.setattr(secrets_store, "_get_protector", fake_dpapi)
    assert secrets_store.get("old") == "plain-legacy-value"
    monkeypatch.setenv("OLD", "from-env")
    assert secrets_store.get("old") == "from-env"


def test_secret_deletion_removes_the_stored_value(monkeypatch):
    monkeypatch.setattr(secrets_store, "_get_protector", fake_dpapi)
    secrets_store.set("tmp", "abcdef123456")
    secrets_store.delete("tmp")
    assert not secrets_store.has("tmp") and "tmp" not in (config.DATA_DIR / "secrets.json").read_text()


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX permission bits")
def test_data_folder_and_sensitive_files_are_owner_only():
    secrets_store.set("x", "abcdef123456")
    db.init()
    backup.create()
    from emailshield import paths
    paths.harden_data_dir(config.DATA_DIR)
    mode = lambda p: oct(os.stat(p).st_mode & 0o777)  # noqa: E731
    assert mode(config.DATA_DIR) == "0o700" and mode(config.DB_PATH) == "0o600" and mode(config.DATA_DIR / "secrets.json") == "0o600"
    assert all(mode(f) == "0o600" for f in (config.DATA_DIR / "backups").glob("*"))


# ---------------- backup / restore ----------------
def test_backup_is_consistent_verified_and_checksummed():
    ingest.ingest_bytes(sample("02_paypal_lookalike"), "a.eml")
    r = backup.create()
    p = __import__("pathlib").Path(r["file"])
    assert p.exists() and len(r["sha256"]) == 64 and p.with_suffix(".db.sha256").exists()
    assert backup.verify(p) == (True, "ok")
    assert sqlite3.connect(p).execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 1


def test_tampered_or_foreign_files_fail_verification(tmp_path):
    r = backup.create()
    p = __import__("pathlib").Path(r["file"])
    data = bytearray(p.read_bytes())
    data[-50:] = b"X" * 50
    p.write_bytes(bytes(data))
    ok, why = backup.verify(p)
    assert not ok and ("SHA-256" in why or "integrity" in why or "Error" in why)
    other = tmp_path / "other.db"
    sqlite3.connect(other).execute("CREATE TABLE t(x)").connection.commit()
    assert backup.verify(other) == (False, "not an EmailShield database")
    (tmp_path / "junk.db").write_bytes(b"not a database at all" * 50)
    assert backup.verify(tmp_path / "junk.db")[0] is False


def test_backup_from_a_newer_version_is_refused(tmp_path):
    p = tmp_path / "future.db"
    c = sqlite3.connect(p)
    for s in migrations.V1.split(";"):
        if s.strip():
            c.execute(s)
    c.execute("INSERT INTO kv VALUES('schema_version', ?)", (str(migrations.LATEST + 1),))
    c.commit()
    c.close()
    ok, why = backup.verify(p)
    assert not ok and "newer" in why


def test_old_backups_are_pruned_to_the_configured_count(monkeypatch):
    import itertools
    ticks = itertools.count()
    monkeypatch.setattr(backup, "datetime", type("D", (), {"now": staticmethod(lambda tz=None: __import__("datetime").datetime(2026, 1, 1, 0, 0, next(ticks), tzinfo=tz))}))
    for _ in range(5):
        backup.create(keep=3)
    assert len(list(backup.backup_dir().glob("emailshield-*.db"))) == 3 and len(list(backup.backup_dir().glob("*.sha256"))) == 3


def test_restore_replaces_the_database_and_keeps_the_previous_one():
    ingest.ingest_bytes(sample("02_paypal_lookalike"), "a.eml")
    good = __import__("pathlib").Path(backup.create()["file"])
    ingest.ingest_bytes(sample("04_invoice_exe"), "b.eml")  # work done after the backup
    assert db.stats()["total"] == 2
    r = backup.restore(good)
    assert db.stats()["total"] == 1  # back to the backed-up state
    aside = __import__("pathlib").Path(r["previous_database_kept_as"])
    assert aside.exists() and sqlite3.connect(aside).execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 2  # nothing destroyed


def test_restore_is_refused_while_the_engine_runs_and_for_bad_backups(monkeypatch, tmp_path):
    good = __import__("pathlib").Path(backup.create()["file"])
    monkeypatch.setattr(server, "engine_info", lambda: {"url": "http://x"})
    with pytest.raises(RuntimeError, match="running"):
        backup.restore(good)
    junk = tmp_path / "bad.db"
    junk.write_bytes(b"x" * 100)
    monkeypatch.setattr(server, "engine_info", lambda: None)
    with pytest.raises(ValueError, match="rejected"):
        backup.restore(junk)


def test_restore_is_refused_when_another_process_holds_the_instance_lock(monkeypatch):
    good = __import__("pathlib").Path(backup.create()["file"])
    monkeypatch.setattr(server, "engine_info", lambda: None)
    held = server.acquire_instance_lock()
    try:
        with pytest.raises(RuntimeError, match="running"):
            backup.restore(good)
    finally:
        held.close()


def test_daily_backup_runs_in_the_service_and_can_be_disabled():
    svc = MonitorService(connector_factory=lambda a: Mailbox({}, a["id"]), interval=1)
    r = svc._maybe_backup(now_ts=10 ** 7, every=3600)
    assert r and len(backup.list_backups()) == 1
    assert svc._maybe_backup(now_ts=10 ** 7 + 100, every=3600) is None  # not due
    settings.update("backup", {"enabled": False})
    assert svc._maybe_backup(now_ts=10 ** 8, every=3600) is None
    with pytest.raises(ValueError):
        settings.update("backup", {"keep": 0})


# ---------------- OAuth error explanations ----------------
def test_google_error_codes_get_plain_language_help():
    t = oauth_gmail.explain_error("access_denied")
    assert "Test users" in t and "verification" in t
    assert "Desktop app" in oauth_gmail.explain_error("invalid_client")
    assert "redirect" in oauth_gmail.explain_error("redirect_uri_mismatch").lower()
    assert "Workspace" in oauth_gmail.explain_error("admin_policy_enforced")


def test_unknown_error_codes_and_descriptions_are_never_echoed_raw():
    out = oauth_gmail.explain_error("<script>alert(1)</script>", "<img src=x onerror=alert(2)>")
    assert "onerror" not in out and out.count("<script>") <= 1  # the (length-capped) code is shown inside quotes only, never the description
    assert len(oauth_gmail.explain_error("x" * 500)) < 400
