import json
import sqlite3

from emailshield import config, db, migrations


def old_db(path):
    """A database exactly as EmailShield 2.1 created it (schema v1) with real-looking history in it."""
    c = sqlite3.connect(path)
    for stmt in migrations.V1.split(";"):
        if stmt.strip():
            c.execute(stmt)
    blob = json.dumps({"parsed": {"subject": "old"}, "analysis": {"score": 40}})
    c.execute("INSERT INTO messages(raw_sha256,filename,source,subject,sender,analyzed_at,score,category,analysis_json,notes) VALUES('h1','a.eml','upload','Old one','a@x.example','2026-01-01T00:00:00+00:00',40,'Suspicious',?,'keep my notes')", (blob,))
    c.execute("INSERT INTO messages(raw_sha256,filename,source,subject,sender,analyzed_at,score,category,analysis_json) VALUES('h2','b.eml','gmail','Two','b@x.example','2026-01-02T00:00:00+00:00',0,'Low risk',?)", (blob,))
    c.execute("INSERT INTO case_events(message_id,ts,actor,action,detail) VALUES(1,'t','a','created','x')")
    for ref, status, att in (("q", "queued", 0), ("d", "done", 1), ("f", "failed", 5), ("p", "processing", 1)):
        c.execute("INSERT INTO jobs(provider,external_id,status,attempts,last_error,created_at,updated_at) VALUES('gmail',?,?,?,?,'2026-01-01T00:00:00+00:00','2026-01-01T01:00:00+00:00')", (ref, status, att, "boom" if status == "failed" else None))
    c.commit()
    c.close()


def test_upgrade_preserves_history_and_maps_job_states(tmp_path, monkeypatch):
    p = tmp_path / "old.db"
    old_db(p)
    monkeypatch.setattr(config, "DB_PATH", p)
    db.init()
    msgs = {m["id"]: m for m in db.list_messages()}
    assert len(msgs) == 2 and db.get_message(1)["notes"] == "keep my notes" and db.get_message(1)["history"][0]["action"] == "created"
    states = {j["external_id"]: j for j in db.list_jobs()}
    assert states["q"]["state"] == "pending" and states["d"]["state"] == "completed" and states["d"]["completed_at"]
    assert states["f"]["state"] == "failed" and states["f"]["dead_lettered_at"] and states["f"]["attempts"] == 5 and states["f"]["last_error"] == "boom"
    assert states["p"]["state"] == "processing"
    c = sqlite3.connect(p)
    assert json.loads(c.execute("SELECT value FROM kv WHERE key='schema_version'").fetchone()[0]) == migrations.LATEST
    for t in ("accounts", "alerts", "exports"):
        c.execute(f"SELECT COUNT(*) FROM {t}")


def test_migration_is_idempotent_and_new_columns_work(tmp_path, monkeypatch):
    p = tmp_path / "old.db"
    old_db(p)
    monkeypatch.setattr(config, "DB_PATH", p)
    db.init()
    db._ready.discard(str(p))
    db.init()  # second start: nothing happens, nothing breaks
    c = sqlite3.connect(p)
    migrations.apply(c)
    assert c.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 2
    assert db.enqueue_job("gmail", "new", "acct") and not db.enqueue_job("gmail", "new", "acct")


def test_fresh_database_is_at_latest_version():
    assert migrations.current_version(sqlite3.connect(config.DB_PATH)) == migrations.LATEST
