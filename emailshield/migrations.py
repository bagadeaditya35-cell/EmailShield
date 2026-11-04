"""Versioned SQLite migrations. Existing databases are upgraded in place and keep all scan history.
Version 1 = the schema shipped up to EmailShield 2.1. Version 2 = monitoring engine (accounts, leased queue, alerts, export outbox)."""
import json

V1 = """
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT, raw_sha256 TEXT UNIQUE NOT NULL, filename TEXT, source TEXT,
  subject TEXT, sender TEXT, analyzed_at TEXT, score INTEGER, category TEXT,
  status TEXT DEFAULT 'new', notes TEXT DEFAULT '', analysis_json TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS indicators(
  message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE, type TEXT, value TEXT);
CREATE INDEX IF NOT EXISTS idx_ind ON indicators(type, value);
CREATE TABLE IF NOT EXISTS case_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE,
  ts TEXT, actor TEXT, action TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, type TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS jobs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, provider TEXT, external_id TEXT, status TEXT DEFAULT 'queued',
  attempts INTEGER DEFAULT 0, next_attempt_at TEXT, last_error TEXT, created_at TEXT, updated_at TEXT,
  UNIQUE(provider, external_id));
CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS ti_cache(provider TEXT, indicator TEXT, result_json TEXT, fetched_at REAL,
  PRIMARY KEY(provider, indicator));
CREATE TABLE IF NOT EXISTS ti_results(
  message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE, provider TEXT, indicator_type TEXT,
  indicator TEXT, verdict TEXT, detail TEXT, fetched_at TEXT, from_cache INTEGER);
"""

V2 = [
    """CREATE TABLE accounts(
      id TEXT PRIMARY KEY, provider TEXT NOT NULL, display TEXT, status TEXT NOT NULL DEFAULT 'connected',
      monitoring_enabled INTEGER NOT NULL DEFAULT 0, initial_sync_done INTEGER NOT NULL DEFAULT 0,
      sync_state TEXT NOT NULL DEFAULT '{}', config TEXT NOT NULL DEFAULT '{}', created_at TEXT,
      last_sync_at TEXT, last_scan_at TEXT, last_error TEXT, last_error_at TEXT, last_error_category TEXT,
      consecutive_failures INTEGER NOT NULL DEFAULT 0, sync_requested_at TEXT)""",
    """CREATE TABLE alerts(
      id INTEGER PRIMARY KEY AUTOINCREMENT, message_id INTEGER UNIQUE REFERENCES messages(id) ON DELETE CASCADE,
      severity TEXT, score INTEGER, status TEXT NOT NULL DEFAULT 'open', title TEXT, engine_version TEXT,
      created_at TEXT, updated_at TEXT)""",
    """CREATE TABLE exports(
      id INTEGER PRIMARY KEY AUTOINCREMENT, dedupe_key TEXT UNIQUE NOT NULL, alert_id INTEGER, message_id INTEGER,
      event_type TEXT, payload TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
      next_attempt_at TEXT, last_error TEXT, created_at TEXT, sent_at TEXT)""",
    "ALTER TABLE messages ADD COLUMN account_id TEXT",
    "ALTER TABLE messages ADD COLUMN external_id TEXT",
    "ALTER TABLE messages ADD COLUMN engine_version TEXT",
    "ALTER TABLE messages ADD COLUMN ruleset_version TEXT",
    "CREATE INDEX idx_msg_ext ON messages(source, account_id, external_id)",
    """CREATE TABLE jobs_v2(
      id INTEGER PRIMARY KEY AUTOINCREMENT, provider TEXT NOT NULL, account_id TEXT NOT NULL DEFAULT '',
      external_id TEXT NOT NULL, engine_version TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT 'pending',
      attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT, last_attempt_at TEXT, next_attempt_at TEXT,
      completed_at TEXT, error_category TEXT, last_error TEXT, scan_id INTEGER, lease_owner TEXT,
      lease_expires_at TEXT, dead_lettered_at TEXT, updated_at TEXT, in_flight INTEGER NOT NULL DEFAULT 0,
      UNIQUE(provider, account_id, external_id, engine_version))""",
    """INSERT INTO jobs_v2(id, provider, account_id, external_id, engine_version, state, attempts, created_at,
        next_attempt_at, completed_at, last_error, dead_lettered_at, updated_at)
       SELECT id, provider, '', external_id, '',
        CASE status WHEN 'queued' THEN 'pending' WHEN 'done' THEN 'completed' WHEN 'processing' THEN 'processing' ELSE 'failed' END,
        COALESCE(attempts, 0), created_at, COALESCE(next_attempt_at, created_at),
        CASE WHEN status='done' THEN updated_at END, last_error,
        CASE WHEN status='failed' THEN updated_at END, updated_at FROM jobs""",
    "DROP TABLE jobs",
    "ALTER TABLE jobs_v2 RENAME TO jobs",
    "CREATE INDEX idx_jobs_due ON jobs(provider, account_id, state, next_attempt_at)",
]
V3 = [  # messages are unique PER ACCOUNT, so the same email in two mailboxes is two separate records (no cross-account merging)
    """CREATE TABLE messages_v3(
      id INTEGER PRIMARY KEY AUTOINCREMENT, raw_sha256 TEXT NOT NULL, filename TEXT, source TEXT, subject TEXT, sender TEXT,
      analyzed_at TEXT, score INTEGER, category TEXT, status TEXT DEFAULT 'new', notes TEXT DEFAULT '', analysis_json TEXT,
      updated_at TEXT, account_id TEXT NOT NULL DEFAULT '', external_id TEXT, engine_version TEXT, ruleset_version TEXT,
      UNIQUE(account_id, raw_sha256))""",
    """INSERT INTO messages_v3(id, raw_sha256, filename, source, subject, sender, analyzed_at, score, category, status, notes,
        analysis_json, updated_at, account_id, external_id, engine_version, ruleset_version)
       SELECT id, raw_sha256, filename, source, subject, sender, analyzed_at, score, category, status, notes,
        analysis_json, updated_at, COALESCE(account_id, ''), external_id, engine_version, ruleset_version FROM messages""",
    "DROP TABLE messages",
    "ALTER TABLE messages_v3 RENAME TO messages",
    "CREATE INDEX idx_msg_ext ON messages(source, account_id, external_id)",
]
MIGRATIONS = {2: V2, 3: V3}
LATEST = max(MIGRATIONS)


def current_version(c):
    try:
        r = c.execute("SELECT value FROM kv WHERE key='schema_version'").fetchone()
    except Exception:
        return 0  # no kv table at all: brand-new file
    return json.loads(r[0]) if r else 1


def needs_backup(c):
    """True when an EXISTING database with data is about to be upgraded."""
    try:
        has_data = c.execute("SELECT 1 FROM sqlite_master WHERE name='messages'").fetchone() is not None
    except Exception:
        return False
    return has_data and current_version(c) < LATEST


def snapshot(conn, dest):
    """Consistent copy using SQLite's online backup API (safe even while the database is in use)."""
    import sqlite3
    out = sqlite3.connect(dest)
    try:
        conn.backup(out)
        ok = out.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        out.close()
    if not ok:
        raise RuntimeError("Backup failed its integrity check")
    return dest


def apply(c):
    """Create/upgrade the schema atomically. Safe if two processes start at once (second sees the new version).
    Foreign keys are switched off for the table rebuilds and verified with foreign_key_check before COMMIT."""
    prev = c.isolation_level
    c.isolation_level = None  # manual transaction control
    c.execute("PRAGMA foreign_keys=OFF")
    try:
        c.execute("BEGIN IMMEDIATE")
        try:
            for stmt in V1.split(";"):
                if stmt.strip():
                    c.execute(stmt)
            ver = current_version(c)
            for v in sorted(MIGRATIONS):
                if v > ver:
                    for stmt in MIGRATIONS[v]:
                        c.execute(stmt)
                    c.execute("INSERT INTO kv(key,value) VALUES('schema_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (json.dumps(v),))
            if c.execute("PRAGMA foreign_key_check").fetchall():
                raise RuntimeError("Migration would break foreign keys; rolled back")
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
    finally:
        c.execute("PRAGMA foreign_keys=ON")
        c.isolation_level = prev
