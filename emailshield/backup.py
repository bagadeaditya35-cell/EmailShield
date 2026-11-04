"""Consistent database backups (SQLite online backup API), verification, and a guarded restore.
Backups contain scan history and are NOT encrypted: protect the backups folder like the live database.
Usage: python -m emailshield.backup create | list | verify FILE | restore FILE"""
import hashlib
import shutil
import sqlite3
import sys
from datetime import datetime, timezone

from . import config, db, migrations, server


def backup_dir():
    d = config.DATA_DIR / "backups"
    d.mkdir(parents=True, exist_ok=True)
    return d


def create(keep=None):
    db.init()
    dest = backup_dir() / f"emailshield-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.db"
    with db.db() as c:
        migrations.snapshot(c, str(dest))
    digest = hashlib.sha256(dest.read_bytes()).hexdigest()
    (dest.with_suffix(".db.sha256")).write_text(f"{digest}  {dest.name}\n")
    if keep:
        prune(keep)
    return {"file": str(dest), "sha256": digest, "bytes": dest.stat().st_size}


def prune(keep):
    files = sorted(backup_dir().glob("emailshield-*.db"))
    for f in files[:-keep] if keep > 0 else []:
        f.unlink(missing_ok=True)
        f.with_suffix(".db.sha256").unlink(missing_ok=True)


def list_backups():
    return [{"file": f.name, "bytes": f.stat().st_size, "created": datetime.fromtimestamp(f.stat().st_mtime, timezone.utc).isoformat(timespec="seconds")}
            for f in sorted(backup_dir().glob("emailshield-*.db"), reverse=True)]


def verify(path):
    """Checks SQLite integrity, that it is an EmailShield database not newer than this build, and the recorded SHA-256 if present."""
    try:
        c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            if c.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                return False, "integrity check failed"
            if not c.execute("SELECT 1 FROM sqlite_master WHERE name='messages'").fetchone():
                return False, "not an EmailShield database"
            ver = migrations.current_version(c)
            if ver > migrations.LATEST:
                return False, f"database version {ver} is newer than this EmailShield (supports {migrations.LATEST})"
        finally:
            c.close()
    except sqlite3.Error as e:
        return False, f"{type(e).__name__}: {e}"
    sidecar = type(path)(str(path) + ".sha256") if not str(path).endswith(".db") else path.with_suffix(".db.sha256")
    if sidecar.exists():
        want = sidecar.read_text().split()[0]
        if hashlib.sha256(path.read_bytes()).hexdigest() != want:
            return False, "SHA-256 does not match the recorded value (file changed or damaged)"
    return True, "ok"


def restore(path):
    """Replace the live database with a verified backup. Refused while the engine is running. The current database is kept aside."""
    from pathlib import Path
    path = Path(path)
    ok, why = verify(path)
    if not ok:
        raise ValueError(f"Backup rejected: {why}")
    lock = server.acquire_instance_lock()
    if lock is None or server.engine_info():
        if lock:
            lock.close()
        raise RuntimeError("EmailShield is running. Stop it first (EmailShield.exe --stop), then restore.")
    try:
        aside = None
        if config.DB_PATH.exists():
            aside = config.DB_PATH.with_name(config.DB_PATH.name + f".before-restore-{datetime.now(timezone.utc):%Y%m%d%H%M%S}.bak")
            shutil.copy2(config.DB_PATH, aside)
        for suffix in ("-wal", "-shm"):
            p = config.DB_PATH.with_name(config.DB_PATH.name + suffix)
            p.unlink(missing_ok=True)
        shutil.copy2(path, config.DB_PATH)
        db._ready.discard(str(config.DB_PATH))
    finally:
        lock.close()
    return {"restored_from": str(path), "previous_database_kept_as": str(aside) if aside else None}


def main(argv):
    if not argv or argv[0] not in ("create", "list", "verify", "restore"):
        print(__doc__)
        return 2
    try:
        if argv[0] == "create":
            print(create(keep=7))
        elif argv[0] == "list":
            for b in list_backups():
                print(b)
        elif argv[0] == "verify":
            ok, why = verify(__import__("pathlib").Path(argv[1]))
            print("OK" if ok else f"FAILED: {why}")
            return 0 if ok else 1
        else:
            print(restore(argv[1]))
    except (ValueError, RuntimeError, IndexError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
