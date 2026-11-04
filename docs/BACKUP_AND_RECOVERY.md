# Backup, restore and recovery
- **Automatic**: while the engine runs, one verified backup per day into `<data>\backups` (newest 7 kept; SHA-256 sidecar files). Before any database migration an extra copy `emailshield.db.pre-migration-vN-<time>.bak` is made; a failed migration rolls back and leaves the original untouched.
- **Manual**: `EmailShield.exe --backup`, or Monitoring page / API `POST /api/backups`.
- **Verify**: `python -m emailshield.backup verify FILE` (integrity, EmailShield schema, version not newer than the program, checksum).
- **Restore** (engine must be stopped): `EmailShield.exe --stop` then `python -m emailshield.backup restore FILE` (or the same inside the portable build). The current database is kept as `*.before-restore-<time>.bak`.
- **Damaged database**: System health shows "DAMAGED". Stop EmailShield, restore the newest good backup. Checkpoints in the backup are older, so some messages are re-fetched and re-scanned; duplicates are prevented by the idempotency rules.
- **Backups are not encrypted** and hold scan history: keep them on an encrypted drive (BitLocker) and delete them when no longer needed.
- Not implemented: off-machine backup, encrypted backups, point-in-time recovery.
