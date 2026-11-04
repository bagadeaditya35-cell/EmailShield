# Database migrations
Implemented in `emailshield/migrations.py`; run automatically the first time a database file is opened, inside one `BEGIN IMMEDIATE` transaction (all-or-nothing; safe if two processes start together). Version is stored in `kv.schema_version`.
- **v1** (EmailShield <= 2.1): original schema, treated as the baseline for existing databases.
- **v2** (monitoring engine): adds `accounts`, `alerts`, `exports`; adds `account_id, external_id, engine_version, ruleset_version` to `messages` (existing rows keep NULLs); rebuilds `jobs` with leases/retry/dead-letter fields and the new uniqueness key.
  Job state mapping: `queued`->`pending`, `done`->`completed` (completed_at = old updated_at), `failed`->`failed` (dead_lettered_at set), `processing` stays and is reclaimed at the next start.
Scan history, notes, case events, threat-intel results and settings are untouched. **Back up before upgrading anyway**: copy the data folder while the app is closed.
Tested: a v1 database with real rows is upgraded, history and job states verified, and a second start is a no-op (`tests/test_migrations.py`). Not tested: upgrading a large production-size database.

- **v3** (2.3): rebuilds `messages` with `UNIQUE(account_id, raw_sha256)` (previously `raw_sha256` was globally unique, which merged the same email arriving in two mailboxes). Row ids are preserved so alerts, indicators, case history and threat-intel results stay linked. Existing rows with no account become account `''` (uploads/legacy). Foreign keys are verified (`PRAGMA foreign_key_check`) before commit.
## Safety net (2.3)
Before any upgrade of an existing database, a consistent backup is written next to it (`emailshield.db.pre-migration-v<N>-<time>.bak`, integrity-checked). A failing migration is rolled back completely (tested: schema version, row counts and tables unchanged) and the backup remains. Migrations never delete user data. Daily backups and guarded restore: see WINDOWS_INSTALLATION.md.
