# Architecture
```
 .eml upload ─┐                          ┌─> SQLite (WAL) <─┐
 CLI batch  ──┼─> ingest.py ─> parser ─> detector ─> db.py │  shared by two processes
 Worker ──────┘      │                                      │
 (folder|gmail)      └─> intel.py (optional, off by default)│
 Dashboard (static JS) ── HTTP + X-API-Key ──> app.py (FastAPI, 127.0.0.1) ─┘
```
- **One ingestion path** (`ingest.py`) is used by API, CLI and worker, so behavior is identical everywhere.
- **Two processes**: the API/dashboard and the worker. They share SQLite in WAL mode; the worker writes a heartbeat the dashboard reads. A crashed worker therefore shows as "stale/not running" instead of silently looking fine.
- **Queue**: `jobs` table with UNIQUE(provider, external_id); statuses queued/processing/done/failed; exponential backoff; jobs left "processing" by a crash are re-queued at startup. Message-level dedupe uses the SHA-256 of the raw email.
- **Scoring**: each rule adds its weight once; rules are grouped (sender, auth, url, content, attachment, structure) and each group is capped so one underlying condition cannot stack up. Heuristic, not a probability.
- **Migration path**: swap SQLite for PostgreSQL by replacing `db.py`; the provider interface (`list_new`, `fetch_raw`) allows Microsoft Graph later.

## Monitoring engine (2.2)
See MONITORING.md. Summary: connector -> discover (history sync) -> atomic checkpoint+queue -> leased claim -> existing detector -> scan + alert -> outbox -> Splunk. The queue, results and checkpoints live in SQLite, so the worker can later run as its own service (`python -m emailshield.worker --service`) without a rewrite; run only one monitor per database (leases make a second one safe but wasteful).

## Processes (2.3)
`EmailShield.exe` (window) -> attaches to -> `EmailShield.exe --background` (engine: API + MonitorService threads per mailbox + Splunk outbox + retention/backup) -> SQLite (WAL) + OS secret store. One engine per PC (instance lock). The window can be closed or crash without affecting monitoring.
