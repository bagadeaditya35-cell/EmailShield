# Automated email monitoring

**Read-only and alert-oriented.** The monitoring engine never sends, forwards, deletes, moves, labels or quarantines mail, never opens attachments and never visits links.

## Components (and where they live)
| Role | Module | Notes |
|---|---|---|
| A. Mailbox connectors | `providers.py` (`MailConnector`, `GmailProvider`, `FolderProvider`), `oauth_gmail.py` | Gmail (read-only scope) and a local-folder mailbox for demos/tests. **Microsoft 365/Graph: interface only, NOT implemented.** |
| B. Ingestion / worker | `worker.py` (`Worker` per mailbox, `MonitorService` for all) | discover -> queue -> claim -> scan -> complete |
| C. Persistent queue | `db.py` `jobs` table | leased claims, retries, dead-letter, idempotent |
| D. Analysis engine | `detector.py`, `parser.py` via `ingest.py` | the ONE existing engine; version + ruleset fingerprint stored per scan |
| E. Results | `messages`, `indicators`, `case_events` | unchanged schema plus engine/ruleset/provider/account/external id columns |
| F. Alerts | `alerts` table, `db.upsert_alert` | one alert per message; re-scans update it |
| G. Splunk exporter | `splunk.py` + `exports` outbox | scanning never waits for Splunk |
| H. Health | `monitor.py` `overview()` | separate facts, honest status |
| I. Dashboard/API | `app.py`, `static/` | Monitoring page; no scanning logic lives here |
| J. Desktop lifecycle | `desktop.py` `Runtime` | hosts the service; single-instance lock; clean stop |
The dashboard does not keep the worker alive and a dashboard restart destroys nothing: jobs and results are in SQLite.

## Engine and window (2.3)
The monitoring service runs in the **background engine** (`EmailShield.exe --background`); the window only attaches to it. Closing the window does not stop monitoring; the Monitoring page and `--stop` do, explicitly. One engine per PC (lock + instance file). Each enabled mailbox runs in its own thread, so a stuck account cannot delay the others. See WINDOWS_INSTALLATION.md and MULTI_ACCOUNT_AND_USERS.md.

## Backpressure and safety limits
- Each mailbox has a queue limit (default 1000 waiting jobs). When reached, discovery pauses; when discovery is cut short the checkpoint does **not** advance, so nothing is skipped.
- Below 200 MB free disk, monitoring pauses (no half-written database) and resumes automatically.
- The Splunk outbox is bounded (5000); refused alerts are counted and shown, never silently dropped.
- Retention (scans 90 days, logs/audit 365 days) runs every 6 hours inside the service; one verified backup per day (newest 7 kept).

## Job lifecycle
`pending` -> `processing` (leased) -> `completed` | `retry_scheduled` (back to processing when due) | `failed` (dead-letter) | `cancelled`.
- **Idempotency**: unique (provider, account, message id, engine version). Routine sync never re-queues an already-scanned message; a re-scan is an explicit, audited request that creates a job with the new engine version.
- **Atomic claims**: `BEGIN IMMEDIATE` makes claims safe across threads and processes. Two workers never get the same job (tested with 4 concurrent threads).
- **Crash recovery**: a claim has a lease (default 5 minutes). If a worker dies, the job becomes claimable again. Only the job that was actually being processed ("in flight") is charged an attempt, so innocent neighbours are never punished; a message that keeps killing the worker is dead-lettered as `interrupted`.
- **Checkpoint + jobs commit together**: the Gmail history checkpoint advances in the same transaction that queues the discovered messages.
- **Shutdown**: unfinished claimed jobs are handed back to `pending`.

## Errors and retries
| Category | Behaviour |
|---|---|
| network, provider_error (5xx), io, database, unknown | retry with bounded exponential backoff + jitter (base 30 s, cap 15 min), up to *max attempts* (default 5), then dead-letter |
| rate_limit | honours the provider's retry-after (up to 1 h), does not consume attempts |
| auth_required (revoked/expired) | account paused, jobs kept (not dead-lettered), dashboard shows **Authentication required**; reconnect to resume |
| config, permission | account paused with the error shown |
| malformed | dead-letter immediately (a retry cannot help) |
Failed jobs are kept with their error category and (redacted) text. **Retry** in the dashboard re-queues only categories where a retry can plausibly help.

## Monitoring states
Disabled, Connecting, Synchronizing, Monitoring, Degraded, Authentication required, Error, Stopping. The overall light is green only if the worker heartbeat is fresh AND a mailbox is connected AND monitoring is on AND no mailbox needs attention. It never says "24/7 protected".
What stops monitoring: closing EmailShield, signing out, shutdown, sleep, losing the network (it resumes from the checkpoint). Pending work is never lost. Gmail history older than about a week may force a full re-listing (handled automatically).

## Change detection: polling with history sync (push NOT implemented)
- First sync: reads the mailbox checkpoint (`historyId`), then lists recent INBOX messages (window = "first sync looks back", default 2 days, bounded).
- After that: `users.history.list` returns only messages added since the checkpoint. Expired history -> automatic full resync. A full reconciliation listing also runs every *reconcile minutes* (default 60) to catch anything missed.
- Interval is configurable (default 60 s, minimum 15 s) and API errors/limits are handled as above.
- **Why not Gmail push (Pub/Sub)**: push needs a Google Cloud topic, publish permission for Gmail's service account, a `watch` renewed at least weekly, and either a public HTTPS endpoint or a Pub/Sub pull subscription with extra credentials/scope. Notifications carry only an address and a history id and can be delayed or dropped, so reconciliation would still be required. That is not available to a laptop app without extra infrastructure, and it was impossible to test here. The design leaves a hook: a future push receiver only has to set `sync_requested_at` ("Sync now" already uses it).

## Gmail setup (use a dedicated TEST mailbox)
1. Google Cloud Console -> new project -> enable **Gmail API**.
2. OAuth consent screen: External, in *Testing*; add your test mailbox as a test user; scope `gmail.readonly` only. (To my knowledge, refresh tokens for apps in Testing expire after about 7 days, so expect to reconnect weekly; verify in Google's documentation.)
3. Credentials -> Create OAuth client ID -> **Desktop app** -> download the JSON.
4. EmailShield -> Monitoring -> Step 1: paste the JSON (stored in the OS keyring/secret store, never shown again) -> Step 2: Connect Gmail -> sign in with the TEST account in your browser -> approve read-only access.
5. Turn monitoring on for the mailbox. Disconnect revokes the token at Google (if reachable), deletes it locally and cancels pending jobs; scan history is kept.
EmailShield never asks for a Gmail password. The OAuth redirect is `http://127.0.0.1:<port>/oauth/gmail/callback`, protected by a one-time `state` and PKCE.
Legacy `scripts/gmail_auth.py` still works.

## What data goes where
| Data | Stored locally | Sent to the mail provider | Exported to Splunk (if enabled) |
|---|---|---|---|
| Raw email | **No** (parsed, then discarded) | fetched read-only | never |
| Body text | first 5,000 characters kept in the scan record | - | never |
| Subject, sender, URLs, attachment names/hashes | yes (scan record) | - | no by default; domains and hashes yes; subject/full URLs only if you opt in |
| Provider message id | yes (job/scan) | yes | **no**: only a 20-character one-way hash |
| OAuth refresh token / HEC token | OS keyring or restricted file | - | never; never shown in the UI or logs (redaction) |
| Findings, score, ATT&CK, engine version, alert id | yes | - | yes |
Retention: `EMAILSHIELD_RETENTION_DAYS` (default 90) purges old scans at start. External reputation lookups are off unless you enable them and only send URLs/hashes.

## Resource use (measured, not promised)
`python scripts/benchmark.py 300` on the Linux build sandbox (Python 3.12, local folder mailbox, no network latency): 300 messages in 5.7 s (~53/s, one worker), peak memory 26 MB, database 1.8 MB. **Not yet measured on your laptop**; run it there. Real throughput is bounded by provider latency and rate limits. Bounded batch size (default 10) and one worker thread keep memory flat; no mailbox is loaded into memory.

## Troubleshooting
- *Authentication required*: reconnect (Monitoring -> Connect Gmail). Jobs are kept.
- *Worker "stopped/stale/not running"*: the app is closed or hung; reopen. Check `worker.log` in the data folder.
- *Nothing arrives*: confirm monitoring is on, "last successful sync" moves, and the first-sync window covers the mail.
- *Failed jobs*: open the details; `malformed` cannot be retried; `network` can.
- *Splunk "failed"*: fix token/URL in Settings, then retry the failed exports.
