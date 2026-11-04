# Release notes

## 2.3.0 (EXPERIMENTAL: not beta, not stable)
Unsigned, untested on Windows as a packaged build. Not approved for confidential or production use.
### New
- **Engine/window split:** monitoring runs in a background engine; closing the window no longer stops it. Stop/status/autostart/backup/restore commands. Single engine per PC.
- **Multi-account:** one thread per mailbox; per-account records (migration v3 stops cross-mailbox merging); explicit audited cross-mailbox correlation.
- **Reliability:** backpressure (bounded queues), low-disk pause, bounded Splunk outbox with visible drops, delivery latency, periodic retention, integrity checks and a health page.
- **Security/privacy:** DPAPI-protected secret file on Windows, owner-only permissions on POSIX, data minimisation defaults (no body text/recipients stored), automatic pre-migration backup, daily verified backups with guarded restore, Gmail error explanations, alert status workflow with audit.
- **Release tooling:** secret scanner (tree + history), release-readiness report, installer script (stop-on-upgrade, optional sign-in start, keep-data prompt).
### Behaviour changes to be aware of
- Default storage no longer keeps the first 5,000 characters of body text or recipients (turn on in Settings if needed).
- Same email in two mailboxes is now two records.
- Closing the window leaves the engine running.
### Fixed after release
- Monitoring page failed with "Internal Server Error": the `/api/health/detail` route called a function instead of the health-checks module (name shadowing in `app.py`). Fixed with regression tests; see docs/TEST_PLAN_AND_RESULTS.md.

### Known limitations
See docs/ROADMAP_AND_LIMITATIONS.md and docs/RELEASE_READINESS.md. Highlights: Gmail OAuth "access blocked" not reproduced/resolved; no live Gmail or Splunk test; no encryption at rest; no TLS by default; monitoring only while signed in; Microsoft 365 and Gmail push not implemented.
- Uninstall can revoke Gmail access and remove stored credentials (`--forget-credentials`), only if you choose to delete your data.

## 2.2.0 (EXPERIMENTAL, not yet built or tested on Windows)
**New**: monitoring engine (leased persistent queue, retries with jitter, dead-letter, restart recovery); Gmail read-only connector with history sync and OAuth+PKCE; multiple mailboxes with per-mailbox threads, queues, checkpoints and credentials; per-mailbox message uniqueness (migration v3); backpressure and low-disk protection; background **engine** separate from the window; stop/status/start-with-sign-in controls; alerts with status and filters; Splunk outbox (bounded, de-duplicated, latency tracked); MITRE ATT&CK mapping; data-minimising storage defaults; retention; verified backups and guarded restore; Windows DPAPI for stored secrets; system health page; rule versions and generated rule reference; release-readiness gate.
**Changed**: job state names; Splunk export is queued instead of inline; body text and recipients are no longer stored by default; correlation is same-mailbox by default.
**Known limitations**: see docs/ROADMAP_AND_LIMITATIONS.md and PROGRESS.md. Gmail push, Microsoft 365, multi-user server, database encryption, code signing: not implemented. Real Gmail/Splunk/two-account/Windows installer: not yet verified.
**Upgrading**: data is migrated automatically after an automatic backup; keep your own copy of the data folder too.
