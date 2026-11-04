# Security and privacy design
- **AuthN**: every `/api/*` route needs `X-API-Key` (constant-time compare). Key from `EMAILSHIELD_API_KEY` or generated into `data/api_key.txt`. 10 failures/minute per client then HTTP 429. Single role only (no per-user accounts yet).
- **Network**: binds 127.0.0.1. Localhost is not a substitute for auth, so auth is always on.
- **XSS**: dashboard uses `textContent` only (no innerHTML); CSP `default-src 'none'; script-src 'self'`; HTML reports escape all content; test sends `<script>` payloads.
- **Uploads**: `.eml` only, size limit enforced while streaming (default 10 MB), filenames reduced to basenames, attachments only hashed/typed in memory, never written or executed.
- **Privacy**: reports omit message body and recipients. Threat intel is OFF unless `EMAILSHIELD_TI_ENABLED=true`; it sends only URLs (query string stripped) and attachment SHA-256 hashes, max 10 URLs, never bodies or files. Enable only with organizational authorization; free API tiers have terms that may forbid sensitive data.
- **Secrets**: API keys via environment variables; Gmail OAuth files in `data/` (git-ignored). Gmail scope is `gmail.readonly` only. Nothing deletes, moves or quarantines mail.
- **Audit**: logins failed, uploads, case updates, report downloads, TI lookups; case history per message.
- **Retention**: `EMAILSHIELD_RETENTION_DAYS` (default 90), purge at API start.
- **Known gaps**: no TLS, no roles, no DB encryption at rest, API key stored plaintext in `data/`. Fine for a local prototype, not for production.

## Added in 2.1
- **Network binding**: loopback by default; non-loopback requires EMAILSHIELD_ALLOW_REMOTE=true AND an explicitly set key of 16+ characters, else startup is refused. Optional TLS via EMAILSHIELD_TLS_CERT/KEY.
- **No duplicate instances**: a loopback lock socket; no other process is ever terminated; the port search skips busy ports.
- **Secrets**: Splunk token write-only through the API; stored via env var / OS keyring / restricted file; never in settings.json, logs, audit entries or reports (tested).
- **Splunk export privacy**: no body/recipients/subject/full URLs by default.
- **Packaged app**: no secrets bundled; per-user data folder; API key generated on first run.
- **Dashboard safety**: DOM text nodes only; a test scans app.js for dangerous sinks.
- **Not done**: dependency vulnerability scanning (needs internet), penetration testing.

## Added with the monitoring engine
- Gmail: OAuth 2.0 authorization code + PKCE, one-time expiring `state`, scope `gmail.readonly` only; no password is ever requested; refresh token in the secret store; disconnect revokes and deletes it.
- Secrets redacted from logs, events, audit entries and stored job errors (`redact.py`, tested with tokens/HEC token).
- Consequential actions (enable monitoring, disconnect, retry all, re-scan, autostart) need a second click/confirmation in the UI and `confirm:true` on the API where destructive; all are audited.
- The API uses a header key, not cookies, so classic CSRF does not apply; the only unauthenticated route is the OAuth callback, protected by the one-time state.
- Start-with-Windows is explicit, per-user, visible in Task Manager, off by default. No hidden tasks, no services installed.
- Not done: dependency vulnerability scan, penetration test, TLS by default, multi-user roles.
