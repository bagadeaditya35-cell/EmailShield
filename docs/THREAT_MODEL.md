# Threat model (STRIDE-style summary, EmailShield 2.2)

**Assets**: OAuth refresh tokens and client secret; Splunk HEC token; scan history (subjects, senders, URLs, hashes, alerts); investigation notes; API key; the mailbox itself (read-only access).
**Trust boundaries**: (1) the user's Windows account; (2) localhost HTTP between the window/browser and the engine; (3) the internet (Google, Splunk, optional threat-intel); (4) untrusted email content.

| Threat | Mitigation in place | Residual risk / not covered |
|---|---|---|
| Malicious email content (HTML/script/MIME tricks) attacks the dashboard | Content never rendered as HTML; DOM text nodes only; CSP; reports escape; tests with `<script>` payloads | Browser/WebView0-days |
| Malicious attachment | Never executed or saved; hashed and typed in memory; size limit | Parser bugs (Python `email` library); no sandbox |
| Another local user/process calls the API | 127.0.0.1 only; API key required; lockout after 10 bad keys; key file owner-only (POSIX) | Malware running as the same user can read the key and the data |
| Credential theft from disk | Windows DPAPI (current user) or keyring; env overrides; redaction in logs | Same-user malware can use DPAPI too; keyring/DPAPI untested here; backups and the database are NOT encrypted (use BitLocker) |
| Token leakage via logs/errors/exports | Central redaction; tested | New code paths could forget to redact |
| Spoofed OAuth callback / CSRF | One-time `state` + PKCE, expiry | Local attacker with same-user rights |
| Cross-mailbox data mixing | Per-account uniqueness, queries scoped per account, correlation same-mailbox by default | Single operator model: all mailboxes belong to the local user |
| Duplicate/lost processing after crash | Leased atomic claims, idempotent jobs, atomic checkpoint+queue | Best effort across a power cut mid-write (SQLite WAL durability) |
| Data exfiltration to third parties | Splunk/TI off by default; privacy-minimal events; hashes not ids | Operator misconfiguration |
| Database damage | Integrity check, daily verified backups, pre-migration copy, guarded restore | Backups unencrypted; disk failure |
| Tampering with audit trail | Audit table with retention | A user with file access can edit SQLite; no tamper-evident log |
| Supply chain | Few dependencies; `pip freeze` recorded at build | Versions unpinned in repo until verified on Windows; no signing |
| Unauthorized remote access | Loopback default; non-loopback needs explicit opt-in + 16+ char key | No TLS by default; no multi-user auth/RBAC |

**Out of scope / not claimed**: multi-user shared service, tamper-proof evidence handling, certified or approved use with confidential or government data, malware detonation.
