# Known limitations
- Rule-based heuristics miss text-only and well-authenticated attacks (see docs/DETECTION_EVALUATION.md for the measured misses) and can flag legitimate bulk/billing mail.
- Evaluation dataset is small, synthetic and written by the rule author; numbers are not real-world accuracy.
- ATT&CK technique IDs were written without internet access; verify against the current release. Mappings are inference, not attribution.
- Single API key, no user accounts/roles; no TLS by default; no database encryption.
- Gmail, VirusTotal, Safe Browsing, Splunk tested against simulated responses only. Microsoft Graph and Gmail push not implemented.
- Native window, packaged exe, installer, Linux/macOS builds and mobile layout not yet verified.
# Roadmap
Real-pytest + browser verification -> clean-VM install test -> code signing -> user accounts/roles -> Microsoft Graph provider -> sender/domain WHOIS-age enrichment (authorized) -> rule tuning on an independent dataset -> Windows service mode.

# Monitoring engine: limitations (2.2)
- Gmail push notifications not implemented (polling + history sync + hourly reconciliation instead). Microsoft 365 not implemented.
- Everything provider-facing was tested only against simulated responses. Gmail apps in OAuth "Testing" status may need reconnecting about weekly.
- One monitor per database is the supported setup; leases make a second one safe but wasteful.
- The folder connector treats a rewritten file (new modified time) as a new reference; the scan is still deduplicated by content.
- Scan records keep the first 5,000 characters of body text; raw mail is not stored, so a re-scan re-fetches from the provider (impossible for uploaded files).
- No automatic response actions by design; no user accounts/roles; no TLS by default.
# Roadmap additions
Verify on Windows -> Gmail push via a small relay or Pub/Sub pull (opt-in) -> Microsoft Graph delta-query connector -> Windows service mode -> signed installer -> rule tuning on an independent dataset.

# Limitations added/updated in 2.3
- Monitoring runs only while the Windows user is signed in (per-user engine). Not a service; not 24/7.
- Data is not encrypted at rest by EmailShield (use BitLocker); backups are unencrypted; DPAPI protection is Windows-only and unverified.
- Single operator model: no user accounts, roles or tenant isolation. Model B (shared server) is not implemented.
- Gmail OAuth for restricted scopes requires Testing-mode test users or Google verification; Testing tokens expire about weekly.
- No Gmail push, no Microsoft 365, no sandboxing of attachments, no automated response.
- Fairness is thread-per-account, not a weighted scheduler. Logs/backups are bounded by rotation/retention, not by a global disk quota.
- Detection: 31 heuristic rules; measured recall ~79% and false-positive rate ~22% on a small self-written synthetic set; not a real-world accuracy claim.
