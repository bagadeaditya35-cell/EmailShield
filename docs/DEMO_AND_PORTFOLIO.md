# Safe demo scenario (no real citizen data)
1. `python scripts\generate_samples.py`; start API and worker (`run_worker.bat folder`).
2. Copy 3 samples into `data\inbox`; show the Dashboard update, then explain a High-risk finding's reason/evidence/next step.
3. Show the two "campaign" emails correlated and say aloud that shared indicators are not proof of one attacker.
4. Download the HTML report. Stop the worker and show the Monitoring page turn stale.
Never show real Cyber Cell cases, mailboxes or screenshots; describe your experience in general terms only and demo with synthetic data.

# Resume bullets (only what is implemented; edit after you verify it on your laptop)
- Built a Python/FastAPI/SQLite email threat-analysis tool with 31 explainable phishing/malware-delivery detection rules and a capped heuristic risk score.
- Implemented a background worker with a persistent job queue, retry with backoff, restart recovery, heartbeat health reporting and a read-only Gmail API provider (tested against simulated API responses).
- Added optional VirusTotal/Safe Browsing enrichment designed for privacy: off by default, URL/hash-only, cached and rate-limit aware.
- Created an investigation dashboard with case notes, audit trail, indicator correlation and JSON/HTML/text reports; hardened with API-key auth, CSP and XSS-safe rendering.

# Interview questions and short answers
- *Why heuristics, not ML?* Explainable evidence analysts can verify, no training data or GPU needed; the score is not a probability.
- *How do you avoid double counting?* Rules are grouped and each group is capped.
- *How do you avoid reprocessing mail after restart?* Unique job keys plus SHA-256 message dedupe; stuck jobs are re-queued at startup.
- *Why polling instead of Gmail push?* Push needs a public HTTPS endpoint (Pub/Sub); polling works from a laptop.
- *What would you do before production?* TLS, per-user roles, encrypted storage, central logging, backups, legal/data-protection approval.
- *What are the limitations?* Rule-based evasion, no content sandboxing, TI/Gmail unverified against live services, single API key.
