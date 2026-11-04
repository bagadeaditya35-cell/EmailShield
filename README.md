# EmailShield 2.3.0 (EXPERIMENTAL)

Defensive, **read-only** email threat detection and investigation tool: explainable detection rules (31), multi-mailbox background monitoring (Gmail read-only + local folder), persistent queue with crash recovery, alerts and case history, MITRE ATT&CK mapping, optional Splunk export, backups, and a Windows desktop app. Python + FastAPI + SQLite.

> **Status:** experimental. Not approved for confidential or production use. See `docs/RELEASE_READINESS.md` and `PROGRESS.md` for what is and is not verified. Use only synthetic mail or mailboxes you are authorized to analyze.

## Run it (Windows, Command Prompt, project folder, Python 3.12 recommended)
| Goal | Command |
|---|---|
| Install | `python -m venv venv` / `venv\Scripts\activate` / `pip install -r requirements.txt` (+ `requirements-desktop.txt` for the window) |
| Check environment | `python scripts\check_env.py` |
| Run the full tests | `verify.bat` (real pytest) |
| Dashboard in a browser (engine in this console) | `run.bat` |
| Desktop window (starts the background engine if needed) | `run_desktop.bat` |
| Stop the background engine | `stop.bat` (or `EmailShield.exe --stop`) |
| Build exe + installer + checksum | `build_windows.bat` |
| Pre-publication checks | `python scripts\release_check.py` and `python scripts\secret_scan.py --history` |

## Documentation
MONITORING · MULTI_ACCOUNT_AND_USERS · BACKUP_AND_RECOVERY · WINDOWS_INSTALLATION · GMAIL_OAUTH_TROUBLESHOOTING · SPLUNK · SECURITY (root) · THREAT_MODEL · PRIVACY · DATABASE_MIGRATIONS · ARCHITECTURE · DETECTION_RULES · DETECTION_EVALUATION · TEST_PLAN_AND_RESULTS · GITHUB_RELEASE · LICENSE_CONSIDERATIONS · RELEASE_READINESS · RELEASE_EVIDENCE.json · ROADMAP_AND_LIMITATIONS (all in `docs/`).
