# Progress record (branch feature/advanced, version 2.3.0 EXPERIMENTAL)

| Phase | Status |
|---|---|
| 1 Audit & preserve | DONE (baseline-2.0.1 and feature/monitoring-engine untouched; new branch; secret scan of tree+history clean) |
| 2 Core reliability | DONE, mock/process-tested: per-account isolation (migration v3), thread-per-account, backpressure, disk guard, health page, in-flight crash accounting |
| 3 Background monitoring | DONE for the per-user engine design; process-tested with a stub server; **real FastAPI/Windows run pending** |
| 4 Real integrations | **NOT DONE**: Gmail OAuth block not reproduced/resolved (diagnostics + docs added); Splunk verified only with fakes (verification script added) |
| 5 Security | PARTIAL: DPAPI-protected secrets (unverified on Windows), permissions, data minimisation, backups/restore, audit coverage, threat model. No encryption at rest, no external review |
| 6 Detection | Audit documented (generated rule docs), rule versions, latency measured; rules NOT tuned on purpose; evaluation unchanged |
| 7 Windows release | scripts and installer written; **not built, not tested** |
| 8 GitHub prep | DONE locally (scanner, readiness report, templates, docs); **nothing published; license undecided** |
| 9 Final verification | PARTIAL: see docs/TEST_PLAN_AND_RESULTS.md |

## Next actions (you, on Windows)
1. `verify.bat` (real pytest), then the checklist in docs/TEST_PLAN_AND_RESULTS.md.
2. Gmail: add yourself as a Test user (docs/GMAIL_OAUTH_TROUBLESHOOTING.md).
3. `build_windows.bat`, test on a clean VM.
4. Decide the license, then follow docs/GITHUB_RELEASE.md (private first).

## Provenance note (read this)
While this version was being finished, files appeared in the working copy that were **not written by the assistant's own edits**: `emailshield/uninstall.py`, `tests/test_uninstall.py`, the `--forget-credentials` option in `desktop.py`, a rewritten `packaging/emailshield.iss` (adds credential cleanup on uninstall; drops the optional start-at-sign-in task, WebView2 notice and "Back up" shortcut), a changed tail of `build_windows.bat`, a replacement `scripts/release_check.py` (reads `docs/RELEASE_EVIDENCE.json`), and new or rewritten docs (`RELEASE_EVIDENCE.json`, `BACKUP_AND_RECOVERY.md`, `MULTI_ACCOUNT_AND_USERS.md`, `docs/RELEASE_NOTES.md`, `PRIVACY.md`, `WINDOWS_INSTALLATION.md`, `GMAIL_OAUTH_TROUBLESHOOTING.md`, `LICENSE_CONSIDERATIONS.md`, `GITHUB_RELEASE.md`). They were reviewed line by line, the full suite was re-run with them (all pass), and their inconsistencies with the code were fixed (stale 2.2.0 version/tag, duplicate documents, a documented Monitoring-page backup button that did not exist). Nothing in them claims verification that did not happen. If you did not expect these files, check who or what else has write access to this folder.

## Health-endpoint fix (post-2.3.0)
Root cause confirmed and fixed (module alias `health_checks`); regression tests added and shown to fail on the buggy code and pass on the fix. Verified only with stand-ins for pytest and FastAPI in the build sandbox: **run `python scripts\pytest_report.py` on Windows** and send `pytest-report.md` so the nine reported failures can be triaged individually. The fix and two of the tests were applied by another writer in the working copy while this was in progress; they were reviewed, one apparent weakening of an auth test turned out to be the un-shadowing of a duplicated test name (both versions now run), and a duplicated constant was tidied.
