# Test plan and results (EmailShield 2.3.0 + health-endpoint fix)

## Update after the Monitoring-page "Internal Server Error" fix (read this first; it supersedes the counts further down)
**Root cause (confirmed):** `emailshield/app.py` imported the module `health` and then defined the route function `def health()`, which rebinds the name. `/api/health/detail` therefore called `health.run_checks()` on a function: `AttributeError: 'function' object has no attribute 'run_checks'` (reproduced exactly). The Monitoring page fetches that endpoint, so the whole page failed.
**Fix:** the module is imported as `health_checks`; `/api/health/detail` calls `health_checks.run_checks()`; `/api/health` and its response (`{"status": "ok"}`) are unchanged. No schema, data, authentication, secret-handling, isolation, backup or Splunk code was touched.
**Regression tests:** `tests/test_app_namespace.py` (a framework-free guard: no module may redefine one of its own imports; checks all of `emailshield/`) and API tests for both endpoints in `tests/test_api.py` (health open and unchanged; detail requires the key, returns the checks, exposes no secrets, changes no data).
**Evidence that the tests are valid (executed in the build sandbox, Python 3.12.3):**
| app.py | Result |
|---|---|
| buggy (reverted to the previous commit, tests kept) | 6 failed (4 API + 2 namespace guards), 244 passed |
| fixed | 253 passed, 0 failed (after adding 3 report-script tests) |
**What "executed" means here:** real `pytest` and real FastAPI could NOT be installed in the build sandbox (no internet). The suite was run with (a) a small stand-in for pytest and (b) a small stand-in for FastAPI's routing and `TestClient` (path/query/header/dependency handling, middleware, lifespan), neither of which is in the repository. So the real `app.py` route code and the real `tests/test_api.py` did run, but not under FastAPI itself. **A real `python -m pytest` run on your machine is still required** and has not been done by me.
**Counts now:** 253 test functions, all names unique (no test is silently shadowed). Bare environment (no web stack): the API module is skipped; with the FastAPI stand-in: 253 executed, 0 failed.
**Extra conditions tried (stand-ins, Linux):** project path containing spaces and non-ASCII characters; `LC_ALL=C` with `PYTHONUTF8=0`; time zones Asia/Kolkata and America/Los_Angeles; `-W error::DeprecationWarning`. All passed; only `ResourceWarning`s from the test stand-in/test helpers (unclosed files), none from product code.
**The nine previously reported failures:** NOT investigated, because the list was never provided to me and nothing in the repository records it. I could not reproduce any failure other than the health bug above. To investigate them individually, run on your machine: `python scripts\pytest_report.py` and send `pytest-report.md` (it contains Python/package versions, counts and one redacted line per failure; no email data).
**Unresolved / not verified:** real pytest on Python 3.12 and 3.14; real FastAPI behaviour; anything on Windows. Known fragility (not changed, per instructions): the Monitoring page loads several endpoints in one go, so any single failing endpoint blanks the whole page.

---
(The sections below are from the earlier 2.3.0 test record; their counts are out of date.)


## Headline
- **245 tests exist; 207 were executed and passed (0 failed) under a small STAND-IN runner I wrote, because pytest could not be installed in the build sandbox. This is NOT a pytest result.**
- **38 tests (all of `tests/test_api.py`) have never been executed anywhere** (they need FastAPI + httpx).
- **Real pytest has not been run on this version.** Official command for you: `python -m pytest -v` (or `verify.bat`). Paste its summary here: collected ___ / passed ___ / failed ___ / skipped ___.
- Nothing was run on Windows. No live Gmail, live Splunk, real browser, packaged exe or installer.

## Environment of the executed runs
Linux (build sandbox), Python 3.12.3, standard library only (no FastAPI, uvicorn, pytest, httpx, pywebview, PyInstaller). Command: `python3 /tmp/shim/run.py` (stand-in; not part of the repository).

## Executed, by module
| Module | Tests | Result | Mock or real |
|---|---|---|---|
| test_alerts | 5 | executed, passed (stand-in runner) |
| test_api | 31 | **NOT executed** (needs FastAPI + httpx) |
| test_attack | 6 | executed, passed (stand-in runner) |
| test_autostart | 3 | executed, passed (stand-in runner) |
| test_core | 16 | executed, passed (stand-in runner) |
| test_desktop_selftest | 2 | executed, passed (stand-in runner) |
| test_detector_v2 | 9 | executed, passed (stand-in runner) |
| test_engine | 12 | executed, passed (stand-in runner) |
| test_errors_redact | 5 | executed, passed (stand-in runner) |
| test_evaluation | 4 | executed, passed (stand-in runner) |
| test_gmail_sync | 14 | executed, passed (stand-in runner) |
| test_intel | 10 | executed, passed (stand-in runner) |
| test_isolation | 10 | executed, passed (stand-in runner) |
| test_migrations | 3 | executed, passed (stand-in runner) |
| test_monitor | 15 | executed, passed (stand-in runner) |
| test_persistence_paths | 3 | executed, passed (stand-in runner) |
| test_ports | 2 | executed, passed (stand-in runner) |
| test_queue | 12 | executed, passed (stand-in runner) |
| test_reliability | 13 | executed, passed (stand-in runner) |
| test_security | 15 | executed, passed (stand-in runner) |
| test_server | 9 | executed, passed (stand-in runner) |
| test_splunk | 13 | executed, passed (stand-in runner) |
| test_splunk_outbox | 9 | executed, passed (stand-in runner) |
| test_worker | 14 | executed, passed (stand-in runner) |

Mock vs real: everything provider-facing (Gmail, OAuth, Splunk, threat intel, Windows registry/DPAPI) used **fake HTTP layers or fake modules**. Real: SQLite databases, threads, sockets, local HTTP stub servers, files, subprocess/signals.

## Also executed (real OS processes, Linux)
- Engine/window split with real processes (HTTP stub in place of uvicorn): window starts a detached engine; closing the window leaves it running; second `--background` and second window do not create a second engine (anchored process counts 0 -> 1 -> 1 -> 0); `--stop` authenticates, stops it, removes the instance file; worker state `stopped`.
- Monitor service as a process with two mailboxes: crash-orphaned job recovered, each mailbox scanned only its own message, clean SIGTERM, restart processed nothing twice.
- Idle soak (45 s, 2 mailboxes, 5 s poll): ~0.7 % of one core, 25 MB RSS, 3 threads. Throughput `scripts/benchmark.py 300`: 300 messages in 3.8 s (~80/s), 27 MB peak, 1.8 MB database. **Sandbox numbers, not your laptop.**
- `scripts/secret_scan.py --history`: 0 blockers, 5 synthetic fixtures in tests/. `scripts/release_check.py`: verdict EXPERIMENTAL. Dashboard JS: `node --check` and a dangerous-sink scan only (no browser).
- Detection evaluation (56 synthetic emails): unchanged by this work, see DETECTION_EVALUATION.md (includes latency).

## Defects found by testing and fixed
Cross-account merging of identical emails (migration v3); a crashing message could dead-letter innocent neighbours (in-flight attribution); `get_message` crashed on partial records; non-reproducible evaluation dataset; a windowed-exe logging crash risk; a CSP-blocked inline style; scanner attributing history hits to the wrong file. Several test defects of my own were also corrected (they are listed in git history).

## NOT verified
Real pytest on Windows; the 22 API tests; browser behaviour of every page; native window; PyInstaller build; installer install/upgrade/uninstall; clean-VM run; real Gmail (OAuth block unresolved) and token refresh/expiry; real Splunk indexing; DPAPI on Windows; Python 3.14 vs 3.12 dependency behaviour; long-duration reliability and resource use on the target laptop; upgrade of a real existing user database.

## Your verification checklist (Windows)
1. `pip install -r requirements.txt`, `python scripts\check_env.py`, `verify.bat` -> record the counts above.
2. `run_desktop.bat`; Monitoring page: add the local-folder demo mailbox, turn monitoring on, drop `.eml` files into its inbox, close the window, confirm monitoring continues (`python -m emailshield.desktop --status`), reopen, stop with `stop.bat`.
3. Copy your existing `data` folder into a test copy and start it: confirm the `.pre-migration-*.bak` file appears and your INV-00001 case is intact.
4. Gmail test account (docs/GMAIL_OAUTH_TROUBLESHOOTING.md), then `python scripts\oauth_diagnose.py` if blocked.
5. Splunk lab: `python scripts\splunk_verify.py 5` and run the printed search.
6. `build_windows.bat` on Windows; test the installer on a clean VM (install, launch, close window, upgrade over it, uninstall keeping data).
7. `python scripts\benchmark.py 300` and a 1-hour idle run with Task Manager open; note CPU/RAM.
