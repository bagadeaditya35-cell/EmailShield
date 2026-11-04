# Windows installation (EmailShield 2.2, EXPERIMENTAL)
**Status: the installer has never been built or run.** Build it with `build_windows.bat` on Windows (see BUILD_WINDOWS.md), then test on a clean machine before giving it to anyone.
## Install / upgrade
Run `EmailShield-Setup.exe` (no administrator needed; per-user install under `%LOCALAPPDATA%\Programs\EmailShield`). The build is **unsigned**: Windows SmartScreen will warn ("unknown publisher"); verify the SHA-256 in `SHA256SUMS.txt` before running. Upgrades stop the running engine, replace program files, and never touch your data (`%APPDATA%\EmailShield`).
## How background monitoring works
- **EmailShield** (Start menu) opens the dashboard window. If the background **engine** is not running, it starts one (hidden, per-user). Closing the window does **not** stop monitoring.
- Monitoring runs only while the engine runs: it pauses when you sign out, shut down, sleep, or lose the network, and resumes from its checkpoints when the engine runs again. Without "Start with Windows" the engine starts when you next open EmailShield.
- Optional **Start with Windows** (Monitoring page, off by default) adds a visible per-user startup entry that starts only the engine at sign-in. It does not run before sign-in (a service was deliberately not chosen: credentials, OAuth consent and DPAPI are per-user, and it would need administrator rights).
## Stop / restart
Monitoring page > Stop engine, or Start menu > "Stop EmailShield engine", or `EmailShield.exe --stop`. Status: `EmailShield.exe --status`. Restart: open EmailShield.
## Uninstall
Settings > Apps, or the Start menu entry. You are asked whether to delete your data; the default is **No** (kept) and silent uninstalls always keep it. Choosing Yes revokes Gmail access (if online), removes stored credentials, and deletes `%APPDATA%\EmailShield`. Credentials in Windows Credential Manager are removed by that step.
## Troubleshooting
Logs: `%APPDATA%\EmailShield\emailshield.log` and `worker.log` (tokens are redacted). Setup log: run the installer with `/LOG=setup.log`. If the window does not open, run `EmailShield.exe --status`; WebView2 runtime missing -> a small control window opens instead.
