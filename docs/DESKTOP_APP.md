# Desktop application
**Design choice:** the desktop app reuses the same backend and dashboard inside a native window (pywebview, which uses Microsoft Edge WebView2 on Windows) instead of re-implementing every page in Qt. One code path, no duplicated logic, and the browser dashboard keeps working. Trade-off: it needs the WebView2 runtime (present on current Windows 10/11; free installer from Microsoft otherwise).

Startup order (`emailshield/desktop.py`): validate bind settings -> take the single-instance lock -> choose a free port -> start the server thread -> optionally start the worker -> open the window and sign in automatically. Closing the window stops the worker, the server and releases the lock.
Fallbacks: no pywebview -> small Tk control window + your browser; no Tk -> headless. `--headless` runs the server only; `--selftest` starts, analyzes one email, stops (used by the build); `--version`.
Errors appear in a message box (and `emailshield.log` in the data folder). Data locations: dev `data\`; installed `%APPDATA%\EmailShield`; portable `data\` beside the exe (when `portable.flag` exists).
**Verification status:** launcher logic is tested with a fake server and as a real OS process with a stub server; the native window itself, WebView2 and the real server inside the exe are NOT yet verified.
