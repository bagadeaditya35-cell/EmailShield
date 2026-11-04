# Cross-platform notes
| Target | How | Status |
|---|---|---|
| Windows | exe/installer/portable via `build_windows.bat`; browser dashboard | scripts written, NOT built/tested |
| Linux | `python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt && ./run.sh` (server + browser). `build_unix.sh` for a PyInstaller build. GUI window needs GTK/WebKit or Qt libs for pywebview; otherwise use the browser or `--headless` | Core logic tested on Linux (Python 3.12) here; FastAPI server/GUI/build NOT tested |
| macOS | same as Linux; a proper .app/.dmg needs an .icns icon and code signing | untested |
| Android / iPhone / iPad | no native app; open the responsive dashboard in the browser | layout written, NOT tested on devices |
A Windows .exe does not run on Linux/macOS/Android/iOS; each platform needs its own build or the browser.

## Using it from another device (explicit opt-in)
Default is loopback only. To allow your phone on the same network:
`set EMAILSHIELD_ALLOW_REMOTE=true`, `set EMAILSHIELD_HOST=0.0.0.0`, `set EMAILSHIELD_API_KEY=<random 16+ characters>` then `run.bat`. Startup is refused unless all three are set properly. The API always requires the key.
**Plain HTTP exposes the key and data to anyone on that network.** Use a private network/VPN, or TLS: `EMAILSHIELD_TLS_CERT` and `EMAILSHIELD_TLS_KEY` (PEM files). Never forward the port to the internet.
