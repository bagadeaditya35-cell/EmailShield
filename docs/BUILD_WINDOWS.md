# Building the Windows executable and installer
**Status: written but NOT built or run.** The author's environment was Linux without internet or Windows, so none of this has been executed. `build_windows.bat` is designed to fail loudly instead of producing a half-working result.
1. Install Python 3.12 (python.org, tick "Add to PATH"). Optional: Inno Setup 6 (https://jrsoftware.org/isinfo.php) for the installer.
2. Command Prompt in the project folder: `build_windows.bat`
3. The script: tests (stops on failure) -> icon + version resource -> PyInstaller -> **runs the built exe with `--selftest`** (starts the real server, analyzes one email through the API, and runs a full monitoring cycle: queue -> worker -> scan -> alert) -> portable zip -> installer (if Inno Setup is found).
4. Outputs: `dist\EmailShield\EmailShield.exe`; `dist_portable\EmailShield-Portable-<ver>.zip`; `dist_installer\EmailShield-Setup-<ver>.exe`.
5. **Test on a clean Windows machine/VM without Python** before sharing: install, launch from Start Menu and desktop shortcut, analyze a sample, close, relaunch, uninstall.
- Shortcuts: the installer creates Start Menu and (optional) desktop shortcuts. Portable build: run `Create-Shortcut.ps1`.
- Uninstall: Settings > Apps > EmailShield (or Start Menu > Uninstall). Your data in `%APPDATA%\EmailShield` is kept; delete that folder for a full wipe.
- No secrets, keys or mail are packaged; the API key is generated on first run in the user's data folder.
- Unsigned executables may trigger SmartScreen/antivirus warnings; code signing is a roadmap item.
