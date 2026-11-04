# Port conflict: find out what is really on port 8000 (Command Prompt, run as normal user)
```
netstat -ano | findstr :8000
tasklist /FI "PID eq <PID from last column>"
```
The process name tells you the owner (e.g. `splunkd.exe` = Splunk). Do not assume. You do NOT need to stop it: EmailShield now defaults to port **8731** and `run.bat` automatically picks the next free port if that is busy (it prints the URL). Override with `run.bat --port 9000` or `set EMAILSHIELD_PORT=9000`. Gmail authorization uses 8766 temporarily.

# Which Python?
- Your real pytest run (58 passed on your setup) shows the core stack (FastAPI, uvicorn, httpx, pytest) worked on your machine. I could not test any Python version myself: my build sandbox has Python 3.12 and no internet.
- Recommendation: **Python 3.12** for building/packaging and for optional extras. Reason: newest Python versions are the last to get prebuilt wheels for compiled packages (`yara-python`, PyInstaller helpers). That is an expectation, not something verified here.
- Keep 3.14 for day-to-day if it works for you. To use both on Windows:
```
py -0p                       (lists installed versions)
py -3.12 -m venv venv312     (needs Python 3.12 installed from python.org)
venv312\Scripts\activate
pip install -r requirements.txt
```
- The project code uses only the standard library plus fastapi, uvicorn, (pytest, httpx for tests), so it should run on 3.10 and newer.

# Dependency check and lock file
`python scripts/check_env.py` reports your Python version and which packages import. After the tests pass on your machine run `python scripts/check_env.py --lock` to write `requirements.lock.txt` (exact versions that worked for you); use it for reproducible installs and builds. Versions are not pinned in the repo because nothing could be installed in the build environment to verify them. To test Python 3.12 in parallel without touching your 3.14 setup: `py -3.12 -m venv venv312`, activate it, `pip install -r requirements.txt`, `python -m pytest -v`.
