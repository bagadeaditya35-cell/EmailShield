@echo off
REM Native window (needs: pip install -r requirements-desktop.txt). Falls back to a small control window.
call venv\Scripts\activate
python -m emailshield.desktop %*
