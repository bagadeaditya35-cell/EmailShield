@echo off
REM Dashboard + API on localhost only; picks a free port automatically (default 8731).
call venv\Scripts\activate
python scripts\run_server.py %*
