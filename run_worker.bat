@echo off
REM Background worker. Usage: run_worker.bat folder   (watches data\inbox)   or   run_worker.bat gmail
call venv\Scripts\activate
python -m emailshield.worker --provider %1 --interval 60
