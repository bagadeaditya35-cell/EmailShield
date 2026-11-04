@echo off
REM Stops the background EmailShield engine (monitoring stops; pending work is kept).
call venv\Scripts\activate
python -m emailshield.desktop --stop
