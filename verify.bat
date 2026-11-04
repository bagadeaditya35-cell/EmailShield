@echo off
REM One command that checks everything. Run from the project folder in Command Prompt.
call venv\Scripts\activate
python scripts\generate_samples.py
python evaluation\build_dataset.py
python -m pytest -v
python evaluation\run_eval.py
python -m emailshield.cli scan samples
