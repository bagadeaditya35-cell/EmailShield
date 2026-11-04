#!/bin/sh
# Linux / macOS build (UNVERIFIED - written without access to those systems). Needs Python 3.10+ and internet once.
set -e
python3 -m venv venv_build && . venv_build/bin/activate
pip install -r requirements.txt -r requirements-desktop.txt
python scripts/generate_samples.py && python evaluation/build_dataset.py && python -m pytest -q
pyinstaller --noconfirm --clean packaging/emailshield.spec
./dist/EmailShield/EmailShield --selftest --out dist/selftest.json && cat dist/selftest.json
echo "Built dist/EmailShield (not an installer). Linux GUI needs pywebview deps (GTK/WebKit or Qt) - or use --headless."
