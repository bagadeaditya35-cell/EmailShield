import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from emailshield import paths
from tests.conftest import ROOT


def run_cli(data_dir):
    env = {**os.environ, "EMAILSHIELD_DATA_DIR": str(data_dir), "PYTHONPATH": str(ROOT)}
    env.pop("EMAILSHIELD_DB", None)
    return subprocess.run([sys.executable, "-m", "emailshield.cli", "scan", str(ROOT / "samples")], cwd=ROOT, env=env,
                          capture_output=True, text=True, check=True).stdout


def test_database_survives_restart_and_duplicates_are_not_readded(tmp_path):
    out1 = run_cli(tmp_path)
    n = sqlite3.connect(tmp_path / "emailshield.db").execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    assert n >= 10 and "duplicate" not in out1
    out2 = run_cli(tmp_path)  # a second, separate process
    assert out2.count("duplicate") == n
    assert sqlite3.connect(tmp_path / "emailshield.db").execute("SELECT COUNT(*) FROM messages").fetchone()[0] == n


def test_dev_data_dir_is_project_data(tmp_path):
    assert paths.default_data_dir(tmp_path) == tmp_path / "data"


def test_installed_app_uses_user_data_dir_and_portable_flag_overrides(tmp_path, monkeypatch):
    exe = tmp_path / "EmailShield.exe"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    monkeypatch.setattr(sys, "platform", "win32")
    assert paths.default_data_dir(Path("x")) == tmp_path / "roaming" / "EmailShield"
    (tmp_path / "portable.flag").write_text("")
    assert paths.default_data_dir(Path("x")) == tmp_path / "data"
