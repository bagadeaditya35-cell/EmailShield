import subprocess
import sys

import pytest

from emailshield import config, db

ROOT = config.BASE_DIR


@pytest.fixture(scope="session", autouse=True)
def _samples():
    subprocess.run([sys.executable, str(ROOT / "scripts" / "generate_samples.py")], check=True, capture_output=True)
    subprocess.run([sys.executable, str(ROOT / "evaluation" / "build_dataset.py")], check=True, capture_output=True)


@pytest.fixture(autouse=True)
def tmpdb(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    db.init()


def sample(name: str) -> bytes:
    return (ROOT / "samples" / f"{name}.eml").read_bytes()
