"""Where user data lives. Dev: <project>/data. Installed Windows app: %APPDATA%\\EmailShield.
Portable build (portable.flag next to the exe): <exe folder>\\data."""
import os
import sys
from pathlib import Path


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def user_data_dir(app="EmailShield") -> Path:
    if sys.platform.startswith("win"):
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / app
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / app
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / app.lower()


def default_data_dir(project_dir: Path) -> Path:
    if is_frozen():
        exe_dir = Path(sys.executable).parent
        return exe_dir / "data" if (exe_dir / "portable.flag").exists() else user_data_dir()
    return project_dir / "data"


def harden_data_dir(path):
    """Owner-only permissions on the data folder and the sensitive files inside it (POSIX). On Windows the folder lives in the
    user's profile and inherits its private ACL; that is documented, not enforced here. Best effort, never raises."""
    if sys.platform.startswith("win"):
        return False
    try:
        os.chmod(path, 0o700)
        for pat in ("*.db", "*.db-wal", "*.db-shm", "*.bak", "secrets.json", "api_key.txt", "*.log", "*.json"):
            for f in Path(path).glob(pat):
                os.chmod(f, 0o600)
        for d in ("backups",):
            if (Path(path) / d).is_dir():
                os.chmod(Path(path) / d, 0o700)
                for f in (Path(path) / d).glob("*"):
                    os.chmod(f, 0o600)
        return True
    except OSError:
        return False
