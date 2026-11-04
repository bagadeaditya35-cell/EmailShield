"""API key handling without importing the web framework (so the CLI can use it)."""
import os
import secrets

from . import config


def get_api_key() -> str:
    """EMAILSHIELD_API_KEY wins; otherwise a random key is generated once into data/api_key.txt (owner-only where supported)."""
    env = os.environ.get("EMAILSHIELD_API_KEY")
    if env:
        return env
    f = config.DATA_DIR / "api_key.txt"
    if not f.exists():
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        f.write_text(secrets.token_urlsafe(24))
        try:
            os.chmod(f, 0o600)
        except OSError:
            pass
    return f.read_text().strip()
