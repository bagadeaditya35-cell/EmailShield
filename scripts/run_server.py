"""Server-only launcher (no GUI). Cross-platform. Usage: python scripts/run_server.py [--port N]
Uses the same Runtime as the desktop app: free-port search, no duplicate instances, clean Ctrl+C shutdown."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from emailshield.server import find_free_port, port_is_free  # noqa: E402,F401  (re-exported for tests)
from emailshield.desktop import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(["--headless"] + sys.argv[1:]))
