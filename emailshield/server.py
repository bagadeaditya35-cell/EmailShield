"""Server runtime helpers: safe bind rules, free-port search, single-instance lock, clean start/stop."""
import socket
import threading
import time
import urllib.request

from . import config

LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class BindError(Exception):
    pass


def validate_bind(host, allow_remote, key_from_env, tls=False):
    """Loopback is always fine. Anything else needs an explicit opt-in and a strong, explicitly configured key."""
    if host in LOOPBACK:
        return
    if not allow_remote:
        raise BindError(f"Refusing to listen on {host}: set EMAILSHIELD_ALLOW_REMOTE=true to allow network access.")
    if not key_from_env or len(key_from_env) < 16:
        raise BindError("Network access requires EMAILSHIELD_API_KEY set explicitly to at least 16 characters.")


def port_is_free(port, host="127.0.0.1"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host if host not in ("localhost",) else "127.0.0.1", port))
            return True
        except OSError:
            return False


def find_free_port(start, host="127.0.0.1", tries=50):
    for p in range(start, start + tries):
        if port_is_free(p, host):
            return p
    raise BindError(f"No free port found in {start}-{start + tries - 1}")


def acquire_instance_lock(port=None):
    """Hold a loopback socket for the life of the process. Returns the socket, or None if another instance runs."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port or config.INSTANCE_PORT))
        s.listen(1)
        return s
    except OSError:
        s.close()
        return None


def health_ok(url, timeout=2.0):
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/api/health", timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


class ServerThread:
    """Runs uvicorn in a background thread so a GUI (or test) can start and stop it cleanly."""

    def __init__(self, app, host, port, uvicorn_module=None, tls_cert="", tls_key=""):
        if uvicorn_module is None:
            import uvicorn as uvicorn_module
        kw = {"ssl_certfile": tls_cert, "ssl_keyfile": tls_key} if tls_cert and tls_key else {}
        cfg = uvicorn_module.Config(app, host=host, port=port, log_level="warning", log_config=None, **kw)
        self.server = uvicorn_module.Server(cfg)
        self.thread = threading.Thread(target=self.server.run, name="emailshield-server", daemon=True)
        self.error = None

    def start(self, timeout=20):
        self.thread.start()
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if getattr(self.server, "started", False):
                return True
            if not self.thread.is_alive():
                break
            time.sleep(0.05)
        self.error = "Server failed to start in time" if self.thread.is_alive() else "Server stopped during startup"
        return False

    def stop(self, timeout=10):
        self.server.should_exit = True
        self.thread.join(timeout)
        return not self.thread.is_alive()


# ---------- engine instance file (which port/pid is the running engine) ----------
def instance_path():
    return config.DATA_DIR / "instance.json"


def write_instance(port, mode, host=None):
    import json
    import os
    from datetime import datetime, timezone
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    instance_path().write_text(json.dumps({"port": port, "pid": os.getpid(), "mode": mode, "host": host or config.HOST,
                                           "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}))


def read_instance():
    import json
    try:
        return json.loads(instance_path().read_text())
    except (OSError, ValueError):
        return None


def clear_instance():
    try:
        instance_path().unlink()
    except OSError:
        pass


def engine_info():
    """The running engine, or None. A leftover instance file from a crash is ignored because the health check fails."""
    info = read_instance()
    if not info:
        return None
    shown = "127.0.0.1" if info.get("host") in (None, "0.0.0.0", "::") else info["host"]
    url = f"http://{shown}:{info['port']}"
    return {**info, "url": url} if health_ok(url, 2.0) else None
