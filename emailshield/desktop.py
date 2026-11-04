"""Desktop launcher: starts the backend safely, shows the dashboard in a native window, and stops cleanly.
Modes: (default) native window via pywebview -> Tk control panel -> headless fallback;
       --headless  server only (Linux servers, services, scripts);   --selftest  start, analyze one email, stop;
       --version."""
import argparse
import json
import logging
import os
import signal
import sys
import tempfile
import threading
import time
import urllib.request
import webbrowser

from . import APP_NAME, __version__, apikey, autostart, config, control, db, server, settings

log = logging.getLogger("emailshield.desktop")


class AlreadyRunning(Exception):
    pass


class Runtime:
    """Owns instance lock + port + server thread + optional worker. Testable with fake uvicorn/app."""

    def __init__(self, app=None, uvicorn_module=None, host=None, worker_factory=None, mode="engine"):
        self._app, self._uv, self.host, self.mode = app, uvicorn_module, host or config.HOST, mode
        self._worker_factory = worker_factory
        self.lock = self.srv = self.worker = self.worker_thread = None
        self.port = None

    @property
    def url(self):
        shown = "127.0.0.1" if self.host in ("0.0.0.0", "::") else self.host
        scheme = "https" if config.TLS_CERT and config.TLS_KEY else "http"
        return f"{scheme}://{shown}:{self.port}"

    @property
    def api_key(self):
        return apikey.get_api_key()

    def start(self):
        server.validate_bind(self.host, config.ALLOW_REMOTE, os.environ.get("EMAILSHIELD_API_KEY"))
        self.lock = server.acquire_instance_lock()
        if self.lock is None:
            raise AlreadyRunning("EmailShield is already running on this computer.")
        try:
            db.init()
            self.port = server.find_free_port(config.PORT, self.host)
            config.PORT = self.port  # the app banner and URLs use the real port
            if self._app is None:
                from .app import app as real_app
                self._app = real_app
            self.srv = server.ServerThread(self._app, self.host, self.port, self._uv, config.TLS_CERT, config.TLS_KEY)
            if not self.srv.start():
                raise RuntimeError(self.srv.error or "Server did not start")
            self._start_worker()
            server.write_instance(self.port, self.mode, self.host)
            log.info("EmailShield %s running at %s", __version__, self.url)
        except Exception:
            self.stop()
            raise

    def _start_worker(self):
        """The monitoring service always runs inside the app but is IDLE (no network, no mailbox access) until a mailbox is
        connected AND monitoring is switched on by the user. It lives outside the dashboard, so closing a browser tab changes nothing."""
        from . import worker
        w = settings.load()["worker"]
        if w["enabled"]:  # legacy setting: watch the local inbox folder
            db.upsert_account("folder:default", "folder", "Local folder", monitoring_enabled=True)
        factory = (lambda acct: self._worker_factory()) if self._worker_factory else None
        self.worker = worker.MonitorService(connector_factory=factory)
        self.worker_thread = threading.Thread(target=self.worker.run, name="emailshield-monitor", daemon=True)
        self.worker_thread.start()

    def stop(self):
        if self.worker:
            self.worker.stop_event.set()
        if self.worker_thread:
            self.worker_thread.join(10)
        if self.srv:
            self.srv.stop()
        if self.lock:
            self.lock.close()
        server.clear_instance()
        self.lock = self.srv = self.worker = self.worker_thread = None


def setup_logging():
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    import logging.handlers
    h = logging.handlers.RotatingFileHandler(config.DATA_DIR / "emailshield.log", maxBytes=1_000_000, backupCount=3)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.getLogger().addHandler(h)
    logging.getLogger().setLevel(logging.INFO)


def _error_box(msg):
    """Show an error without a console (windowed exe); fall back to stderr."""
    try:
        import tkinter
        from tkinter import messagebox
        r = tkinter.Tk()
        r.withdraw()
        messagebox.showerror(APP_NAME, msg)
        r.destroy()
    except Exception:
        print(msg, file=sys.stderr)


def _run_webview(url, key):
    import webview  # type: ignore
    k = json.dumps(key)
    win = webview.create_window(f"{APP_NAME} {__version__}", url, width=1360, height=860, min_size=(1000, 650))
    win.events.loaded += lambda: win.evaluate_js(f"if(sessionStorage.getItem('es_key')!=={k}){{sessionStorage.setItem('es_key',{k});location.reload();}}")
    webview.start()


def _run_tk(url, key, on_stop=None):
    import tkinter as tk
    root = tk.Tk()
    root.title(f"{APP_NAME} {__version__}")
    root.geometry("460x250")
    tk.Label(root, text=f"{APP_NAME} is running", font=("Segoe UI", 14, "bold")).pack(pady=(14, 2))
    tk.Label(root, text=url, fg="#0b5").pack()
    tk.Label(root, text="Closing this window does NOT stop monitoring. Use 'Stop engine' to stop it.", wraplength=420).pack(pady=6)
    row = tk.Frame(root)
    row.pack(pady=6)

    def copy_key():
        root.clipboard_clear()
        root.clipboard_append(key)
        status.config(text="API key copied to clipboard")
    tk.Button(row, text="Open dashboard", command=lambda: webbrowser.open(url)).grid(row=0, column=0, padx=4)
    tk.Button(row, text="Copy API key", command=copy_key).grid(row=0, column=1, padx=4)
    tk.Button(row, text="Close window", command=root.destroy).grid(row=0, column=2, padx=4)
    if on_stop:
        tk.Button(row, text="Stop engine", command=lambda: (on_stop(), root.destroy())).grid(row=0, column=3, padx=4)
    status = tk.Label(root, text="")
    status.pack()
    webbrowser.open(url)
    root.mainloop()


def _run_headless(rt, poll=0.5):
    stop = control.STOP
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, lambda *_: stop.set())
        except ValueError:  # not the main thread (tests)
            pass
    print(f"{APP_NAME} {__version__} running at {rt.url}\nAPI key (paste into the dashboard): {rt.api_key}\nPress Ctrl+C to stop.")
    while not stop.wait(poll):
        pass


# ---------- engine <-> window split ----------
def engine_command():
    """How to start the background engine. EMAILSHIELD_ENGINE_CMD (JSON list) overrides it for diagnostics/tests."""
    if os.environ.get("EMAILSHIELD_ENGINE_CMD"):
        return json.loads(os.environ["EMAILSHIELD_ENGINE_CMD"])
    if getattr(sys, "frozen", False):
        return [sys.executable, "--background"]
    return [sys.executable, "-m", "emailshield.desktop", "--background"]


def spawn_engine():
    """Start the engine detached from this process, so closing the window never stops monitoring."""
    import subprocess
    kw = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "close_fds": True}
    if sys.platform.startswith("win"):
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) | getattr(subprocess, "DETACHED_PROCESS", 0x8) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)
    else:
        kw["start_new_session"] = True
    return subprocess.Popen(engine_command(), **kw)


def attach_or_spawn(timeout=30.0, spawn=spawn_engine, sleep=time.sleep, info_fn=server.engine_info):
    """Return (engine_info, started_it). Reuses a running engine; otherwise starts one and waits until it answers."""
    info = info_fn()
    if info:
        return info, False
    spawn()
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        info = info_fn()
        if info:
            return info, True
        sleep(0.25)
    return None, True


def request_stop(info, key, timeout=10):
    req = urllib.request.Request(info["url"] + "/api/engine/stop", data=json.dumps({"confirm": True}).encode(), method="POST",
                                 headers={"X-API-Key": key, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status == 200


def _cmd_stop(wait=15.0):
    info = server.engine_info()
    if not info:
        print("EmailShield engine is not running.")
        return 0
    try:
        request_stop(info, apikey.get_api_key())
    except Exception as e:
        print(f"Could not stop the engine: {e}", file=sys.stderr)
        return 1
    end = time.monotonic() + wait
    while time.monotonic() < end:
        if not server.engine_info():
            print("EmailShield engine stopped. Pending work is kept and resumes at the next start.")
            return 0
        time.sleep(0.25)
    print("The engine did not stop in time.", file=sys.stderr)
    return 1


def _cmd_status():
    info = server.engine_info()
    print(f"EmailShield engine: {'RUNNING at ' + info['url'] + ' (pid ' + str(info['pid']) + ', since ' + str(info.get('started_at')) + ')' if info else 'not running'}")
    return 0 if info else 3


def _cmd_autostart(mode):
    if not autostart.supported():
        print("Start-with-sign-in is only available on Windows.")
        return 1
    if mode == "on":
        autostart.enable()
    elif mode == "off":
        autostart.disable()
    print(f"Start with Windows sign-in: {'ON' if autostart.is_enabled() else 'OFF'}  ({autostart.command()})")
    return 0


def _win_mutex(name="EmailShieldEngine"):
    """Named mutex so the installer can detect (and ask to close) a running engine. Windows only, best effort."""
    if not sys.platform.startswith("win"):
        return None
    try:
        import ctypes
        return ctypes.windll.kernel32.CreateMutexW(None, False, name)
    except Exception:
        return None


SELFTEST_EML = (b"From: Test <t@example.com>\r\nTo: u@example.org\r\nSubject: monitor selftest\r\nDate: Tue, 27 Oct 2026 09:30:00 +0530\r\n"
                b"Message-ID: <monitor-selftest@synthetic.test>\r\n\r\nUrgent: verify your account at http://203.0.113.9/login now.\r\n")


def monitor_selftest(tmpdir):
    """Exercise the whole monitoring pipeline with a local-folder mailbox: discover -> persistent job -> scan -> alert -> completion.
    Needs no network and no web server, so it also validates that the worker modules are present inside a packaged build."""
    from pathlib import Path
    from . import worker
    inbox = Path(tmpdir) / "monitor-inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    (inbox / "one.eml").write_bytes(SELFTEST_EML)
    db.upsert_account("folder:selftest", "folder", "selftest", monitoring_enabled=True, config_={"path": str(inbox)})
    svc = worker.MonitorService(interval=1)
    svc.start()
    svc.step()
    jobs = db.job_counts("folder:selftest")
    return {"ok": jobs["completed"] >= 1 and jobs["failed"] == 0 and db.stats()["total"] >= 1,
            "completed_jobs": jobs["completed"], "failed_jobs": jobs["failed"], "alerts": db.alert_counts()}


def selftest(out=None):
    """Start the real server, analyze one email through the real API, stop. Used to smoke-test a built executable."""
    tmp = tempfile.mkdtemp(prefix="emailshield-selftest-")
    config.DATA_DIR = type(config.DATA_DIR)(tmp)
    config.DB_PATH = config.DATA_DIR / "selftest.db"
    os.environ.pop("EMAILSHIELD_API_KEY", None)
    config.INSTANCE_PORT = server.find_free_port(config.INSTANCE_PORT + 100)
    rt, result = Runtime(), {"version": __version__}
    try:
        result["monitoring"] = monitor_selftest(tmp)
        rt.start()
        eml = (b"From: Test <t@example.com>\r\nTo: u@example.org\r\nSubject: selftest\r\nDate: Tue, 27 Oct 2026 09:30:00 +0530\r\n"
               b"Message-ID: <selftest@synthetic.test>\r\n\r\nHello. See http://203.0.113.9/login now.\r\n")
        hdr = {"X-API-Key": rt.api_key}
        result["health"] = server.health_ok(rt.url)
        req = urllib.request.Request(rt.url + "/api/analyze?filename=selftest.eml", data=eml, headers=hdr, method="POST")
        result["analyze"] = json.loads(urllib.request.urlopen(req, timeout=10).read())["ok"]
        req = urllib.request.Request(rt.url + "/api/stats", headers=hdr)
        result["stored"] = json.loads(urllib.request.urlopen(req, timeout=10).read())["total"] == 1
        result["stored"] = json.loads(urllib.request.urlopen(urllib.request.Request(rt.url + "/api/stats", headers=hdr), timeout=10).read())["total"] >= 2
        result["ok"] = all(result[k] for k in ("health", "analyze", "stored")) and result["monitoring"]["ok"]
    except Exception as e:
        result.update(ok=False, error=f"{type(e).__name__}: {e}")
    finally:
        rt.stop()
    print(json.dumps(result))
    if out:
        with open(out, "w") as f:
            json.dump(result, f)
    return 0 if result.get("ok") else 1


def _fix_std_streams():
    """A windowed (no-console) executable has sys.stdout/stderr = None; give them a harmless sink."""
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w"))


def main(argv=None):
    _fix_std_streams()
    ap = argparse.ArgumentParser(prog="emailshield")
    ap.add_argument("--background", action="store_true", help="run only the background engine (no window); this is what runs at sign-in")
    ap.add_argument("--embedded", action="store_true", help="run engine AND window in this one process (stops when the window closes)")
    ap.add_argument("--headless", action="store_true", help="engine in this process, foreground console (servers/scripts)")
    ap.add_argument("--stop", action="store_true", help="stop the running engine")
    ap.add_argument("--status", action="store_true", help="show whether the engine is running")
    ap.add_argument("--autostart", choices=["on", "off", "status"], help="start the engine when you sign in to Windows")
    ap.add_argument("--backup", action="store_true", help="create a verified database backup now")
    ap.add_argument("--restore", metavar="FILE", help="restore a backup (the engine must be stopped first)")
    ap.add_argument("--forget-credentials", action="store_true", help="revoke Gmail access and delete stored credentials (used by the uninstaller)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--version", action="store_true")
    ap.add_argument("--out", help="with --selftest: also write the JSON result to this file")
    ap.add_argument("--port", type=int)
    a = ap.parse_args(argv)
    if a.version:
        print(f"{APP_NAME} {__version__}")
        return 0
    if a.selftest:
        return selftest(a.out)
    if a.forget_credentials:
        from . import uninstall
        for r in uninstall.forget_all():
            print(r)
        print("Stored credentials removed.")
        return 0
    if a.backup or a.restore:
        from . import backup
        return backup.main(["create"] if a.backup else ["restore", a.restore])
    if a.stop:
        return _cmd_stop()
    if a.status:
        return _cmd_status()
    if a.autostart:
        return _cmd_autostart(a.autostart)
    if a.port:
        config.PORT = a.port
    setup_logging()
    if not (a.background or a.embedded or a.headless):
        # window only: attach to the engine, starting it detached if it is not running
        info, started = attach_or_spawn()
        if not info:
            _error_box(f"The EmailShield engine did not start. Details: {config.DATA_DIR / 'emailshield.log'}")
            return 1
        key = apikey.get_api_key()
        try:
            _run_webview(info["url"], key)
        except ImportError:
            try:
                _run_tk(info["url"], key, on_stop=_cmd_stop)
            except ImportError:
                webbrowser.open(info["url"])
                print(f"Dashboard: {info['url']}  (API key in {config.DATA_DIR / 'api_key.txt'})")
        return 0  # closing the window leaves the engine (and monitoring) running
    rt = Runtime(mode="background" if a.background else "embedded" if a.embedded else "headless")
    try:
        rt.start()
    except AlreadyRunning as e:
        if a.background:  # started twice (e.g. at sign-in and by the window): that is fine
            log.info("engine already running; nothing to do")
            return 0
        _error_box(f"{e}\nClose the other EmailShield window first (or check Task Manager).")
        return 2
    except server.BindError as e:
        _error_box(f"Cannot start: {e}")
        return 3
    except Exception as e:
        log.exception("startup failed")
        _error_box(f"EmailShield could not start: {e}\nDetails: {config.DATA_DIR / 'emailshield.log'}")
        return 1
    mutex = _win_mutex()  # noqa: F841 (kept alive for the process lifetime)
    try:
        if a.embedded:
            key = rt.api_key
            try:
                _run_webview(rt.url, key)
            except ImportError:
                try:
                    _run_tk(rt.url, key)
                except ImportError:
                    _run_headless(rt)
        else:
            _run_headless(rt)
    finally:
        rt.stop()
        control.STOP.clear()
        log.info("EmailShield stopped cleanly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
