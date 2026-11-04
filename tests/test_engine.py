import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from emailshield import apikey, config, control, desktop, server


class Engine:
    """A tiny real HTTP server standing in for the engine's API (health + stop)."""

    def __init__(self, key="k"):
        self.stopped, self.seen, outer = threading.Event(), {}, self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200 if self.path == "/api/health" else 404)
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
                outer.seen = {"key": self.headers.get("X-API-Key"), "body": body, "path": self.path}
                ok = self.path == "/api/engine/stop" and self.headers.get("X-API-Key") == key and body.get("confirm") is True
                self.send_response(200 if ok else 401)
                self.end_headers()
                self.wfile.write(b"{}")
                if ok:
                    outer.stopped.set()
                    threading.Thread(target=outer.httpd.shutdown).start()  # the engine goes away after answering

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def test_no_instance_file_means_no_engine():
    assert server.engine_info() is None


def test_stale_instance_file_after_a_crash_is_ignored():
    server.write_instance(1, "background")  # nothing listens on port 1
    assert server.read_instance()["pid"] and server.engine_info() is None


def test_running_engine_is_found_via_health_check():
    e = Engine()
    try:
        server.write_instance(e.port, "background")
        info = server.engine_info()
        assert info and info["url"] == f"http://127.0.0.1:{e.port}" and info["mode"] == "background" and info["started_at"]
    finally:
        e.close()


def test_window_reuses_a_running_engine_and_does_not_start_a_second_one():
    spawned = []
    info, started = desktop.attach_or_spawn(spawn=lambda: spawned.append(1), info_fn=lambda: {"url": "http://x"})
    assert info == {"url": "http://x"} and started is False and spawned == []


def test_window_starts_the_engine_when_missing_and_waits_for_it():
    state = {"up": False, "calls": 0}

    def info_fn():
        state["calls"] += 1
        return {"url": "http://x"} if state["up"] else None
    info, started = desktop.attach_or_spawn(spawn=lambda: state.update(up=True), info_fn=info_fn, sleep=lambda s: None)
    assert info and started is True


def test_window_gives_up_cleanly_if_the_engine_never_appears():
    info, started = desktop.attach_or_spawn(timeout=0.2, spawn=lambda: None, info_fn=lambda: None, sleep=lambda s: __import__("time").sleep(0.05))
    assert info is None and started is True


def test_stop_command_authenticates_confirms_and_waits_for_the_engine_to_go(monkeypatch, capsys):
    monkeypatch.setenv("EMAILSHIELD_API_KEY", "k")
    e = Engine("k")
    try:
        server.write_instance(e.port, "background")
        assert desktop._cmd_stop(wait=10) == 0
        assert e.stopped.is_set() and e.seen["key"] == "k" and e.seen["body"] == {"confirm": True}
        assert "stopped" in capsys.readouterr().out
    finally:
        e.close()


def test_stop_with_a_wrong_key_is_refused_and_reported(monkeypatch, capsys):
    monkeypatch.setenv("EMAILSHIELD_API_KEY", "wrong")
    e = Engine("k")
    try:
        server.write_instance(e.port, "background")
        assert desktop._cmd_stop(wait=1) == 1 and not e.stopped.is_set()
    finally:
        e.close()


def test_stop_when_nothing_runs_is_a_harmless_success(capsys):
    assert desktop._cmd_stop() == 0 and "not running" in capsys.readouterr().out
    assert desktop._cmd_status() == 3


def test_engine_main_loop_obeys_the_stop_flag_without_signals():
    class RT:
        url, api_key = "http://x", "k"
    control.STOP.clear()
    t = threading.Thread(target=desktop._run_headless, args=(RT(), 0.02))
    t.start()
    assert t.is_alive()
    control.STOP.set()
    t.join(5)
    control.STOP.clear()
    assert not t.is_alive()


def test_engine_command_override_and_default(monkeypatch):
    assert desktop.engine_command()[-1] == "--background"
    monkeypatch.setenv("EMAILSHIELD_ENGINE_CMD", json.dumps(["python", "x.py", "--background"]))
    assert desktop.engine_command() == ["python", "x.py", "--background"]


def test_api_key_helper_needs_no_web_framework_and_is_private(tmp_path, monkeypatch):
    monkeypatch.delenv("EMAILSHIELD_API_KEY", raising=False)
    k = apikey.get_api_key()
    assert len(k) >= 24 and apikey.get_api_key() == k  # generated once, then stable
    import os, sys
    if not sys.platform.startswith("win"):
        assert oct(os.stat(config.DATA_DIR / "api_key.txt").st_mode & 0o777) == "0o600"
