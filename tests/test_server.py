import json
import socket
import threading
import time

import pytest

from emailshield import config, db, server, settings
from emailshield.desktop import AlreadyRunning, Runtime


class FakeUvicorn:
    """Stands in for uvicorn: Server.run() flips `started`, then waits for should_exit."""
    crash = False

    class Config:
        def __init__(self, app, host, port, log_level="warning", log_config="x", **kw):
            self.app, self.host, self.port, self.kw = app, host, port, kw

    class Server:
        def __init__(self, cfg):
            self.config, self.started, self.should_exit = cfg, False, False

        def run(self):
            if FakeUvicorn.crash:
                raise RuntimeError("bind failed")
            self.started = True
            while not self.should_exit:
                time.sleep(0.01)


class IdleProvider:
    name = "fake"

    def list_new(self):
        return []

    def fetch_raw(self, ref):
        return None


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(autouse=True)
def isolated_ports(monkeypatch):
    FakeUvicorn.crash = False
    monkeypatch.setattr(config, "INSTANCE_PORT", free_port())
    monkeypatch.setattr(config, "PORT", free_port())


def rt(**kw):
    return Runtime(app=object(), uvicorn_module=FakeUvicorn, **kw)


def test_loopback_is_always_allowed():
    for h in ("127.0.0.1", "::1", "localhost"):
        server.validate_bind(h, False, None)


def test_network_binding_needs_explicit_opt_in_and_strong_key():
    with pytest.raises(server.BindError):
        server.validate_bind("0.0.0.0", False, "x" * 32)
    with pytest.raises(server.BindError):
        server.validate_bind("0.0.0.0", True, None)
    with pytest.raises(server.BindError):
        server.validate_bind("0.0.0.0", True, "short")
    server.validate_bind("0.0.0.0", True, "x" * 16)


def test_busy_port_is_skipped_and_url_is_correct():
    busy = socket.socket()
    busy.bind(("127.0.0.1", 0))
    busy.listen(1)
    config.PORT = busy.getsockname()[1]
    r = rt()
    r.start()
    try:
        assert r.port != busy.getsockname()[1] and str(r.port) in r.url and config.PORT == r.port
        assert busy.fileno() != -1  # we never touched the other process's socket
    finally:
        r.stop()
        busy.close()


def test_no_duplicate_instances_and_lock_released_on_stop():
    a = rt()
    a.start()
    with pytest.raises(AlreadyRunning):
        rt().start()
    a.stop()
    b = rt()
    b.start()
    b.stop()


def test_failed_start_releases_lock_and_reports_error():
    FakeUvicorn.crash = True
    with pytest.raises(RuntimeError):
        rt().start()
    FakeUvicorn.crash = False
    ok = rt()
    ok.start()
    ok.stop()


def test_clean_shutdown_stops_server_thread_and_removes_instance_file():
    r = rt()
    r.start()
    inst = config.DATA_DIR / "instance.json"
    assert json.loads(inst.read_text())["port"] == r.port
    t = r.srv.thread
    r.stop()
    assert not t.is_alive() and not inst.exists()


def test_monitor_service_is_idle_until_a_mailbox_is_enabled_and_stops_with_the_app():
    r = rt(worker_factory=IdleProvider)
    r.start()
    assert r.worker_thread.is_alive() and db.list_accounts() == []  # running but idle: nothing is watched, nothing is contacted
    wt = r.worker_thread
    r.stop()
    assert not wt.is_alive() and db.monitoring()["worker"]["state"] == "stopped"
    settings.update("worker", {"enabled": True, "interval": 5})  # legacy setting: watch the local inbox folder
    r2 = rt(worker_factory=IdleProvider)
    r2.start()
    try:
        assert r2.worker_thread.is_alive() and db.get_account("folder:default")["monitoring_enabled"]
    finally:
        wt = r2.worker_thread
        r2.stop()
    assert not wt.is_alive() and db.monitoring()["worker"]["state"] == "stopped" and db.monitoring()["health"] == "stopped"


def test_remote_bind_refused_by_runtime(monkeypatch):
    monkeypatch.delenv("EMAILSHIELD_API_KEY", raising=False)
    with pytest.raises(server.BindError):
        Runtime(app=object(), uvicorn_module=FakeUvicorn, host="0.0.0.0").start()


def test_tls_options_are_passed_to_server(monkeypatch):
    monkeypatch.setattr(config, "TLS_CERT", "c.pem")
    monkeypatch.setattr(config, "TLS_KEY", "k.pem")
    r = rt()
    r.start()
    try:
        assert r.srv.server.config.kw == {"ssl_certfile": "c.pem", "ssl_keyfile": "k.pem"} and r.url.startswith("https://")
    finally:
        r.stop()
