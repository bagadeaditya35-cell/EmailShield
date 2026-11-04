import socket
import sys

from emailshield import config
from tests.conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import run_server  # noqa: E402


def test_default_port_is_not_8000():
    assert config.PORT != 8000 and config.HOST == "127.0.0.1"


def test_busy_port_is_skipped():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    busy = s.getsockname()[1]
    s.listen(1)
    try:
        assert not run_server.port_is_free(busy)
        assert run_server.find_free_port(busy) != busy
    finally:
        s.close()
