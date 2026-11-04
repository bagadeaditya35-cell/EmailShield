"""Tiny HTTP helper (stdlib only) with explicit timeouts and typed errors."""
import ssl
import urllib.error
import urllib.request

MAX_READ = 30 * 1024 * 1024


class ConnectionProblem(Exception):
    """Network failure, timeout or 5xx - safe to retry later."""


class RateLimited(Exception):
    def __init__(self, retry_after=60):
        super().__init__(f"rate limited, retry after {retry_after}s")
        self.retry_after = retry_after


class AuthError(Exception):
    """Credentials missing, revoked or rejected - needs human action."""


def request(method, url, headers=None, body=None, timeout=15, verify=True):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        ctx = None if verify else ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(MAX_READ)
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(MAX_READ)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise ConnectionProblem(f"{type(e).__name__}: {e}")
