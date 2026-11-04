import logging
import sqlite3

import pytest

from emailshield import db, errors, net, redact


def test_classification_table():
    cases = [(net.RateLimited(42), "rate_limit", True), (net.ConnectionProblem("timed out"), "network", True),
             (net.ConnectionProblem("Gmail HTTP 503"), "provider_error", True), (net.AuthError("revoked"), "auth_required", False),
             (errors.ConfigError("bad"), "config", False), (sqlite3.OperationalError("locked"), "database", True),
             (PermissionError("no"), "permission", False), (ValueError("bad mime"), "malformed", False),
             (OSError("disk"), "io", True), (RuntimeError("?"), "unknown", True)]
    for exc, cat, retry in cases:
        c = errors.classify(exc)
        assert (c.category, c.retryable) == (cat, retry), exc
    assert errors.classify(net.RateLimited(42)).retry_after == 42
    assert errors.classify(net.AuthError("x")).needs_user and errors.classify(errors.ConfigError("x")).needs_user


def test_backoff_is_bounded_jittered_and_monotone():
    lo = [errors.backoff(a, 30, 900, rng=lambda: 0.0) for a in range(12)]
    hi = [errors.backoff(a, 30, 900, rng=lambda: 1.0) for a in range(12)]
    assert lo == sorted(lo) and hi == sorted(hi) and max(hi) == 900 and all(l <= h for l, h in zip(lo, hi))
    assert lo[0] == 15 and hi[0] == 30  # attempt 0: between base/2 and base
    assert errors.backoff(10 ** 6, 30, 900, rng=lambda: 1.0) == 900  # no overflow, still capped
    assert len({errors.backoff(3, 30, 900) for _ in range(20)}) > 1  # real randomness by default


def test_provider_retry_guidance_is_respected_but_capped():
    assert errors.backoff(0, 30, 900, retry_after=120, rng=lambda: 0.0) == 120
    assert errors.backoff(0, 30, 900, retry_after=10 ** 6, rng=lambda: 0.0) == 3600


def test_redaction_patterns_and_registered_secrets():
    text = ("Bearer ya29.A0AfH6SMBx_secret-token  refresh_token=1//0gAbCdEfGhIjKlMnOpQrStUvWxYz  Authorization: Splunk 11111111-2222-3333-4444-555555555555 "
            "https://x.example/cb?code=4/0AbCdEf&state=s")
    out = redact.redact(text)
    for leak in ("ya29.A0AfH6", "1//0gAbCd", "11111111-2222", "4/0AbCdEf"):
        assert leak not in out
    redact.register("my-custom-secret-value")
    assert "my-custom-secret-value" not in redact.redact("error talking to host with my-custom-secret-value")
    assert redact.redact("normal text, 42 items") == "normal text, 42 items"


def test_logging_filter_redacts_and_events_are_sanitized(caplog):
    lg = logging.getLogger("t.redact")
    lg.addFilter(redact.RedactFilter())
    rec = lg.makeRecord("t", logging.INFO, "f", 1, "token is %s", ("ya29.SECRET_VALUE_123",), None)
    assert lg.filter(rec) and "SECRET_VALUE" not in rec.getMessage()
    db.add_event("error", "failed with Bearer ya29.LEAKYTOKEN999 in header")
    db.add_audit("analyst", "x", "client_secret=GOCSPX-abcdef123456")
    assert "LEAKYTOKEN" not in str(db.list_events()) and "GOCSPX" not in str(db.list_audit())
