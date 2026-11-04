"""Error classification and retry timing for the monitoring pipeline."""
import random
import sqlite3
from dataclasses import dataclass

from . import net


class ConfigError(Exception):
    """Invalid or missing configuration. Needs a human to fix it; retrying will not help."""


@dataclass(frozen=True)
class Classification:
    category: str
    retryable: bool
    retry_after: float = 0.0
    needs_user: bool = False  # True: show "needs attention" in the dashboard


def classify(exc) -> Classification:
    if isinstance(exc, net.RateLimited):
        return Classification("rate_limit", True, float(exc.retry_after))
    if isinstance(exc, net.AuthError):
        return Classification("auth_required", False, needs_user=True)
    if isinstance(exc, ConfigError):
        return Classification("config", False, needs_user=True)
    if isinstance(exc, net.ConnectionProblem):
        return Classification("provider_error" if "HTTP 5" in str(exc) else "network", True)
    if isinstance(exc, sqlite3.Error) and "full" in str(exc).lower():
        return Classification("disk_full", True)
    if isinstance(exc, sqlite3.Error):
        return Classification("database", True)
    if isinstance(exc, PermissionError):
        return Classification("permission", False, needs_user=True)
    if isinstance(exc, (ValueError, UnicodeError)):
        return Classification("malformed", False)
    if isinstance(exc, OSError):
        return Classification("io", True)
    return Classification("unknown", True)


def backoff(attempt, base=30.0, cap=900.0, retry_after=0.0, rng=random.random, hard_cap=3600.0):
    """Bounded exponential backoff with 'equal jitter'. Provider guidance (retry_after) is respected up to hard_cap."""
    raw = min(cap, base * (2 ** min(max(attempt, 0), 30)))
    delay = raw / 2 + rng() * raw / 2
    if retry_after:
        delay = max(delay, min(retry_after, hard_cap))
    return min(delay, hard_cap if retry_after else cap)
