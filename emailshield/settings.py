"""Non-secret user settings in DATA_DIR/settings.json (secrets are NEVER stored here)."""
import copy
import json
import os
import tempfile

from . import config

DEFAULTS = {
    "worker": {"enabled": False, "provider": "folder", "interval": 60},
    "monitoring": {"poll_seconds": 60, "batch_size": 10, "initial_days": 2, "reconcile_minutes": 60, "max_attempts": 5, "max_queue": 1000},
    "backup": {"enabled": True, "keep": 7},
    "privacy": {"retention_days": config.RETENTION_DAYS, "log_retention_days": 365, "store_body_chars": 0, "store_recipients": False},
    "splunk": {"enabled": False, "url": "", "index": "", "sourcetype": "emailshield:alert", "verify_tls": True,
               "min_category": "Suspicious", "include_urls": False, "include_subject": False},
}
CATEGORIES = ["Suspicious", "High risk"]


def _path():
    return config.DATA_DIR / "settings.json"


def load():
    s = copy.deepcopy(DEFAULTS)
    try:
        saved = json.loads(_path().read_text())
        for sect, vals in saved.items():
            if sect in s and isinstance(vals, dict):
                s[sect].update({k: v for k, v in vals.items() if k in s[sect]})
    except (OSError, ValueError):
        pass
    return s


def validate(section, values):
    d = DEFAULTS[section]
    for k, v in values.items():
        if k not in d:
            raise ValueError(f"Unknown setting: {section}.{k}")
        if type(v) is not type(d[k]):
            raise ValueError(f"{section}.{k} must be {type(d[k]).__name__}")
    if section == "splunk":
        u = values.get("url")
        if u and not u.startswith(("https://", "http://")):
            raise ValueError("Splunk URL must start with https:// or http://")
        if values.get("min_category", "Suspicious") not in CATEGORIES:
            raise ValueError("min_category must be Suspicious or High risk")
    if section == "monitoring":
        ranges = {"poll_seconds": (15, 3600), "batch_size": (1, 50), "initial_days": (1, 30), "reconcile_minutes": (5, 1440), "max_attempts": (1, 10), "max_queue": (10, 100000)}
        for k, v in values.items():
            lo, hi = ranges[k]
            if not lo <= v <= hi:
                raise ValueError(f"monitoring.{k} must be between {lo} and {hi}")
    if section == "backup" and not 1 <= values.get("keep", 7) <= 90:
        raise ValueError("backup.keep must be between 1 and 90")
    if section == "privacy":
        ranges = {"retention_days": (1, 3650), "log_retention_days": (7, 3650), "store_body_chars": (0, 5000)}
        for k, v in values.items():
            if k in ranges and not ranges[k][0] <= v <= ranges[k][1]:
                raise ValueError(f"privacy.{k} must be between {ranges[k][0]} and {ranges[k][1]}")
    if section == "worker":
        if values.get("provider", "folder") not in ("folder", "gmail"):
            raise ValueError("worker.provider must be folder or gmail")
        if not 5 <= values.get("interval", 60) <= 3600:
            raise ValueError("worker.interval must be 5-3600 seconds")


def update(section, values):
    if section not in DEFAULTS:
        raise ValueError("Unknown settings section")
    validate(section, values)
    s = load()
    s[section].update(values)
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=config.DATA_DIR)
    with os.fdopen(fd, "w") as f:
        json.dump(s, f, indent=2)
    os.replace(tmp, _path())
    return s
