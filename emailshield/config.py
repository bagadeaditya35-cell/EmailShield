"""EmailShield configuration. Scoring weights and thresholds are heuristic and editable."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
from . import paths

DATA_DIR = Path(os.environ.get("EMAILSHIELD_DATA_DIR") or paths.default_data_dir(BASE_DIR))
DB_PATH = Path(os.environ.get("EMAILSHIELD_DB", DATA_DIR / "emailshield.db"))
MAX_EML_BYTES = int(os.environ.get("EMAILSHIELD_MAX_EML_MB", "10")) * 1024 * 1024
RETENTION_DAYS = int(os.environ.get("EMAILSHIELD_RETENTION_DAYS", "90"))

# Score >= suspicious -> "Suspicious"; score >= high -> "High risk"
THRESHOLDS = {"suspicious": 30, "high": 70}

# Points added once per rule that fires (total capped at 100).
WEIGHTS = {
    "no_sender": 10,
    "reply_to_mismatch": 15,
    "return_path_mismatch": 8,
    "spf_fail": 12,
    "dkim_fail": 10,
    "dmarc_fail": 15,
    "no_auth_results": 0,
    "display_name_impersonation": 20,
    "sender_lookalike_domain": 25,
    "sender_brand_in_domain": 15,
    "url_ip_host": 20,
    "url_punycode": 15,
    "url_shortener": 8,
    "url_suspicious_tld": 8,
    "url_userinfo": 15,
    "url_many_subdomains": 6,
    "url_http": 3,
    "link_text_mismatch": 22,
    "url_brand_in_domain": 15,
    "url_lookalike_domain": 25,
    "kw_urgency": 8,
    "kw_credentials": 15,
    "kw_payment": 12,
    "att_dangerous": 30,
    "att_double_ext": 25,
    "att_macro": 15,
    "att_archive": 8,
    "att_html": 15,
    "malformed_headers": 30,
    "att_type_mismatch": 30,
    "att_yara_match": 35,
}
# Rules in the same group describe overlapping conditions, so each group's contribution is capped.
GROUP_CAPS = {"sender": 40, "auth": 30, "url": 45, "content": 25, "attachment": 50, "structure": 30}

# Optional external threat intelligence. OFF unless explicitly enabled (needs organizational authorization).
TI_ENABLED = os.environ.get("EMAILSHIELD_TI_ENABLED", "false").lower() == "true"
TI_CACHE_TTL = int(os.environ.get("EMAILSHIELD_TI_CACHE_HOURS", "24")) * 3600
TI_STRIP_QUERY = os.environ.get("EMAILSHIELD_TI_STRIP_QUERY", "true").lower() == "true"
TI_MAX_URLS = int(os.environ.get("EMAILSHIELD_TI_MAX_URLS", "10"))
VT_MIN_INTERVAL = float(os.environ.get("EMAILSHIELD_VT_MIN_INTERVAL", "15"))  # free tier ~4 requests/min
YARA_RULES_DIR = Path(os.environ.get("EMAILSHIELD_YARA_DIR", DATA_DIR / "yara_rules"))

# Web server (default avoids 8000, which is commonly used by Splunk and dev servers)
HOST = os.environ.get("EMAILSHIELD_HOST", "127.0.0.1")
ALLOW_REMOTE = os.environ.get("EMAILSHIELD_ALLOW_REMOTE", "false").lower() == "true"
TLS_CERT = os.environ.get("EMAILSHIELD_TLS_CERT", "")
TLS_KEY = os.environ.get("EMAILSHIELD_TLS_KEY", "")
INSTANCE_PORT = int(os.environ.get("EMAILSHIELD_INSTANCE_PORT", "47731"))  # held while the app runs: no duplicate instances
PORT = int(os.environ.get("EMAILSHIELD_PORT", "8731"))

MIN_FREE_MB = int(os.environ.get("EMAILSHIELD_MIN_FREE_MB", "200"))  # monitoring pauses (does not corrupt) below this
MAX_OUTBOX = int(os.environ.get("EMAILSHIELD_MAX_OUTBOX", "5000"))  # Splunk export queue bound

# Background worker
WORKER_INTERVAL = int(os.environ.get("EMAILSHIELD_POLL_SECONDS", "60"))
WORKER_MAX_ATTEMPTS = int(os.environ.get("EMAILSHIELD_MAX_ATTEMPTS", "5"))
INBOX_DIR = Path(os.environ.get("EMAILSHIELD_INBOX", DATA_DIR / "inbox"))

STATUSES = ["new", "investigating", "escalated", "false_positive", "closed"]
