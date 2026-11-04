"""Secret redaction for logs, events, audit entries and stored error text."""
import logging
import re

_PATTERNS = [
    (re.compile(r"ya29\.[A-Za-z0-9_\-\.]+"), "[REDACTED_ACCESS_TOKEN]"),
    (re.compile(r"1//[A-Za-z0-9_\-]{20,}"), "[REDACTED_REFRESH_TOKEN]"),
    (re.compile(r"(?i)\b(bearer|splunk)\s+[A-Za-z0-9\-_\.=]{8,}"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)([?&](?:key|code|token|access_token|refresh_token|client_secret)=)[^&\s]+"), r"\1[REDACTED]"),
    (re.compile(r'(?i)("?(?:refresh_token|access_token|client_secret|api[_-]?key|authorization)"?\s*[:=]\s*"?)([^"\s,&}]+)'), r"\1[REDACTED]"),
]
_known = set()


def register(secret):
    """Remember an exact secret value so it is masked wherever it appears."""
    if secret and len(secret) >= 6:
        _known.add(secret)


def redact(text):
    s = str(text)
    for secret in sorted(_known, key=len, reverse=True):
        s = s.replace(secret, "[REDACTED]")
    for pat, rep in _PATTERNS:
        s = pat.sub(rep, s)
    return s


class RedactFilter(logging.Filter):
    def filter(self, record):
        record.msg = redact(record.getMessage())
        record.args = ()
        return True
