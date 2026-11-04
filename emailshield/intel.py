"""Optional threat-intelligence lookups (VirusTotal, Google Safe Browsing).
Privacy: OFF unless EMAILSHIELD_TI_ENABLED=true. Only URL strings (query stripped by default) and attachment
SHA-256 hashes are sent - never email bodies or attachment files. 'No detections' is NOT proof of safety."""
import base64
import json
import os
import time
from urllib.parse import urlsplit, urlunsplit

from . import config, db, net


class IntelError(Exception):
    pass


def strip_url(url: str) -> str:
    if not config.TI_STRIP_QUERY:
        return url
    s = urlsplit(url)
    return urlunsplit((s.scheme, s.netloc, s.path, "", ""))


class VirusTotal:
    name = "virustotal"
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, key=None, http=net.request, min_interval=None, sleep=time.sleep):
        self.key = key if key is not None else os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.http, self.sleep, self._last = http, sleep, 0.0
        self.min_interval = config.VT_MIN_INTERVAL if min_interval is None else min_interval

    def enabled(self):
        return bool(self.key)

    def _get(self, path):
        wait = self.min_interval - (time.monotonic() - self._last)
        if wait > 0:
            self.sleep(wait)
        self._last = time.monotonic()
        st, h, body = self.http("GET", self.BASE + path, {"x-apikey": self.key}, None, 10)
        if st == 429:
            raise net.RateLimited(int(h.get("retry-after", 60)))
        if st == 404:
            return None
        if st in (401, 403):
            raise IntelError("VirusTotal rejected the API key")
        if st != 200:
            raise IntelError(f"VirusTotal HTTP {st}")
        return json.loads(body)

    @staticmethod
    def _verdict(data):
        if data is None:
            return {"verdict": "not_found", "detail": "Not known to VirusTotal (this is not a clean verdict)"}
        stats = data["data"]["attributes"].get("last_analysis_stats", {})
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        verdict = "malicious" if mal else "suspicious" if sus else "no_detections"
        return {"verdict": verdict, "detail": f"malicious={mal} suspicious={sus} harmless={stats.get('harmless', 0)}"}

    def check_url(self, url):
        uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return self._verdict(self._get(f"/urls/{uid}"))

    def check_hash(self, sha256):
        return self._verdict(self._get(f"/files/{sha256}"))


class SafeBrowsing:
    name = "google_safe_browsing"
    URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(self, key=None, http=net.request):
        self.key = key if key is not None else os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
        self.http = http

    def enabled(self):
        return bool(self.key)

    def check_url(self, url):
        body = json.dumps({
            "client": {"clientId": "emailshield", "clientVersion": "2.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                           "threatEntries": [{"url": url}]}}).encode()
        st, h, resp = self.http("POST", f"{self.URL}?key={self.key}", {"Content-Type": "application/json"}, body, 10)
        if st == 429:
            raise net.RateLimited(int(h.get("retry-after", 60)))
        if st in (400, 401, 403):
            raise IntelError(f"Safe Browsing rejected the request (HTTP {st})")
        if st != 200:
            raise IntelError(f"Safe Browsing HTTP {st}")
        matches = json.loads(resp or b"{}").get("matches", [])
        if matches:
            return {"verdict": "malicious", "detail": ", ".join(sorted({m["threatType"] for m in matches}))}
        return {"verdict": "no_detections", "detail": "No match in Safe Browsing lists (this is not a clean verdict)"}

    def check_hash(self, sha256):
        return None  # not supported by this provider


def default_providers():
    return [p for p in (VirusTotal(), SafeBrowsing()) if p.enabled()]


def enrich(message_id, providers=None, enabled=None):
    """Look up approved indicators for one stored message. Never raises; failures are recorded."""
    if not (config.TI_ENABLED if enabled is None else enabled):
        return {"enabled": False, "note": "Threat intelligence is disabled (local-only mode)."}
    providers = default_providers() if providers is None else providers
    if not providers:
        return {"enabled": True, "providers": [], "note": "TI enabled but no API keys configured."}
    msg = db.get_message(message_id)
    if not msg:
        return {"enabled": True, "error": "not found"}
    inds = msg["analysis"]["indicators"]
    urls = [strip_url(i["value"]) for i in inds if i["type"] == "url"][:config.TI_MAX_URLS]
    hashes = [i["value"] for i in inds if i["type"] == "attachment_sha256"][:config.TI_MAX_URLS]
    done = 0
    for prov in providers:
        blocked = False
        for itype, values, fn in (("url", urls, prov.check_url), ("sha256", hashes, prov.check_hash)):
            for val in dict.fromkeys(values):
                if blocked:
                    break
                cached = db.ti_cache_get(prov.name, val, config.TI_CACHE_TTL)
                try:
                    res = cached or fn(val)
                    if res is None:
                        continue
                    if not cached:
                        db.ti_cache_put(prov.name, val, res)
                except net.RateLimited as e:
                    res, blocked = {"verdict": "error", "detail": f"rate limited, retry after {e.retry_after}s"}, True
                except (IntelError, net.ConnectionProblem) as e:
                    res = {"verdict": "error", "detail": str(e)[:200]}
                    db.add_event("ti_error", f"{prov.name}: {str(e)[:200]}")
                db.ti_result_save(message_id, prov.name, itype, val, res["verdict"], res["detail"], bool(cached))
                done += 1
    return {"enabled": True, "providers": [p.name for p in providers], "lookups": done}
