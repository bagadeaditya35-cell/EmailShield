"""Mailbox providers for the background worker. Each provider only READS mail.
FolderProvider: watch a local folder for .eml files (works offline, ideal for demos/tests).
GmailProvider: official Gmail REST API, read-only scope, OAuth2 refresh-token flow, polling."""
import base64
import json
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode

from . import config, net, redact, secrets_store

GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


class HistoryExpired(Exception):
    """Gmail no longer has history for our checkpoint; a full resync is required."""


@dataclass
class ChangeSet:
    refs: list = field(default_factory=list)
    state: dict = field(default_factory=dict)   # new checkpoint, committed together with the queued jobs
    initial: bool = False                       # True for the first synchronization of an account
    reconciled: bool = False                    # True when a full listing was used (first sync, expiry, periodic)


class MailConnector:
    """Interface every mailbox connector implements (Gmail today; Microsoft Graph is planned, NOT implemented).
    name/account_id identify the source; all methods are read-only with respect to the mailbox."""
    name = ""
    account_id = ""

    def describe(self): ...
    def validate(self): ...            # raises net.AuthError / ConnectionProblem; returns {"ok": True, ...}
    def discover(self, state): ...     # -> ChangeSet: new/changed message refs + next checkpoint
    def fetch_raw(self, ref): ...      # -> bytes | None (None = message no longer exists)
    def disconnect(self): ...          # revoke/forget credentials; returns {"revoked": bool}


class FolderProvider(MailConnector):
    name = "folder"
    account_id = "folder:default"

    def __init__(self, path=None):
        self.path = (path or config.INBOX_DIR)

    def validate(self):
        self.path.mkdir(parents=True, exist_ok=True)
        return {"ok": True, "location": str(self.path)}

    def discover(self, state):
        return ChangeSet(self.list_new(), dict(state), initial=not state.get("seen"), reconciled=True)

    def disconnect(self):
        return {"revoked": False}

    def describe(self):
        return {"provider": self.name, "location": str(self.path)}

    def list_new(self):
        self.path.mkdir(parents=True, exist_ok=True)
        return [f"{p.name}|{p.stat().st_mtime_ns}" for p in sorted(self.path.glob("*.eml")) if p.is_file()]

    def fetch_raw(self, ref):
        name = ref.split("|", 1)[0]
        if "/" in name or "\\" in name or name.startswith("."):
            raise ValueError("invalid file reference")
        p = self.path / name
        return p.read_bytes() if p.is_file() else None


class GmailProvider(MailConnector):
    name = "gmail"
    API = "https://gmail.googleapis.com/gmail/v1/users/me"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    REVOKE_URL = "https://oauth2.googleapis.com/revoke"

    def __init__(self, http=net.request, client_file=None, token_file=None,
                 query="in:inbox newer_than:2d", max_results=50, max_pages=3, clock=time.time,
                 account_id="gmail:default", reconcile_seconds=3600, max_history_pages=20):
        self.http, self.clock, self.account_id = http, clock, account_id
        self.client_file = client_file or config.DATA_DIR / "client_secret.json"
        self.token_file = token_file or config.DATA_DIR / "gmail_token.json"
        self.query, self.max_results, self.max_pages = query, max_results, max_pages
        self.reconcile_seconds, self.max_history_pages = reconcile_seconds, max_history_pages
        self._access, self._exp = None, 0

    def describe(self):
        return {"provider": self.name, "scope": GMAIL_SCOPE, "query": self.query}

    def _creds(self):
        """Legacy files (scripts/gmail_auth.py) are honoured; otherwise the dashboard flow's secret store is used."""
        try:
            if self.client_file.exists() and self.token_file.exists():
                c = json.loads(self.client_file.read_text())
                c = c.get("installed") or c.get("web") or c
                cid, sec, refresh = c["client_id"], c["client_secret"], json.loads(self.token_file.read_text())["refresh_token"]
            else:
                cid, sec = secrets_store.get("gmail_client_id"), secrets_store.get("gmail_client_secret")
                refresh = secrets_store.get(f"gmail_refresh_token:{self.account_id}")
            if not (cid and sec and refresh):
                raise KeyError("missing")
        except (OSError, KeyError, ValueError):
            raise net.AuthError("Gmail is not authorized. Connect the mailbox from the Monitoring page.")
        for secret in (sec, refresh):
            redact.register(secret)
        return cid, sec, refresh

    def _access_token(self):
        if self._access and self.clock() < self._exp - 60:
            return self._access
        cid, secret, refresh = self._creds()
        body = urlencode({"client_id": cid, "client_secret": secret, "refresh_token": refresh,
                          "grant_type": "refresh_token"}).encode()
        st, h, resp = self.http("POST", self.TOKEN_URL, {"Content-Type": "application/x-www-form-urlencoded"}, body, 15)
        if st in (400, 401):
            raise net.AuthError("Gmail refresh token rejected (revoked or expired). Re-run scripts/gmail_auth.py")
        if st == 429:
            raise net.RateLimited(int(h.get("retry-after", 60)))
        if st != 200:
            raise net.ConnectionProblem(f"token endpoint HTTP {st}")
        data = json.loads(resp)
        self._access, self._exp = data["access_token"], self.clock() + int(data.get("expires_in", 3600))
        return self._access

    def _get(self, path, params=None, _retry=True):
        url = self.API + path + ("?" + urlencode(params) if params else "")
        st, h, body = self.http("GET", url, {"Authorization": f"Bearer {self._access_token()}"}, None, 20)
        if st == 401 and _retry:
            self._access = None
            return self._get(path, params, False)
        if st == 401:
            raise net.AuthError("Gmail rejected the access token")
        if st == 429 or (st == 403 and b"ateLimit" in body):
            raise net.RateLimited(int(h.get("retry-after", 60)))
        if st == 404:
            return None
        if st >= 500:
            raise net.ConnectionProblem(f"Gmail HTTP {st}")
        if st != 200:
            raise net.ConnectionProblem(f"Gmail unexpected HTTP {st}")
        return json.loads(body)

    # ----- connector interface -----
    def profile(self):
        return self._get("/profile") or {}

    def validate(self):
        p = self.profile()
        return {"ok": True, "email": p.get("emailAddress"), "history_id": p.get("historyId")}

    def _history(self, start):
        refs, token, latest = [], None, None
        for _ in range(self.max_history_pages):
            params = {"startHistoryId": start, "historyTypes": "messageAdded", "labelId": "INBOX", "maxResults": 100}
            if token:
                params["pageToken"] = token
            data = self._get("/history", params)
            if data is None:
                raise HistoryExpired()
            for h in data.get("history", []):
                refs += [m["message"]["id"] for m in h.get("messagesAdded", [])]
            latest = data.get("historyId", latest)
            token = data.get("nextPageToken")
            if not token:
                return list(dict.fromkeys(refs)), latest
        raise HistoryExpired()  # too much to page through safely: fall back to a bounded full listing

    def discover(self, state):
        """Incremental sync via users.history (cheap). First sync, expired history and the periodic reconciliation use a
        bounded listing instead. The new checkpoint is returned, not saved: the caller commits it with the queued jobs."""
        hid, now_ts, refs, new = state.get("history_id"), self.clock(), [], dict(state)
        initial = not hid
        full = initial
        if hid:
            try:
                refs, latest = self._history(hid)
                new["history_id"] = latest or hid
            except HistoryExpired:
                full = True
            if now_ts - state.get("last_reconcile", 0) >= self.reconcile_seconds:
                full = True
        if full:
            prof = self.profile()  # read the checkpoint BEFORE listing so mail arriving meanwhile is not missed
            refs = list(dict.fromkeys(refs + self.list_new()))
            new.update(history_id=prof.get("historyId") or hid, last_reconcile=now_ts)
        return ChangeSet(refs, new, initial=initial, reconciled=full)

    def disconnect(self):
        revoked = False
        try:
            token = secrets_store.get(f"gmail_refresh_token:{self.account_id}")
            if token:
                st, _, _ = self.http("POST", self.REVOKE_URL, {"Content-Type": "application/x-www-form-urlencoded"},
                                     urlencode({"token": token}).encode(), 15)
                revoked = st == 200
        except net.ConnectionProblem:
            pass
        secrets_store.delete(f"gmail_refresh_token:{self.account_id}")
        self._access = None
        return {"revoked": revoked}

    def list_new(self):
        refs, token = [], None
        for _ in range(self.max_pages):
            params = {"q": self.query, "maxResults": self.max_results}
            if token:
                params["pageToken"] = token
            data = self._get("/messages", params) or {}
            refs += [m["id"] for m in data.get("messages", [])]
            token = data.get("nextPageToken")
            if not token:
                break
        return refs

    def fetch_raw(self, ref):
        data = self._get(f"/messages/{ref}", {"format": "raw"})
        if data is None:
            return None
        raw = data["raw"]
        return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
