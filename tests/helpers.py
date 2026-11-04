import base64
import json

from emailshield import net


class Mailbox:
    """Fake connector: a dict of ref -> raw bytes (or an exception/list of exceptions to raise first)."""
    name = "fake"

    def __init__(self, messages=None, account_id="fake:acct", list_error=None):
        self.account_id, self.messages, self.list_error, self.fetch_log = account_id, dict(messages or {}), list_error, []
        self.fetch_errors = {}

    def describe(self):
        return {"provider": self.name}

    def list_new(self):
        if self.list_error:
            raise self.list_error
        return list(self.messages)

    def fetch_raw(self, ref):
        self.fetch_log.append(ref)
        errs = self.fetch_errors.get(ref)
        if errs:
            raise errs.pop(0)
        return self.messages.get(ref)


class FakeGmail:
    """Minimal Gmail REST + OAuth server behind the http(method,url,headers,body,timeout) interface."""

    def __init__(self, raw_by_id=None):
        self.raw = dict(raw_by_id or {})
        self.history = []                  # list of (historyId, [message ids added])
        self.history_id = "100"
        self.listing = list(self.raw)      # what the 'list' endpoint returns
        self.history_expired = False
        self.token_status, self.calls, self.revoked = 200, [], []
        self.statuses = []                 # scripted statuses for the next API calls (None = normal)

    def __call__(self, method, url, headers=None, body=None, timeout=10, **kw):
        self.calls.append((method, url))
        if "oauth2.googleapis.com/token" in url:
            if self.token_status != 200:
                return self.token_status, {}, b'{"error":"invalid_grant"}'
            return 200, {}, json.dumps({"access_token": "ya29.fake", "expires_in": 3600}).encode()
        if "oauth2.googleapis.com/revoke" in url:
            self.revoked.append(body)
            return 200, {}, b"{}"
        if self.statuses:
            st = self.statuses.pop(0)
            if st is not None:
                return st, {"retry-after": "7"}, b"{}"
        if url.endswith("/profile"):
            return 200, {}, json.dumps({"emailAddress": "test@example.org", "historyId": self.history_id}).encode()
        if "/history?" in url:
            if self.history_expired:
                return 404, {}, b"{}"
            return 200, {}, json.dumps({"history": [{"id": h, "messagesAdded": [{"message": {"id": m}} for m in ids]} for h, ids in self.history],
                                        "historyId": self.history_id}).encode()
        if "/messages?" in url:
            return 200, {}, json.dumps({"messages": [{"id": i} for i in self.listing]}).encode()
        if "/messages/" in url:
            mid = url.split("/messages/")[1].split("?")[0]
            if mid not in self.raw:
                return 404, {}, b"{}"
            return 200, {}, json.dumps({"raw": base64.urlsafe_b64encode(self.raw[mid]).decode().rstrip("=")}).encode()
        raise AssertionError(f"unexpected call {method} {url}")
