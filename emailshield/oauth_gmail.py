"""Gmail OAuth 2.0 authorization-code flow with PKCE and a one-time, expiring `state` (CSRF protection).
EmailShield never sees a Gmail password; it stores only the refresh token (via secrets_store).
Scope requested: gmail.readonly only."""
import base64
import hashlib
import json
import secrets
import time
from urllib.parse import urlencode

from . import net
from .providers import GMAIL_SCOPE

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
STATE_TTL = 600
_pending = {}


class OAuthError(Exception):
    pass


def start(client_id, redirect_uri, clock=time.time):
    for k in [k for k, v in _pending.items() if v["expires"] < clock()]:
        _pending.pop(k, None)
    state, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    _pending[state] = {"verifier": verifier, "redirect": redirect_uri, "expires": clock() + STATE_TTL}
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return AUTH_URL + "?" + urlencode({
        "client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code", "scope": GMAIL_SCOPE,
        "access_type": "offline", "prompt": "consent", "state": state,
        "code_challenge": challenge, "code_challenge_method": "S256"})


def finish(state, code, client_id, client_secret, http=net.request, clock=time.time):
    """Validate state (single use, not expired), exchange the code. Returns {'refresh_token','access_token'}."""
    entry = _pending.pop(state or "", None)
    if not entry or entry["expires"] < clock():
        raise OAuthError("Authorization request is unknown or expired. Start the connection again.")
    if not code:
        raise OAuthError("Authorization was cancelled or denied.")
    body = urlencode({"code": code, "client_id": client_id, "client_secret": client_secret, "redirect_uri": entry["redirect"],
                      "grant_type": "authorization_code", "code_verifier": entry["verifier"]}).encode()
    try:
        st, _, resp = http("POST", TOKEN_URL, {"Content-Type": "application/x-www-form-urlencoded"}, body, 15)
    except net.ConnectionProblem as e:
        raise OAuthError(f"Could not reach Google: {e}")
    if st != 200:
        raise OAuthError(f"Google rejected the authorization (HTTP {st}).")
    data = json.loads(resp)
    if "refresh_token" not in data:
        raise OAuthError("Google did not return a refresh token. Remove EmailShield from your Google account permissions and connect again.")
    return {"refresh_token": data["refresh_token"], "access_token": data["access_token"]}


def fetch_email(access_token, http=net.request):
    st, _, body = http("GET", "https://gmail.googleapis.com/gmail/v1/users/me/profile", {"Authorization": f"Bearer {access_token}"}, None, 15)
    if st != 200:
        raise OAuthError(f"Could not read the mailbox profile (HTTP {st}).")
    return json.loads(body)["emailAddress"].lower()


HINTS = {
    "access_denied": ("Google refused access. Most common causes: (1) the OAuth consent screen is in 'Testing' and this Google account is not listed under Test users; "
                      "(2) the app is in 'In production' but has not completed Google's verification (gmail.readonly is a restricted scope); "
                      "(3) a Google Workspace admin restricts third-party apps; (4) you pressed Cancel. Fix: Google Cloud Console > APIs & Services > OAuth consent screen > "
                      "add the account as a Test user (or use an Internal app in a Workspace organisation)."),
    "invalid_client": "The client ID/secret is wrong or from another project. Paste the JSON of an OAuth client of type 'Desktop app' from the SAME project that has the Gmail API enabled.",
    "redirect_uri_mismatch": "The redirect address is not allowed for this client. Use a 'Desktop app' client (loopback addresses are allowed automatically) or add the redirect URI shown on the Monitoring page.",
    "invalid_scope": "Google rejected the requested permission. EmailShield asks only for gmail.readonly: enable the Gmail API in the project and add that scope on the consent screen.",
    "admin_policy_enforced": "A Google Workspace administrator blocks this app. Ask the administrator to allow it, or use a personal test account.",
    "org_internal": "The app is restricted to its organisation; sign in with an account of that organisation.",
    "access_blocked": "Google blocked the sign-in because the app is not verified for this account. Add the account as a Test user, or see docs/GMAIL_OAUTH_TROUBLESHOOTING.md.",
}


def explain_error(code, description=""):
    """Plain-language explanation for the error Google put in the redirect. Never echoes the raw description back."""
    code = (code or "").strip().lower()[:60]
    return HINTS.get(code, f"Google reported '{code or 'an error'}'. See docs/GMAIL_OAUTH_TROUBLESHOOTING.md.")
