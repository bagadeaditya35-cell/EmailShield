"""One-time Gmail authorization (read-only scope) using the OAuth loopback flow. Stdlib only.
Setup: Google Cloud Console -> create project -> enable Gmail API -> OAuth consent (Testing; add YOUR TEST account
as a test user) -> Credentials -> OAuth client ID -> Desktop app -> download JSON as data/client_secret.json.
Then run:  python scripts\\gmail_auth.py   (a browser opens; sign in with the TEST mailbox only).
The refresh token is saved to data/gmail_token.json - never paste it anywhere."""
import json
import secrets
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from emailshield import config, net  # noqa: E402
from emailshield.providers import GMAIL_SCOPE  # noqa: E402

PORT = 8766  # distinct from the dashboard port (8731 by default)


def main():
    cf = config.DATA_DIR / "client_secret.json"
    if not cf.exists():
        sys.exit(f"Missing {cf}. See the instructions at the top of this script.")
    c = json.loads(cf.read_text())
    c = c.get("installed") or c.get("web") or c
    state, box = secrets.token_urlsafe(16), {}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            q = parse_qs(urlparse(self.path).query)
            box["code"], box["state"] = q.get("code", [""])[0], q.get("state", [""])[0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"EmailShield authorized. You can close this tab.")

        def log_message(self, *a):
            pass

    url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode({
        "client_id": c["client_id"], "redirect_uri": f"http://127.0.0.1:{PORT}", "response_type": "code",
        "scope": GMAIL_SCOPE, "access_type": "offline", "prompt": "consent", "state": state})
    print("Opening browser. If it does not open, visit:\n", url)
    webbrowser.open(url)
    srv = HTTPServer(("127.0.0.1", PORT), H)
    srv.handle_request()
    if box.get("state") != state or not box.get("code"):
        sys.exit("Authorization failed or was cancelled.")
    body = urlencode({"code": box["code"], "client_id": c["client_id"], "client_secret": c["client_secret"],
                      "redirect_uri": f"http://127.0.0.1:{PORT}", "grant_type": "authorization_code"}).encode()
    st, _, resp = net.request("POST", "https://oauth2.googleapis.com/token", {"Content-Type": "application/x-www-form-urlencoded"}, body)
    data = json.loads(resp)
    if st != 200 or "refresh_token" not in data:
        sys.exit(f"Token exchange failed (HTTP {st}).")
    tf = config.DATA_DIR / "gmail_token.json"
    tf.write_text(json.dumps({"refresh_token": data["refresh_token"]}))
    print(f"Saved {tf}. Scope granted: read-only Gmail. Start the worker with:  python -m emailshield.worker --provider gmail")


if __name__ == "__main__":
    main()
