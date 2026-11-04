"""Gmail OAuth configuration diagnostics. Reads what EmailShield has stored locally and prints what to check in Google Cloud Console.
It CANNOT see your Google project settings (consent-screen status, test users); it tells you where to look.
Usage: python scripts/oauth_diagnose.py"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from emailshield import config, db, oauth_gmail, providers, secrets_store  # noqa: E402


def main():
    cid = secrets_store.get("gmail_client_id")
    sec = bool(secrets_store.get("gmail_client_secret"))
    f = config.DATA_DIR / "client_secret.json"
    kind = None
    if f.exists():
        raw = json.loads(f.read_text())
        kind = "installed (Desktop app)" if "installed" in raw else "web" if "web" in raw else "unknown"
        c = raw.get("installed") or raw.get("web") or {}
        cid = cid or c.get("client_id")
        sec = sec or bool(c.get("client_secret"))
    print("EmailShield Gmail OAuth diagnostics\n")
    print(f"client id stored:     {'yes (' + cid.split('-')[0] + '-...)' if cid else 'NO  -> paste your OAuth client JSON on the Monitoring page'}")
    print(f"client secret stored: {'yes' if sec else 'NO'}")
    if kind:
        print(f"client type (file):   {kind}" + ("" if kind.startswith("installed") else "   <-- use a 'Desktop app' client"))
    print(f"scope requested:      {providers.GMAIL_SCOPE}  (read-only; nothing broader is requested)")
    print(f"redirect URI used:    http://127.0.0.1:{config.PORT}/oauth/gmail/callback  (loopback; allowed automatically for Desktop clients)")
    try:
        for a in db.list_accounts():
            if a["provider"] == "gmail":
                print(f"account {a['id']}: status={a['status']} token stored={'yes' if secrets_store.has('gmail_refresh_token:' + a['id']) else 'NO'} last_error={a['last_error_category'] or '-'}")
    except Exception:
        pass
    print("\nIf Google shows 'Access blocked' / 'has not completed the Google verification process', check IN Google Cloud Console:")
    for step in ("Same project as the OAuth client above, with the Gmail API ENABLED  (APIs & Services > Library)",
                 "OAuth consent screen > Publishing status: 'Testing'  -> your Gmail address MUST be listed under 'Test users'",
                 "If status is 'In production' the app needs Google verification for the restricted gmail.readonly scope: switch back to Testing for development",
                 "Scopes on the consent screen include .../auth/gmail.readonly",
                 "Credentials > the client is type 'Desktop app'",
                 "Workspace account? An administrator may block third-party apps (Admin console > Security > API controls)"):
        print("  [ ]", step)
    print("\nPlain-language explanations of Google's error codes:")
    for k in ("access_denied", "invalid_client", "redirect_uri_mismatch"):
        print(f"  {k}: {oauth_gmail.explain_error(k)}")
    print("\nSee docs/GMAIL_OAUTH_TROUBLESHOOTING.md. Nothing here has been checked against Google itself.")


if __name__ == "__main__":
    main()
