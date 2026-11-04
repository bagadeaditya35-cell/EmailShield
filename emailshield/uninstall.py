"""Credential cleanup used by the uninstaller when the user chooses to delete their data.
Best effort: revokes Gmail access at Google (needs internet), then removes every stored secret. Prints no secret values."""
from . import db, net, providers, secrets_store

SECRET_NAMES = ("gmail_client_id", "gmail_client_secret", "splunk_hec_token")


def forget_all(http=None):
    results = []
    try:
        accounts = [a for a in db.list_accounts() if a["provider"] == "gmail"]
    except Exception:
        accounts = []
    for a in accounts:
        try:
            r = providers.GmailProvider(http=http or net.request, account_id=a["id"]).disconnect()
            results.append({"account": a["id"], "revoked_at_google": r["revoked"], "local_token_removed": True})
        except Exception as e:
            results.append({"account": a["id"], "revoked_at_google": False, "local_token_removed": False, "error": type(e).__name__})
    for n in SECRET_NAMES:
        secrets_store.delete(n)
    return results
