# Gmail OAuth: "Access blocked" and related errors
EmailShield requests only `https://www.googleapis.com/auth/gmail.readonly`. **Not yet confirmed against a live Google account**: this page is the diagnosis checklist, not a verified fix.

## What the error usually means
"Access blocked: <app> has not completed the Google verification process" / `Error 403: access_denied` is Google refusing the sign-in **before** EmailShield gets any data. To my knowledge (verify in Google's documentation) the common causes are:
1. **Consent screen is in "Testing" and your account is not a Test user.** Fix: Google Cloud Console > APIs & Services > OAuth consent screen (Audience) > Test users > add the exact Gmail address. Up to 100 test users are allowed without verification.
2. **Consent screen is "In production" but unverified.** `gmail.readonly` is a *restricted* scope; public apps need Google's verification (and possibly a security assessment). Switch back to *Testing* for development. Do not try to work around verification.
3. **Wrong project or client.** The OAuth client must be of type **Desktop app**, in the same project where the **Gmail API is enabled**.
4. **Scope missing** from the consent screen configuration (add `gmail.readonly`).
5. **Google Workspace account** where an administrator restricts third-party apps (Admin console > Security > API controls). Use a personal test account or ask the admin. An "Internal" app avoids verification only inside a Workspace organization.
6. **Testing-mode refresh tokens expire after about 7 days** (to my knowledge): EmailShield then shows "Authentication required"; reconnect.

## Tools
- `python scripts\oauth_diagnose.py` prints what EmailShield has stored (client type, redirect URI, scope, accounts) and the checklist above. It cannot read your Google project.
- Monitoring page > **Test connection** performs a read-only profile call and reports the exact error class.
- The callback page translates Google's error code into plain language and records only the code in the audit trail.

## Development vs public distribution
Testing mode (≤100 named test users, weekly re-consent) is enough for a personal or lab deployment. Distributing EmailShield to many users with their own Gmail accounts would require Google's OAuth verification for a restricted scope; each user/organization can instead create their own Google Cloud project and OAuth client, which is what EmailShield's "paste your client JSON" flow is designed for.
