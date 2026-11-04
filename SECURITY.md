# Security policy

EmailShield is an **experimental** defensive tool. It has not been security-reviewed or approved for confidential or government data.

## Reporting a vulnerability
Please do **not** open a public issue for a security problem. Use GitHub's private "Report a vulnerability" (Security tab) if enabled, or contact the maintainer privately. Include the version (`EmailShield.exe --version`), what you did, and what you expected. **Never include real credentials, tokens, or real emails**: describe or redact them.
You can expect an acknowledgement, but there is no guaranteed response time: this is a student project.

## Supported versions
Only the latest release. There is no long-term support.

## Scope notes
- Read-only mailbox access (Gmail `gmail.readonly`); no actions on mail.
- Local operation: the API listens on 127.0.0.1 and requires a key. See docs/THREAT_MODEL.md and docs/SECURITY_AND_PRIVACY.md.
- Do not use EmailShield on mailboxes you are not authorized to monitor.
