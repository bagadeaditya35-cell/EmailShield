# Privacy and data handling
EmailShield reads authorized mailboxes **read-only** and stores analysis results locally. Nothing is uploaded unless you configure an integration.

## What is stored (default settings)
| Data | Stored | Notes |
|---|---|---|
| Raw email, attachments | No | parsed in memory then discarded |
| Body text | **No** (default `store_body_chars = 0`) | optional up to 5,000 chars in Settings |
| Recipients (To) | **No** (default) | optional |
| Subject, sender address/domain, Reply-To, authentication results | Yes | needed for alerts and correlation |
| URLs, URL domains, attachment names, SHA-256 hashes | Yes | indicators of compromise |
| Findings, score, ATT&CK ids, engine/ruleset version | Yes | evidence for explainability |
| Provider message id, account id | Yes | needed for idempotency and explicit re-scans |
| OAuth refresh token, client secret, Splunk token | Credential store only | DPAPI/keyring; never shown, logged or exported |
| Audit trail, events | Yes | no secrets; see retention |

## Retention (configurable, applied while the service runs)
Scan records and their alerts: 90 days. Events, audit rows, finished jobs, delivered exports: 365 days. Backups: newest 7. Failed jobs are kept until you retry or the 365-day log retention removes finished ones. Deleting a mailbox keeps its history until retention removes it (delete via retention or by removing the data folder).

## What leaves the computer
- Gmail API calls (read-only) to Google.
- Optional Splunk events: score, findings, domains, hashes, a one-way message reference; **not** body, recipients, subject or full URLs unless you opt in.
- Optional threat-intel lookups (off by default): URLs with query strings removed, and attachment hashes only.

## Your controls
Turn monitoring off per mailbox; Disconnect (revokes the token at Google when reachable); change retention; `EmailShield.exe --forget-credentials`; uninstall with "delete my data".
Not provided: encryption of the database or backups by EmailShield itself (use BitLocker/EFS), per-record deletion, data-subject request tooling.
Any use with real citizen, organizational or government data requires the organization's authorization and a privacy assessment: this document is not one.
