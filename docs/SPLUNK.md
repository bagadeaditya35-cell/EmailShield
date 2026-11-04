# Splunk HEC integration (optional, off by default)
**Setup in Splunk:** Settings > Data inputs > HTTP Event Collector > enable HEC > New Token (name `emailshield`, default sourcetype `emailshield:alert`, an index you choose). Default port 8088 (HTTPS).
**In EmailShield:** Settings page > Splunk: URL (`https://host:8088`), index, tick *Enable*, paste the token, *Save and test connection*. Lab Splunk with a self-signed certificate: untick *Verify TLS certificate* (not for production).
- Token storage: environment variable `SPLUNK_HEC_TOKEN`, else Windows Credential Manager/macOS Keychain if `keyring` is installed (included in requirements-desktop.txt), else a restricted file in the data folder (weakest option). The token is never returned by the API, logged or put in settings.json.
- Test = health check + one event with `synthetic: true`, sourcetype `emailshield:test`.
- Alerts are sent for messages at/above the chosen category. Fields: case_ref, score, category, status, sender_address/domain, reply_to_domain, auth, findings (id/title/points), attack_techniques, url_domains, attachment_sha256, attachment_count, message_sha256. **Not sent by default:** body, recipients, subject, full URLs, attachments (subject and URLs are separate opt-in boxes).
- Reliability (since 2.2): events go through a durable **outbox** (`exports` table) so scanning never waits for Splunk. Each cycle makes one 10 s attempt per event; failures get jittered exponential backoff up to 5 attempts, then stay `failed` (kept, retryable). 400/401/403 are permanent until you fix the configuration. An event counts as **sent only after Splunk answers HTTP 200**. TLS certificates are verified unless you untick the option.
- Deduplication: one event per alert + severity + engine/ruleset version; routine re-syncs and identical re-scans send nothing new.
- Event fields added for automation: provider, severity, alert_id, scan_status, message_ref (one-way hash, no provider id or address), engine_version, ruleset_version.
## Example searches (use `| spath` if fields are not auto-extracted)
```
index=main sourcetype="emailshield:alert" | spath | stats count by category
index=main sourcetype="emailshield:alert" category="High risk" | spath | table _time case_ref score sender_domain "attack_techniques{}"
index=main sourcetype="emailshield:alert" | spath | stats count by sender_domain | sort -count
index=main sourcetype="emailshield:alert" | spath | where attachment_count>0 | table case_ref "attachment_sha256{}"
index=main sourcetype="emailshield:test"
```
**Status:** tested only against a fake HTTP layer. Not yet tested against a real Splunk instance.

## Verification against a real Splunk (not yet done)
`python scripts\splunk_verify.py 5` sends 5 synthetic events (`sourcetype=emailshield:verify`), prints HEC acknowledgement latency and the search that proves they were **indexed** (an HTTP 200 only means accepted). Record the result in docs/TEST_PLAN_AND_RESULTS.md. Until then Splunk delivery is verified only against a fake HTTP layer.
## Operational limits
Outbox bounded at 5000 queued events (`EMAILSHIELD_MAX_OUTBOX`); beyond that new alerts are refused, counted ("dropped") and logged. Dashboard shows queue counts, last/average delivery latency and the age of the oldest waiting event.
