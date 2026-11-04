# User guide
1. **Email Analysis**: upload one or more `.eml` files. Attachments are hashed and typed in memory, never opened; URLs are never visited.
2. Read the **detection reasons**: each finding shows why it fired, the evidence, its weight and a recommended next step. The score (0-100) is a heuristic; groups of related rules are capped so one condition cannot stack. A low score never proves an email is safe.
3. **MITRE ATT&CK mapping** shows three separate layers: *observed* facts, the engine's *inference*, and *analyst interpretation* (left for you).
4. **Investigation**: search and filter; every message gets a case ID (INV-00001). Set status (new, investigating, escalated, false_positive, closed), write notes. Every change is recorded in the case History and in the audit log.
5. **Related emails** shares URLs, domains, attachment hashes and sender details, with reasons. Matching indicators do not prove one attacker.
6. **Reports**: JSON, HTML or text per case. They contain findings, evidence, ATT&CK mapping, indicators, notes and history; they omit the message body and recipients.
7. **Monitoring**: worker health, last sync, last error, queue (queued/processing/done/failed). **Settings**: Splunk and worker options.
