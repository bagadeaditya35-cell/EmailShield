# Supported deployment model
**Model A (supported): multi-account, single operator.** One installation serves several mailboxes that belong to, or are authorized for, the local user.
Implemented: separate account records, credentials (per-account secret names), sync checkpoints, queues, retry state, errors and health; one thread per mailbox so a slow, hung, rate-limited or revoked mailbox does not stop the others; per-account queue limit (backpressure); messages unique per mailbox (the same email in two mailboxes is two records); queries and alerts filterable per mailbox; correlation across mailboxes is **off by default** and audited when enabled; disconnect affects only that mailbox.
Tested: with fake mailboxes and fake Gmail HTTP (isolation, concurrency, failure containment). **Not tested with two real Gmail accounts.**
**Model B (multiple independent users on a shared server): NOT implemented and not claimed.** It would need user authentication, roles, tenant separation, per-user secret isolation and a hardened network service. Colleagues who need their own mailboxes should each install EmailShield on their own PC; installations do not share data.
Guarantees (implemented): idempotent jobs, atomic claims, atomic checkpoint+queue. Best effort only: behaviour across power loss mid-write, and exactly-once delivery to Splunk (at-least-once with de-duplication per alert+severity+engine).

## Guarantees and the tests that exercise them
| Guarantee | Status | Evidence |
|---|---|---|
| Each enabled mailbox runs in its own thread; a hung/slow mailbox does not delay others | implemented, **tested** (hung fetch vs healthy account) | tests/test_reliability.py |
| A failing/rate-limited/revoked mailbox does not stop others | implemented, tested | test_isolation.py, test_monitor.py |
| Same email in two mailboxes = two separate records, alerts, jobs | implemented, tested (migration v3) | test_isolation.py |
| Queue claims never cross accounts; no two workers take one job | implemented, tested (4 threads) | test_queue.py |
| Credentials are per account; disconnecting one keeps the others | implemented, tested | test_isolation.py |
| Correlation does not cross mailboxes unless explicitly requested (audited) | implemented, tested | test_isolation.py |
| No duplicate processing within a mailbox | implemented, tested | test_monitor.py |
| Fair scheduling | thread-per-account; no weighted scheduler | best effort |
| Isolation against a malicious operator | **not a goal**: the operator sees all connected mailboxes | - |
All of the above were tested with simulated mailboxes only. Live Gmail with two real accounts has not been tested.
