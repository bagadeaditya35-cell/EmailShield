import sqlite3
import threading

import pytest

from emailshield import config, db, ingest
from tests.conftest import sample


def force(jid, **cols):
    c = sqlite3.connect(config.DB_PATH)
    c.execute(f"UPDATE jobs SET {', '.join(f'{k}=?' for k in cols)} WHERE id=?", [*cols.values(), jid])
    c.commit()


def test_duplicate_jobs_are_prevented_and_rescans_are_explicit():
    assert db.enqueue_job("gmail", "m1", "a") is True and db.enqueue_job("gmail", "m1", "a") is False
    assert db.enqueue_job("gmail", "m1", "b") is True  # another account is another job
    assert db.enqueue_job("gmail", "m1", "a", engine_version="2.2") is True  # explicit re-scan with a new engine version
    assert len(db.list_jobs()) == 3


def test_routine_sync_never_requeues_an_already_scanned_message():
    ingest.ingest_bytes(sample("01_benign_newsletter"), "x.eml", "gmail", "a", "m-scanned")
    assert db.enqueue_job("gmail", "m-scanned", "a") is False
    assert db.enqueue_job("gmail", "m-scanned", "a", engine_version="9.9") is True  # but an explicit re-scan is allowed


def test_claims_are_atomic_across_concurrent_workers():
    for i in range(40):
        db.enqueue_job("gmail", f"m{i}", "a")
    got, lock = [], threading.Lock()

    def grab(name):
        while True:
            jobs = db.claim_jobs("gmail", "a", name, limit=3)
            if not jobs:
                return
            with lock:
                got.extend(j["id"] for j in jobs)
    ts = [threading.Thread(target=grab, args=(f"w{i}",)) for i in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(got) == 40 and len(set(got)) == 40  # every job taken exactly once, none twice


def test_lease_expiry_reclaims_dead_workers_jobs_and_counts_an_attempt():
    db.enqueue_job("gmail", "m", "a")
    j = db.claim_jobs("gmail", "a", "dead", lease_seconds=-1)[0]
    db.mark_in_flight(j["id"], "dead")  # the worker had started working on it when it died
    assert db.claim_jobs("gmail", "a", "live", lease_seconds=300)[0]["attempts"] == 1
    assert db.complete_job(j["id"], "dead") is False  # the dead worker lost the lease and cannot overwrite state
    assert db.complete_job(j["id"], "live", scan_id=7) is True and db.get_job(j["id"])["scan_id"] == 7


def test_live_lease_blocks_other_workers():
    db.enqueue_job("gmail", "m", "a")
    assert len(db.claim_jobs("gmail", "a", "w1", lease_seconds=300)) == 1
    assert db.claim_jobs("gmail", "a", "w2") == []


def test_retry_scheduling_and_not_claimable_until_due():
    db.enqueue_job("gmail", "m", "a")
    j = db.claim_jobs("gmail", "a", "w")[0]
    assert db.schedule_retry(j["id"], "w", 600, "network", "timeout") is True
    row = db.get_job(j["id"])
    assert row["state"] == "retry_scheduled" and row["attempts"] == 1 and row["error_category"] == "network"
    assert db.claim_jobs("gmail", "a", "w") == []
    force(j["id"], next_attempt_at="2000-01-01T00:00:00+00:00")
    assert len(db.claim_jobs("gmail", "a", "w")) == 1


def test_dead_letter_is_kept_and_manual_retry_respects_eligibility():
    for ref in ("net", "bad"):
        db.enqueue_job("gmail", ref, "a")
    a, b = db.claim_jobs("gmail", "a", "w")
    db.dead_letter(a["id"], "w", "network", "Bearer ya29.SECRETSECRETSECRET gave up")
    db.dead_letter(b["id"], "w", "malformed", "not an email")
    failed = db.list_jobs("failed")
    assert len(failed) == 2 and all(j["dead_lettered_at"] for j in failed)
    assert "SECRETSECRET" not in str(failed)
    assert db.retry_jobs() == [a["id"]]  # only the plausibly-fixable one
    assert db.get_job(a["id"])["state"] == "pending" and db.get_job(b["id"])["state"] == "failed"
    assert db.retry_jobs(force=True) == [b["id"]]


def test_shutdown_release_and_account_cancel():
    for i in range(3):
        db.enqueue_job("gmail", f"m{i}", "a")
    db.claim_jobs("gmail", "a", "w")
    assert db.release_owner("w") == 3 and db.job_counts()["pending"] == 3
    assert db.cancel_account_jobs("a") == 3 and db.job_counts()["cancelled"] == 3 and db.claim_jobs("gmail", "a", "w") == []


def test_checkpoint_and_jobs_commit_together(monkeypatch):
    db.upsert_account("gmail:t", "gmail", "t", monitoring_enabled=True)
    real = db._enqueue
    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] == 2:
            raise sqlite3.OperationalError("disk I/O error")
        return real(*a, **k)
    monkeypatch.setattr(db, "_enqueue", flaky)
    with pytest.raises(sqlite3.OperationalError):
        db.record_sync("gmail:t", "gmail", ["a", "b", "c"], {"history_id": "999"})
    monkeypatch.setattr(db, "_enqueue", real)  # restore only this function (undo() would also revert the temp-DB fixture)
    assert db.get_account("gmail:t")["sync_state"] == {} and db.job_counts()["pending"] == 0  # nothing advanced, nothing half-queued
    assert db.record_sync("gmail:t", "gmail", ["a", "b", "c"], {"history_id": "999"}) == 3
    assert db.get_account("gmail:t")["sync_state"] == {"history_id": "999"}


def test_queue_and_results_survive_a_process_restart():
    db.enqueue_job("gmail", "m", "a")
    ingest.ingest_bytes(sample("01_benign_newsletter"), "x.eml")
    db._ready.clear()  # a new process knows nothing in memory
    assert db.job_counts()["pending"] == 1 and db.stats()["total"] == 1


def test_only_the_in_flight_job_is_charged_when_a_worker_dies():
    for ref in ("poison", "innocent1", "innocent2"):
        db.enqueue_job("gmail", ref, "a")
    batch = db.claim_jobs("gmail", "a", "dead", limit=3, lease_seconds=-1)
    db.mark_in_flight(batch[0]["id"], "dead")  # died while processing the first one; the others were merely claimed
    again = {j["external_id"]: j for j in db.claim_jobs("gmail", "a", "live", limit=3)}
    assert again["poison"]["attempts"] == 1 and again["innocent1"]["attempts"] == 0 and again["innocent2"]["attempts"] == 0


def test_startup_recovery_also_charges_only_the_in_flight_job():
    for ref in ("a", "b"):
        db.enqueue_job("gmail", ref, "acct")
    batch = db.claim_jobs("gmail", "acct", "old-process", limit=2, lease_seconds=-1)
    db.mark_in_flight(batch[0]["id"], "old-process")
    assert db.reset_stuck_jobs("gmail") == 2
    j = {x["external_id"]: x for x in db.list_jobs()}
    assert j["a"]["attempts"] == 1 and j["a"]["error_category"] == "interrupted" and j["b"]["attempts"] == 0 and j["b"]["state"] == "pending"
