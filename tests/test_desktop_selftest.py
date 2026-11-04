from emailshield import db
from emailshield.desktop import monitor_selftest


def test_monitoring_selftest_exercises_the_whole_pipeline(tmp_path):
    r = monitor_selftest(tmp_path)
    assert r["ok"] and r["completed_jobs"] == 1 and r["failed_jobs"] == 0
    assert db.stats()["total"] == 1 and db.get_account("folder:selftest")["last_scan_at"]


def test_monitoring_selftest_is_repeatable_without_duplicates(tmp_path):
    assert monitor_selftest(tmp_path)["ok"]
    again = monitor_selftest(tmp_path)  # the file is rewritten (new mtime -> new job), but its content is a known duplicate
    assert again["ok"] and again["failed_jobs"] == 0 and db.stats()["total"] == 1 and sum(db.alert_counts().values()) <= 1
