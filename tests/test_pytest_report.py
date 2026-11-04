import sys

from tests.conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import pytest_report  # noqa: E402

XML = """<?xml version="1.0"?><testsuites><testsuite name="pytest" tests="5">
<testcase classname="tests.test_a" name="test_ok" time="0.01"/>
<testcase classname="tests.test_a" name="test_bad" time="0.02"><failure type="AttributeError" message="AttributeError: 'function' object has no attribute 'run_checks'">trace...</failure></testcase>
<testcase classname="tests.test_b" name="test_err" time="0.02"><error type="RuntimeError" message="boom with Bearer ya29.SECRETSECRETSECRETSECRET in it">trace</error></testcase>
<testcase classname="tests.test_c" name="test_skip"><skipped message="needs fastapi"/></testcase>
<testcase classname="tests.test_c" name="test_skip2"><skipped message="needs fastapi"/></testcase>
</testsuite></testsuites>"""


def test_junit_is_summarised_into_counts_and_one_row_per_problem():
    s = pytest_report.summarize_junit(XML)
    assert (s["total"], s["passed"], s["failed"], s["errors"], s["skipped"]) == (5, 1, 1, 1, 2)
    assert [p["test"] for p in s["problems"]] == ["tests.test_a::test_bad", "tests.test_b::test_err"]
    assert s["problems"][0]["type"] == "AttributeError" and "run_checks" in s["problems"][0]["message"]
    assert s["skips"] == {"needs fastapi": 2}


def test_secrets_are_redacted_from_the_shareable_report():
    s = pytest_report.summarize_junit(XML)
    text = pytest_report.render(s, ["python", "-m", "pytest"], 1)
    assert "SECRETSECRET" not in text and "REDACTED" in text and "failed 1" in text and "tests.test_a::test_bad" in text
    assert "NOT INSTALLED" in text or "pytest" in text  # environment line is present


def test_a_single_bare_testsuite_root_is_also_accepted():
    s = pytest_report.summarize_junit('<testsuite><testcase classname="x" name="y"/></testsuite>')
    assert s["total"] == 1 and s["passed"] == 1 and s["problems"] == []
