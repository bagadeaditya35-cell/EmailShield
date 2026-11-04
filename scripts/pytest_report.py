"""Runs the REAL pytest suite and writes a compact, shareable report: environment, counts, and one line per failure/error/skip.
Nothing from your mailboxes is included, and secret-looking strings are redacted. Paste pytest-report.md when asking for help.
Usage:  python scripts/pytest_report.py [extra pytest arguments]        (writes pytest-report.md and pytest-junit.xml)"""
import importlib.metadata as md
import platform
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from emailshield import redact  # noqa: E402


def summarize_junit(xml_text):
    """Parse a pytest JUnit XML string into counts and per-test problem rows."""
    root = ET.fromstring(xml_text)
    suites = [root] if root.tag == "testsuite" else list(root)
    out = {"total": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0, "problems": [], "skips": {}}
    for suite in suites:
        for tc in suite.iter("testcase"):
            out["total"] += 1
            name = f"{tc.get('classname', '')}::{tc.get('name', '')}".strip(":")
            bad = tc.find("failure") if tc.find("failure") is not None else tc.find("error")
            if bad is not None:
                kind = "failed" if bad.tag == "failure" else "errors"
                out[kind] += 1
                msg = redact.redact((bad.get("message") or (bad.text or "")).strip().splitlines()[0] if (bad.get("message") or bad.text) else "")[:200]
                out["problems"].append({"test": name, "kind": bad.tag, "type": bad.get("type") or "", "message": msg})
            elif tc.find("skipped") is not None:
                out["skipped"] += 1
                reason = redact.redact(tc.find("skipped").get("message") or "")[:120]
                out["skips"][reason] = out["skips"].get(reason, 0) + 1
            else:
                out["passed"] += 1
    return out


def versions():
    got = {}
    for pkg in ("pytest", "fastapi", "starlette", "httpx", "uvicorn", "pydantic", "anyio"):
        try:
            got[pkg] = md.version(pkg)
        except md.PackageNotFoundError:
            got[pkg] = "NOT INSTALLED"
    return got


def render(summary, cmd, returncode):
    L = ["# pytest report", "", f"- Python {platform.python_version()} on {platform.platform()}", f"- Command: `{' '.join(cmd)}` (exit code {returncode})",
         "- Packages: " + ", ".join(f"{k} {v}" for k, v in versions().items()), "",
         f"**collected {summary['total']} | passed {summary['passed']} | failed {summary['failed']} | errors {summary['errors']} | skipped {summary['skipped']}**", ""]
    if summary["problems"]:
        L += ["## Failures and errors", "", "| # | Test | Kind | Exception | First line |", "|---|---|---|---|---|"]
        L += [f"| {i} | `{p['test']}` | {p['kind']} | {p['type']} | {p['message'].replace('|', '/')} |" for i, p in enumerate(summary["problems"], 1)]
    if summary["skips"]:
        L += ["", "## Skipped (grouped by reason)", ""] + [f"- {n} x {r or '(no reason)'}" for r, n in summary["skips"].items()]
    return "\n".join(L) + "\n"


def main(argv):
    xml = ROOT / "pytest-junit.xml"
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={xml}", *argv]
    proc = subprocess.run(cmd, cwd=ROOT)
    if not xml.exists():
        print("pytest did not produce a result file (is pytest installed? pip install -r requirements.txt)", file=sys.stderr)
        return proc.returncode or 2
    summary = summarize_junit(xml.read_text(encoding="utf-8"))
    report = render(summary, [Path(cmd[0]).name, *cmd[1:2], *cmd[2:3], "..."], proc.returncode)
    (ROOT / "pytest-report.md").write_text(report, encoding="utf-8")
    print("\n" + report)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
