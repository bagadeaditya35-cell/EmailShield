"""Secret and confidentiality scanner for the working tree AND the full git history (stdlib only).
Usage: python scripts/secret_scan.py [--history]      Exit code 1 if any BLOCKER is found.
Findings under tests/ are reported as 'fixture' (synthetic test values); they are not blockers but should be eyeballed.
A removed file is NOT safe: anything found in history must be treated as exposed, rotated/revoked, and the history rewritten before publishing."""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PATTERNS = {
    "Google OAuth client secret": re.compile(r"GOCSPX-[A-Za-z0-9_\-]{20,}"),
    "Google access token": re.compile(r"ya29\.[A-Za-z0-9_\-\.]{20,}"),
    "Google refresh token": re.compile(r"\b1//[A-Za-z0-9_\-]{30,}"),
    "Google API key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Splunk HEC token (uuid after 'Splunk')": re.compile(r"(?i)splunk\s+[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    "Bearer token": re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_\.=]{30,}"),
    "client_secret JSON value": re.compile(r'"client_secret"\s*:\s*"(?!\s*")[^"]{12,}"'),
    "Generic secret assignment": re.compile(r"(?i)\b(?:api[_-]?key|secret|passwd|password|token)\s*[:=]\s*[\"'][A-Za-z0-9/+_\-]{20,}[\"']"),
}
FORBIDDEN_FILES = re.compile(r"(^|/)(data/|.*\.db(-wal|-shm)?$|.*\.sqlite3?$|secrets\.json$|api_key\.txt$|gmail_token\.json$|client_secret.*\.json$|\.env$|.*\.pem$|.*\.pfx$|.*\.log$)")
BINARY = re.compile(r"\.(png|ico|zip|exe|pyc|jpg|gif|eml)$", re.I)


def sh(*a):
    return subprocess.run(a, cwd=ROOT, capture_output=True, text=True, errors="replace").stdout


def scan_text(label, text, findings):
    for name, pat in PATTERNS.items():
        for m in pat.finditer(text):
            findings.append((name, label, m.group(0)[:6] + "..." + m.group(0)[-3:]))


def main():
    history = "--history" in sys.argv
    findings, bad_files = [], []
    tracked = sh("git", "ls-files").splitlines()
    for f in tracked:
        if FORBIDDEN_FILES.search(f) and not f.startswith(("samples/", "evaluation/dataset/")):
            bad_files.append(f)
        if BINARY.search(f):
            continue
        p = ROOT / f
        if p.is_file() and p.stat().st_size < 2_000_000:
            scan_text(f, p.read_text(errors="replace"), findings)
    hist_findings, hist_bad = [], []
    if history:
        names = set(sh("git", "log", "--all", "--name-only", "--pretty=format:").split())
        hist_bad = sorted(n for n in names if FORBIDDEN_FILES.search(n) and not n.startswith(("samples/", "evaluation/dataset/")))
        cur, buf = "?", {}
        for line in sh("git", "log", "--all", "-p", "--no-color", "--pretty=format:").splitlines():
            if line.startswith("diff --git "):
                cur = line.split(" b/", 1)[-1]
            elif line.startswith("+") and not line.startswith("+++") and not BINARY.search(cur):
                buf.setdefault(cur, []).append(line[1:])
        for fname, lines in buf.items():
            scan_text(f"history:{fname}", "\n".join(lines), hist_findings)
    blockers = [f for f in findings if not f[1].startswith("tests/")] + bad_files + hist_bad + [f for f in hist_findings if not f[1].startswith("history:tests/")]
    fixtures = [f for f in findings if f[1].startswith("tests/")]
    print(f"tracked files scanned: {len(tracked)}  history scanned: {'yes' if history else 'no (use --history)'}")
    print(f"BLOCKERS: {len(blockers)}   fixture-only findings in tests/: {len(fixtures)}")
    for b in blockers:
        print("  BLOCKER:", b)
    for name, where, snip in sorted(set(fixtures))[:12]:
        print(f"  fixture: {name} in {where} ({snip})  <- confirm this is a synthetic test value")
    if history and hist_findings and not [f for f in hist_findings if not f[1].startswith("history:tests/")]:
        print(f"  history contains {len(hist_findings)} pattern hit(s), all inside test fixtures (see above); verify they are synthetic")
    return 1 if blockers else 0


if __name__ == "__main__":
    raise SystemExit(main())
