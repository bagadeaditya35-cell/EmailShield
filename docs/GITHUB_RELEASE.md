# Publishing to GitHub (prepare locally first; publish only after the checks pass)
1. `python scripts\release_check.py` must report **0 blockers** for the label you intend (it writes docs\RELEASE_READINESS.md).
2. `python scripts\secret_scan.py --history` must report 0 blockers. If a real secret is ever found in history: **revoke/rotate it first**, then rewrite history (e.g. a fresh repository from a clean tree). Deleting the file in a new commit does not make an exposed secret safe.
3. Decide the licence (LICENSE_CONSIDERATIONS.md). Review README for accuracy against PROGRESS.md.
4. Create an empty GitHub repository (private first). `git remote add origin <url>` then `git push -u origin feature/advanced` (never force-push; keep the `baseline-2.0.1` tag). Review the diff on GitHub before making it public.
5. Release: tag `v2.3.0-experimental` (use `-beta` only when RELEASE_EVIDENCE.json shows the required evidence), attach `EmailShield-Setup-<ver>.exe`, `EmailShield-Portable-<ver>.zip`, `SHA256SUMS.txt`, `build-requirements.lock.txt`; paste the release notes and the Known limitations. State clearly that builds are unsigned.
No GitHub credentials are needed or requested by this project; do the push from your own authenticated Git.
