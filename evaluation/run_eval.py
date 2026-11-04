"""Runs the detection engine over the labelled dataset and writes docs/DETECTION_EVALUATION.md + evaluation/results.json."""
import csv
import json
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from emailshield import __version__, config, detector, parser  # noqa: E402
from evaluation.metrics import confusion  # noqa: E402


def evaluate():
    labels = list(csv.DictReader(open(ROOT / "evaluation" / "labels.csv")))
    import time
    out = []
    for r in labels:
        raw = (ROOT / "evaluation" / "dataset" / r["file"]).read_bytes()
        t = time.perf_counter()
        a = detector.analyze(parser.parse_eml(raw))
        ms = (time.perf_counter() - t) * 1000
        out.append({**r, "label": int(r["label"]), "score": a["score"], "category": a["category"], "ms": ms,
                    "findings": [f["id"] for f in a["findings"] if f["points"] > 0]})
    return out


def pct(x):
    return "n/a" if x is None else f"{x * 100:.1f}%"


def main():
    res = evaluate()
    y = [r["label"] for r in res]
    th = config.THRESHOLDS
    views = {f"Suspicious or higher (score >= {th['suspicious']})": [r["score"] >= th["suspicious"] for r in res],
             f"High risk only (score >= {th['high']})": [r["score"] >= th["high"] for r in res]}
    stats = {k: confusion(y, v) for k, v in views.items()}
    json.dump({"version": __version__, "thresholds": th, "stats": stats, "samples": res}, open(ROOT / "evaluation" / "results.json", "w"), indent=1)
    L = [f"# Detection evaluation (generated {date.today()} by evaluation/run_eval.py, EmailShield {__version__})", "",
         "## Dataset", f"{len(res)} synthetic emails: {sum(y)} malicious-delivery, {len(y) - sum(y)} legitimate. Harmless by construction: fictional domains, inert marker bytes, no real malware or personal data. "
         "Generated deterministically by `evaluation/build_dataset.py` (fixed seed).", "",
         "## Method", "Each file is parsed and scored by the same engine the application uses (no database, no threat-intel). A message counts as *flagged* when its score meets the threshold. Positive class = malicious. Thresholds are the defaults in `config.py`; they were **not tuned** to this dataset.", "",
         "## Results", "", "| Threshold | TP | FP | TN | FN | Precision | Recall | F1 | False-positive rate |", "|---|---|---|---|---|---|---|---|---|"]
    for k, s in stats.items():
        L.append(f"| {k} | {s['tp']} | {s['fp']} | {s['tn']} | {s['fn']} | {pct(s['precision'])} | {pct(s['recall'])} | {pct(s['f1'])} | {pct(s['false_positive_rate'])} |")
    flag = views[list(views)[0]]
    ms = sorted(r["ms"] for r in res)
    import platform
    L += ["", "## Processing latency (parse + score, one message at a time, no network)", "",
          f"n={len(ms)}  median {ms[len(ms) // 2]:.2f} ms  p95 {ms[int(len(ms) * 0.95) - 1]:.2f} ms  max {ms[-1]:.2f} ms  (measured on {platform.system()} {platform.machine()}, Python {platform.python_version()}; NOT your laptop)"]
    L += ["", "## Misclassified at the 'Suspicious or higher' threshold", "", "| File | Truth | Score | Category | Why (rules that fired) | Group |", "|---|---|---|---|---|---|"]
    for r, f in zip(res, flag):
        if f != bool(r["label"]):
            L.append(f"| {r['file']} | {'malicious' if r['label'] else 'legitimate'} | {r['score']} | {r['category']} | {', '.join(r['findings']) or 'nothing fired'} | {r['tag']} |")
    L += ["", "## By scenario", "", "| Scenario | n | Flagged |", "|---|---|---|"]
    tags = {}
    for r, f in zip(res, flag):
        t = tags.setdefault(r["tag"], [0, 0]); t[0] += 1; t[1] += int(f)
    for t, (n, fl) in sorted(tags.items()):
        L.append(f"| {t} | {n} | {fl} |")
    L += ["", "## Limitations (read before quoting any number)",
          "- Small dataset: each percentage moves several points per single email; no confidence intervals are given.",
          "- **Author bias**: the samples were written by the same developer who wrote the rules, so results are optimistic and say nothing about real-world traffic.",
          "- Synthetic emails lack the noise, languages, formatting and volume of real mail; the legitimate class is probably easier than reality.",
          "- Hard-positive samples (no links, clean authentication, text-only lures, QR codes) are included on purpose; misses there are expected for a rule-based engine and show what it cannot see.",
          "- Threat intelligence, attachment sandboxing and content analysis are not part of this measurement.",
          "- This is **not** a production accuracy claim."]
    (ROOT / "docs" / "DETECTION_EVALUATION.md").write_text("\n".join(L) + "\n")
    print("\n".join(L[:12]))


if __name__ == "__main__":
    main()
