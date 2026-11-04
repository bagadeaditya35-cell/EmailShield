import csv
import subprocess
import sys

from evaluation import metrics, run_eval
from tests.conftest import ROOT


def test_confusion_math_known_values():
    s = metrics.confusion([1, 1, 1, 0, 0, 0, 0, 1], [1, 1, 0, 1, 0, 0, 0, 0])
    assert (s["tp"], s["fp"], s["tn"], s["fn"]) == (2, 1, 3, 2)
    assert abs(s["precision"] - 2 / 3) < 1e-9 and abs(s["recall"] - 0.5) < 1e-9
    assert abs(s["f1"] - 2 * (2 / 3) * 0.5 / (2 / 3 + 0.5)) < 1e-9 and abs(s["false_positive_rate"] - 0.25) < 1e-9


def test_zero_division_gives_none_not_a_fake_number():
    s = metrics.confusion([0, 0], [0, 0])
    assert s["precision"] is None and s["recall"] is None and s["f1"] is None and s["false_positive_rate"] == 0.0


def test_dataset_is_labelled_both_classes_and_deterministic():
    labels = list(csv.DictReader(open(ROOT / "evaluation" / "labels.csv")))
    assert {r["label"] for r in labels} == {"0", "1"} and len(labels) >= 40
    before = (ROOT / "evaluation" / "labels.csv").read_bytes()
    first = {p.name: p.read_bytes() for p in (ROOT / "evaluation" / "dataset").glob("*.eml")}
    subprocess.run([sys.executable, str(ROOT / "evaluation" / "build_dataset.py")], check=True, capture_output=True)
    assert (ROOT / "evaluation" / "labels.csv").read_bytes() == before
    assert first == {p.name: p.read_bytes() for p in (ROOT / "evaluation" / "dataset").glob("*.eml")}


def test_every_sample_is_scored_and_counts_add_up():
    res = run_eval.evaluate()
    assert len(res) == len(list(csv.DictReader(open(ROOT / "evaluation" / "labels.csv"))))
    y = [r["label"] for r in res]
    s = metrics.confusion(y, [r["score"] >= 30 for r in res])
    assert s["tp"] + s["fp"] + s["tn"] + s["fn"] == len(res)
