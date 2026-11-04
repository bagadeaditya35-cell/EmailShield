"""Measures what the monitoring pipeline actually costs on THIS machine (time, peak memory, database size).
Usage: python scripts/benchmark.py [N]   (default 200 synthetic messages, in a temporary folder; touches none of your data)"""
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
n = int(sys.argv[1]) if len(sys.argv) > 1 else 200
tmp = Path(tempfile.mkdtemp(prefix="emailshield-bench-"))
os.environ["EMAILSHIELD_DATA_DIR"] = str(tmp)
from emailshield import config, db, providers  # noqa: E402
from emailshield.worker import Worker  # noqa: E402

samples = sorted((ROOT / "evaluation" / "dataset").glob("*.eml"))
if not samples:
    sys.exit("Run: python evaluation/build_dataset.py first")
inbox = tmp / "inbox"
inbox.mkdir()
for i in range(n):  # unique content so nothing is deduplicated
    (inbox / f"m{i:05d}.eml").write_bytes(samples[i % len(samples)].read_bytes() + f"X-Bench: {i}\r\n".encode())
w = Worker(providers.FolderProvider(inbox), interval=1, batch=25, deliver_exports=False)
w.start()
t0 = time.perf_counter()
cycles = 0
while True:
    r = w.step()
    cycles += 1
    c = db.job_counts()
    if c["pending"] + c["retry_scheduled"] + c["processing"] == 0:
        break
dt = time.perf_counter() - t0
try:
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # MB on Linux
except ImportError:
    peak = None  # Windows: use Task Manager or `pip install psutil`
print(f"messages: {db.stats()['total']}  completed jobs: {db.job_counts()['completed']}  failed: {db.job_counts()['failed']}  cycles: {cycles}")
print(f"elapsed: {dt:.2f}s  ->  {n / dt:.1f} messages/second (single worker, batch 25)")
print(f"peak memory: {'%.0f MB' % peak if peak else 'not measured on this OS'}   database: {config.DB_PATH.stat().st_size / 1024:.0f} KB")
print(f"python {sys.version.split()[0]} on {sys.platform}")
