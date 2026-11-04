"""Real Splunk HEC check against YOUR authorized test instance. Sends N clearly synthetic events, measures delivery latency, prints
the searches to run to confirm the events are searchable. Uses the HEC URL/token already saved in EmailShield (Settings) or the
environment (SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN).  Usage: python scripts/splunk_verify.py [N]"""
import os
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from emailshield import net, secrets_store, settings, splunk  # noqa: E402


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    cfg = settings.load()["splunk"]
    url = os.environ.get("SPLUNK_HEC_URL") or cfg["url"]
    token = secrets_store.get(splunk.TOKEN_NAME)
    if not (url and token):
        sys.exit("Configure Splunk in EmailShield (Settings) or set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN.")
    hec = splunk.HEC(url, token, cfg["index"], "emailshield:verify", cfg["verify_tls"])
    run_id = uuid.uuid4().hex[:12]
    print(f"HEC health endpoint: {'OK' if hec.health() else 'NOT healthy'}")
    lat = []
    for i in range(n):
        t = time.perf_counter()
        try:
            hec.send({"event_type": "emailshield_verify", "synthetic": True, "run_id": run_id, "seq": i}, sourcetype="emailshield:verify")
        except (splunk.SplunkError, net.ConnectionProblem) as e:
            sys.exit(f"Event {i} FAILED: {e}")
        lat.append((time.perf_counter() - t) * 1000)
    print(f"sent {n} synthetic events, run_id={run_id}")
    print(f"HEC acknowledgement latency: min {min(lat):.0f} ms / avg {sum(lat) / n:.0f} ms / max {max(lat):.0f} ms")
    print("Now confirm they are SEARCHABLE (events can take a few seconds):")
    print(f'  index={cfg["index"] or "*"} sourcetype="emailshield:verify" run_id={run_id} | stats count')
    print(f"Expected count: {n}.  An HTTP 200 from HEC means 'accepted', not 'indexed': the search is the proof.")


if __name__ == "__main__":
    main()
