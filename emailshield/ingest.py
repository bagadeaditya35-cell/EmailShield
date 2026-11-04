"""Shared ingestion path used by the API, the CLI and the monitoring worker."""
import os
from pathlib import Path

from . import config, db, detector, intel, parser, settings, splunk, yara_opt


def ingest_bytes(raw: bytes, filename: str, source="upload", account_id="", external_id="", rescan=False) -> dict:
    """Parse -> score (existing engine) -> save -> alert -> queue export. Raw mail is never stored; attachments never opened."""
    filename = os.path.basename((filename or "unnamed.eml").replace("\\", "/"))[:200] or "unnamed.eml"
    try:
        if len(raw) > config.MAX_EML_BYTES:
            raise ValueError(f"File exceeds {config.MAX_EML_BYTES // (1024 * 1024)} MB limit")
        parsed = parser.parse_eml(raw, yara_opt.get_scanner())
        analysis = detector.analyze(parsed)
        pv = settings.load()["privacy"]  # data minimisation: store only what the settings allow (default: no body text, no recipients)
        stored = {**parsed, "text": parsed["text"][:pv["store_body_chars"]], "to": parsed["to"] if pv["store_recipients"] else ""}
        mid, dup = db.save_analysis(filename, stored, analysis, source, account_id, external_id)
        rescanned = False
        if dup and rescan:
            rescanned = db.update_analysis(mid, parsed, analysis)
        db.add_event("duplicate" if dup and not rescanned else "rescanned" if rescanned else "analyzed",
                     f"{filename} -> #{mid} ({analysis['category']}, {analysis['score']})")
        alert_id = None
        if not dup or rescanned:
            alert_id, created, changed = db.upsert_alert(mid, analysis["category"], analysis["score"], parsed["subject"] or "(no subject)",
                                                         analysis["engine"]["version"])
            try:  # optional integrations must never break local analysis
                splunk.enqueue_export(mid, alert_id, changed)
            except Exception as e:
                db.add_event("splunk_error", f"enqueue: {type(e).__name__}")
        if not dup:
            try:
                intel.enrich(mid)
            except Exception as e:
                db.add_event("ti_error", f"{type(e).__name__}: {e}")
        return {"ok": True, "id": mid, "duplicate": dup and not rescanned, "rescanned": rescanned, "alert_id": alert_id,
                "score": analysis["score"], "category": analysis["category"]}
    except Exception as e:
        db.add_event("error", f"{filename}: {type(e).__name__}: {e}")
        return {"ok": False, "filename": filename, "error": f"{type(e).__name__}: {e}"}


def ingest_folder(folder, source="batch") -> list:
    return [{"file": p.name, **ingest_bytes(p.read_bytes(), p.name, source)} for p in sorted(Path(folder).glob("*.eml"))]
