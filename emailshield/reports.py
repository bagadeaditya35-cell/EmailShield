"""Investigation reports (JSON, text, HTML). Reports exclude the message body and recipient list on purpose."""
import html
from datetime import datetime, timezone

from . import db


def build_report(mid):
    m = db.get_message(mid)
    if not m:
        return None
    a, p = m["analysis"], m["parsed"]
    ts = datetime.now(timezone.utc)
    return {
        "report_id": f"ES-{ts:%Y%m%d%H%M%S}-{mid}", "case_ref": m["case_ref"],
        "generated_at": ts.isoformat(timespec="seconds"), "message_id": mid, "analyzed_at": m["analyzed_at"],
        "investigation_status": m["status"],
        "metadata": {k: p[k] for k in ("subject", "from_name", "from_addr", "reply_to_addr", "return_path_addr",
                                       "date", "message_id", "received_hops", "auth", "raw_sha256")},
        "risk": {"score": a["score"], "category": a["category"], "thresholds": a["thresholds"],
                 "group_scores": a.get("group_scores", {}), "note": a["note"]},
        "findings": a["findings"], "attack_mapping": m["attack"], "indicators": a["indicators"], "attachments": p["attachments"],
        "threat_intelligence": m["intel"] or "No external lookups were performed (local-only mode or not enabled).",
        "related_messages": db.find_related(mid), "recommended_steps": a["recommended_steps"],
        "investigation_notes": m["notes"], "investigation_history": m["history"], "limitations": a["limitations"],
    }


def to_text(r):
    L = [f"EMAILSHIELD INVESTIGATION REPORT {r['report_id']}  ({r['case_ref']})", "=" * 64,
         f"Generated: {r['generated_at']}   Analyzed: {r['analyzed_at']}   Status: {r['investigation_status']}", "", "METADATA"]
    L += [f"  {k}: {v}" for k, v in r["metadata"].items()]
    L += ["", f"RISK: {r['risk']['category']} (heuristic score {r['risk']['score']}/100)", f"  {r['risk']['note']}", "", "FINDINGS"]
    for f in r["findings"]:
        L += [f"  [{f['severity'].upper()} +{f['points']}] {f['title']} ({f['id']})", f"      Why: {f['reason']}"]
        L += [f"      Evidence: {e}" for e in f["evidence"]] + [f"      Next step: {f['step']}"]
    if r.get("attack_mapping"):
        L += ["", "MITRE ATT&CK MAPPING (engine inference - not proof)"]
        for t in r["attack_mapping"]:
            L += [f"  {t['technique_id']} {t['name']} [{t['tactic']}]", f"      Observed: " + "; ".join(t["observed"]), f"      Inference: {t['inference']}", f"      Analyst: {t['analyst_interpretation']}"]
    if r["attachments"]:
        L += ["", "ATTACHMENTS (never opened)"] + [f"  {a['filename']} ({a['size']} B, type {a.get('detected_type', '?')}) sha256={a['sha256']}" for a in r["attachments"]]
    L += ["", "INDICATORS"] + [f"  {i['type']}: {i['value']}" for i in r["indicators"]]
    L += ["", "THREAT INTELLIGENCE"]
    ti = r["threat_intelligence"]
    L += [f"  {ti}"] if isinstance(ti, str) else [f"  [{t['fetched_at']}] {t['provider']} {t['indicator_type']} {t['indicator']}: {t['verdict']} - {t['detail']}" for t in ti]
    L += ["", "RELATED MESSAGES"]
    rel = r["related_messages"]["related"]
    L += [f"  {x['case_ref']} {x['subject']} - " + "; ".join(x["reasons"]) for x in rel] or ["  none found"]
    L += [f"  Note: {r['related_messages']['caveat']}", "", "RECOMMENDED STEPS"] + [f"  {i}. {s}" for i, s in enumerate(r["recommended_steps"], 1)]
    L += ["", "INVESTIGATION NOTES", f"  {r['investigation_notes'] or '(none)'}", "", "HISTORY"]
    L += [f"  {h['ts']} {h['actor']}: {h['action']} {h['detail']}" for h in r["investigation_history"]]
    L += ["", "LIMITATIONS"] + [f"  - {x}" for x in r["limitations"]]
    return "\n".join(L)


def to_html(r):
    e = html.escape
    rows = "".join(f"<tr><th>{e(k)}</th><td>{e(str(v))}</td></tr>" for k, v in r["metadata"].items())
    finds = "".join(
        f"<div class='f {e(f['severity'])}'><b>{e(f['title'])}</b> (+{f['points']}) <small>{e(f['id'])}</small>"
        f"<p>{e(f['reason'])}</p>" + "".join(f"<code>{e(x)}</code> " for x in f["evidence"]) + f"<p><i>Next step:</i> {e(f['step'])}</p></div>"
        for f in r["findings"]) or "<p>No indicators fired. This does not prove the email is safe.</p>"
    rel = "".join(f"<li>{e(x['case_ref'])} {e(x['subject'] or '')}: {e('; '.join(x['reasons']))}</li>" for x in r["related_messages"]["related"]) or "<li>none found</li>"
    ti = r["threat_intelligence"]
    tih = f"<p>{e(ti)}</p>" if isinstance(ti, str) else "<ul>" + "".join(
        f"<li>{e(t['fetched_at'])} {e(t['provider'])} {e(t['indicator_type'])} <code>{e(t['indicator'])}</code>: {e(t['verdict'])} - {e(t['detail'])}</li>" for t in ti) + "</ul>"
    atk = "".join(f"<p><b>{e(t['technique_id'])} {e(t['name'])}</b> ({e(t['tactic'])})<br>Observed: {e('; '.join(t['observed']))}<br>Inference: {e(t['inference'])}<br>Analyst: {e(t['analyst_interpretation'])}</p>" for t in r.get("attack_mapping", [])) or "<p>No techniques mapped.</p>"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{e(r['report_id'])}</title>
<style>body{{font:14px system-ui,sans-serif;max-width:900px;margin:24px auto;padding:0 16px;color:#111}}th{{text-align:left;padding-right:12px;vertical-align:top}}
code{{background:#eee;padding:1px 4px;word-break:break-all}}.f{{border-left:4px solid #f59e0b;padding:4px 10px;margin:8px 0;background:#fafafa}}.f.high{{border-color:#ef4444}}small{{color:#666}}</style></head><body>
<h1>EmailShield report {e(r['report_id'])}</h1><p>{e(r['case_ref'])} &middot; generated {e(r['generated_at'])} &middot; status {e(r['investigation_status'])}</p>
<h2>Risk: {e(r['risk']['category'])} ({r['risk']['score']}/100)</h2><p><i>{e(r['risk']['note'])}</i></p>
<h2>Metadata</h2><table>{rows}</table><h2>Findings</h2>{finds}
<h2>MITRE ATT&amp;CK mapping (engine inference, not proof)</h2>{atk}<h2>Attachments (never opened)</h2><ul>{''.join(f"<li>{e(a['filename'])} {a['size']} B <code>{e(a['sha256'])}</code></li>" for a in r['attachments']) or '<li>none</li>'}</ul>
<h2>Threat intelligence</h2>{tih}<h2>Related messages</h2><ul>{rel}</ul><p><small>{e(r['related_messages']['caveat'])}</small></p>
<h2>Recommended steps</h2><ol>{''.join(f'<li>{e(s)}</li>' for s in r['recommended_steps'])}</ol>
<h2>Investigation notes</h2><p>{e(r['investigation_notes'] or '(none)')}</p>
<h2>History</h2><ul>{''.join(f"<li>{e(h['ts'])} {e(h['actor'])}: {e(h['action'])} {e(h['detail'])}</li>" for h in r['investigation_history'])}</ul>
<h2>Limitations</h2><ul>{''.join(f'<li>{e(x)}</li>' for x in r['limitations'])}</ul></body></html>"""
