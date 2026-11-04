"""MITRE ATT&CK mapping. Each mapping separates three layers:
  observed     - facts found in the message (from rule evidence)
  inference    - what the detection engine infers from those facts (NOT proven)
  analyst      - left for the human; the engine never fills this in
Technique IDs/names were written from memory without internet access: verify against the current ATT&CK release."""

URL_RULES = {"url_ip_host", "url_punycode", "url_shortener", "url_suspicious_tld", "url_userinfo", "url_many_subdomains",
             "url_http", "link_text_mismatch", "url_brand_in_domain", "url_lookalike_domain"}
ATT_RULES = {"att_dangerous", "att_double_ext", "att_macro", "att_archive", "att_html", "att_type_mismatch", "att_yara_match"}

TECHNIQUES = {
    "T1566.001": ("Phishing: Spearphishing Attachment", "Initial Access",
                  "The message carries an attachment with risky properties; delivery by email attachment is consistent with this technique."),
    "T1566.002": ("Phishing: Spearphishing Link", "Initial Access",
                  "The message contains link(s) with deceptive or risky traits; a malicious link delivered by email is consistent with this technique."),
    "T1036.007": ("Masquerading: Double File Extension", "Defense Evasion",
                  "The attachment name pairs a document extension with an executable one."),
    "T1036.008": ("Masquerading: Masquerade File Type", "Defense Evasion",
                  "The file signature does not match the file extension."),
    "T1656": ("Impersonation", "Defense Evasion",
              "The sender identity resembles a known brand but the domain does not belong to it."),
}


def map_findings(findings):
    """Return a list of mappings supported by findings that actually scored points."""
    active = [f for f in findings if f.get("points", 0) > 0]
    by_id = {f["id"]: f for f in active}
    ids = set(by_id)
    wanted = {}

    def add(tid, rules):
        wanted.setdefault(tid, set()).update(rules)

    if ids & ATT_RULES:
        add("T1566.001", ids & ATT_RULES)
    if ids & URL_RULES:
        add("T1566.002", ids & URL_RULES)
    if "att_double_ext" in ids:
        add("T1036.007", {"att_double_ext"})
    if "att_type_mismatch" in ids:
        add("T1036.008", {"att_type_mismatch"})
    imp = ids & {"display_name_impersonation", "sender_lookalike_domain"}
    if imp:
        add("T1656", imp)

    out = []
    for tid in sorted(wanted):
        name, tactic, inference = TECHNIQUES[tid]
        observed = [f"{r}: {e}" for r in sorted(wanted[tid]) for e in by_id[r]["evidence"]][:12]
        out.append({"technique_id": tid, "name": name, "tactic": tactic, "rules": sorted(wanted[tid]),
                    "observed": observed, "inference": inference,
                    "analyst_interpretation": "Not provided. Record your own assessment in the case notes.",
                    "confidence_note": "Heuristic mapping only; it does not establish attacker intent."})
    return out
