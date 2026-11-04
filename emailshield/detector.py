"""Heuristic phishing detector. Every finding carries a reason and evidence.
The score is a heuristic, NOT a calibrated probability of compromise."""
import ipaddress
import re
from urllib.parse import urlsplit

import hashlib
import json

from . import __version__, config

BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com", "microsoftonline.com", "office365.com"],
    "google": ["google.com", "gmail.com", "googlemail.com", "youtube.com", "googleapis.com", "gstatic.com"],
    "amazon": ["amazon.com", "amazon.in", "amazonaws.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "meta.com", "fb.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"],
    "hdfc": ["hdfcbank.com", "hdfc.com"],
    "icici": ["icicibank.com"],
    "npci": ["npci.org.in"],
    "income tax": ["incometax.gov.in", "incometaxindia.gov.in"],
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "link", "support", "gq", "tk", "ml", "cf", "ga",
                   "work", "rest", "country", "loan", "icu", "cyou", "buzz"}
TWO_LEVEL = {"co.in", "com.au", "co.uk", "org.uk", "gov.in", "nic.in", "ac.in", "org.in", "net.in", "com.br"}
DANGEROUS_EXT = {"exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "com", "lnk", "hta", "ps1",
                 "msi", "jar", "iso", "img", "dll", "wsf", "reg"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "cab"}
HTML_EXT = {"html", "htm", "xhtml", "svg"}
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt)\.(exe|scr|js|vbs|bat|cmd|com|lnk|hta|ps1)$", re.I)

KEYWORDS = {
    "kw_urgency": ["urgent", "immediately", "within 24 hours", "account will be suspended", "account suspended",
                   "final notice", "act now", "action required", "limited time", "will expire"],
    "kw_credentials": ["password", "verify your account", "verify your identity", "confirm your account",
                       "log in", "login", "sign in", "otp", "one-time password", "cvv", "card number",
                       "kyc", "update your details"],
    "kw_payment": ["wire transfer", "gift card", "bank details", "payment overdue", "pay now", "upi",
                   "refund", "bitcoin", "outstanding payment", "invoice"],
}
TITLES = {
    "malformed_headers": "Message has no usable From, Subject or Date headers",
    "att_type_mismatch": "Attachment content does not match its file extension",
    "att_yara_match": "Attachment matched a local YARA rule",
    "no_sender": "Missing sender address", "reply_to_mismatch": "Reply-To domain differs from From domain",
    "return_path_mismatch": "Return-Path domain differs from From domain", "spf_fail": "SPF check did not pass",
    "dkim_fail": "DKIM check failed", "dmarc_fail": "DMARC check failed",
    "no_auth_results": "No authentication results in headers",
    "display_name_impersonation": "Display name uses a brand the sender domain does not own",
    "sender_lookalike_domain": "Sender domain closely resembles a known brand domain",
    "sender_brand_in_domain": "Brand name inside an unofficial sender domain",
    "url_ip_host": "Link points to a raw IP address", "url_punycode": "Link uses punycode (possible homograph)",
    "url_shortener": "Link uses a URL shortener", "url_suspicious_tld": "Link uses a TLD often abused",
    "url_userinfo": "Link contains user-info ('@') trick", "url_many_subdomains": "Link has many subdomains",
    "url_http": "Link is not HTTPS", "link_text_mismatch": "Visible link text differs from real destination",
    "url_brand_in_domain": "Brand name inside an unofficial link domain",
    "url_lookalike_domain": "Link domain closely resembles a known brand domain",
    "kw_urgency": "Urgency language", "kw_credentials": "Credential/login request language",
    "kw_payment": "Payment/financial request language",
    "att_dangerous": "Potentially executable attachment", "att_double_ext": "Attachment with deceptive double extension",
    "att_macro": "Macro-capable Office attachment", "att_archive": "Archive attachment (contents not inspected)",
    "att_html": "HTML/SVG attachment (can host phishing forms)",
}
REASONS = {
    "reply_to_mismatch": "Replies would go to a different domain than the visible sender - common in phishing and BEC.",
    "return_path_mismatch": "Envelope sender differs from From. Legitimate bulk-mail providers also do this, so weight is low.",
    "spf_fail": "The sending server was not authorized by the sender domain's SPF record.",
    "dkim_fail": "The DKIM signature did not validate; the message may be forged or altered.",
    "dmarc_fail": "DMARC alignment failed, so the From domain is not verified as the true sender.",
    "no_auth_results": "Authentication results are unavailable (e.g., exported without server headers). Absence is NOT evidence of safety.",
    "display_name_impersonation": "Attackers put a trusted brand in the display name; many mail apps show only that name.",
    "sender_lookalike_domain": "Within 1-2 characters of an official domain (typosquatting).",
    "sender_brand_in_domain": "Brand keyword appears in a domain the brand does not own.",
    "url_ip_host": "Legitimate services rarely send users to bare IP addresses.",
    "url_punycode": "Punycode (xn--) can hide look-alike Unicode characters in domains.",
    "url_shortener": "Shorteners hide the real destination.",
    "url_suspicious_tld": "These TLDs have high abuse rates; this is a weak signal on its own.",
    "url_userinfo": "Text before '@' in a URL can make a malicious host look like a trusted one.",
    "url_many_subdomains": "Deep subdomain chains are used to bury the real registered domain.",
    "url_http": "Unencrypted link; weak signal.",
    "link_text_mismatch": "The clickable text shows one domain while the link goes to another - classic deception.",
    "url_brand_in_domain": "Brand keyword appears in a domain the brand does not own.",
    "url_lookalike_domain": "Within 1-2 characters of an official domain (typosquatting).",
    "kw_urgency": "Pressure to act quickly is a common social-engineering tactic.",
    "kw_credentials": "Requests involving credentials or identity verification. Legitimate mail also uses these words, so context matters.",
    "kw_payment": "Payment or financial language; verify any request out-of-band.",
    "att_dangerous": "File type can execute code when opened.",
    "att_double_ext": "Name imitates a document but ends in an executable extension.",
    "att_macro": "Macros are a frequent malware delivery route.",
    "att_archive": "Archives can conceal malicious files from simple scanners.",
    "att_html": "HTML attachments can render local credential-harvesting pages.",
    "no_sender": "No parsable From address was found.",
    "malformed_headers": "The file could not be parsed as a normal email (no From, Subject or Date). It may be corrupted, truncated or crafted to evade parsers.",
    "att_type_mismatch": "File signature shows an executable although the name suggests a harmless document type.",
    "att_yara_match": "A locally configured YARA rule matched the attachment bytes (analysed in memory, never executed).",
    "display_name_impersonation_": "",
}
STEPS = {
    "reply_to_mismatch": "Compare the From and Reply-To addresses with a known-good contact record.",
    "spf_fail": "Review the full Received chain and authentication headers in the original message.",
    "dmarc_fail": "Review the full Received chain and authentication headers in the original message.",
    "dkim_fail": "Review the full Received chain and authentication headers in the original message.",
    "display_name_impersonation": "Contact the claimed organization through an official channel (not via this email).",
    "url_ip_host": "Check URLs in an isolated environment or a reputation service you are authorized to use.",
    "link_text_mismatch": "Check URLs in an isolated environment or a reputation service you are authorized to use.",
    "att_dangerous": "Do not open the attachment. Look up its SHA-256 in an authorized sandbox/reputation service.",
    "att_double_ext": "Do not open the attachment. Look up its SHA-256 in an authorized sandbox/reputation service.",
    "att_macro": "Do not open the attachment. Look up its SHA-256 in an authorized sandbox/reputation service.",
    "kw_credentials": "If a recipient entered credentials, reset them and review account sign-in activity.",
    "kw_payment": "Verify any payment request by phone using a number from an independent source.",
}
DEFAULT_STEP = "Review the evidence for this finding in the original message and confirm or dismiss it in your notes."
STEPS.update({
    "no_sender": "Inspect the raw file; request the original message from the reporter.",
    "malformed_headers": "Treat as untrusted. Obtain the original message in a safe format and compare it with this file.",
    "return_path_mismatch": "Check whether the envelope domain belongs to a known mail provider for the sender.",
    "no_auth_results": "Re-export the message with server headers so SPF/DKIM/DMARC can be assessed.",
    "sender_lookalike_domain": "Compare the domain character by character with the official one; consider a takedown/abuse report via your authorized process.",
    "sender_brand_in_domain": "Verify domain ownership (WHOIS/registration age) using an authorized lookup.",
    "url_punycode": "Decode the punycode hostname and inspect it for look-alike characters.",
    "url_shortener": "Expand the short link only in an isolated, authorized environment.",
    "url_suspicious_tld": "Check the domain's registration age and reputation with an authorized service.",
    "url_userinfo": "Identify the real host after the '@' sign and assess that host instead.",
    "url_many_subdomains": "Identify the registered domain at the end of the host name and assess that.",
    "url_http": "Note that traffic is unencrypted; weigh together with other URL findings.",
    "url_brand_in_domain": "Verify domain ownership (WHOIS/registration age) using an authorized lookup.",
    "url_lookalike_domain": "Compare the domain with the official one and treat the link as hostile until verified.",
    "kw_urgency": "Contact the apparent sender through a separately verified channel before acting.",
    "att_archive": "Inspect archive contents only inside an isolated sandbox.",
    "att_html": "Do not open the file; review its source as text in an isolated environment.",
    "att_type_mismatch": "Do not open the attachment. Submit its SHA-256 to an authorized sandbox or reputation service.",
    "att_yara_match": "Review the matched rule names and escalate according to your procedure.",
})
BASE_STEPS = [
    "Do not click links or open attachments on a production machine.",
    "Search the mailbox for related messages (see Related Emails) and note shared indicators.",
    "Record your decision and reasoning in the investigation notes.",
]
LIMITATIONS = [
    "The risk score is a heuristic sum of rule weights, not a calibrated probability of compromise.",
    "A low score does NOT mean the email is safe; novel or well-crafted attacks may trigger no rule.",
    "No external threat-intelligence lookups were performed unless explicitly shown in this report.",
    "Attachment contents were not opened or scanned; only metadata and SHA-256 were recorded.",
]


# Bump a rule's version when its logic changes (the ruleset fingerprint below also changes with weights/caps/thresholds).
RULE_VERSIONS = {}




def ruleset_version() -> str:
    """Short fingerprint of everything that influences a verdict (rule list, weights, caps, thresholds)."""
    blob = json.dumps({"rules": sorted(TITLES), "rv": RULE_VERSIONS, "w": config.WEIGHTS, "caps": config.GROUP_CAPS, "th": config.THRESHOLDS}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:12]


def reg_domain(host: str) -> str:
    host = (host or "").lower().strip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    return ".".join(labels[-3:]) if ".".join(labels[-2:]) in TWO_LEVEL else ".".join(labels[-2:])


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _brand_check(reg: str):
    """Return ('lookalike', official) / ('brand', keyword) / None for a registered domain."""
    if not reg:
        return None
    for officials in BRANDS.values():
        if reg in officials:
            return None
    label = reg.split(".")[0]
    for officials in BRANDS.values():
        for off in officials:
            ol = off.split(".")[0]
            if len(ol) >= 5 and label != ol and 0 < levenshtein(label, ol) <= 2:
                return ("lookalike", off)
    tokens = re.split(r"[-_.]", reg)
    flat = reg.replace(".", "").replace("-", "")
    for kw in BRANDS:
        k = kw.replace(" ", "")
        if k in tokens or (len(k) >= 5 and k in flat):
            return ("brand", kw)
    return None


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def group_of(rid: str) -> str:
    if rid.startswith(("url_", "link_")):
        return "url"
    if rid.startswith("kw_"):
        return "content"
    if rid.startswith("att_"):
        return "attachment"
    if rid in ("spf_fail", "dkim_fail", "dmarc_fail", "no_auth_results"):
        return "auth"
    if rid == "malformed_headers":
        return "structure"
    return "sender"


def _category(score, th):
    return "High risk" if score >= th["high"] else "Suspicious" if score >= th["suspicious"] else "Low risk"


def analyze(p: dict, weights=None, thresholds=None) -> dict:
    w = {**config.WEIGHTS, **(weights or {})}
    th = {**config.THRESHOLDS, **(thresholds or {})}
    findings = []

    def add(rid, evidence):
        pts = w.get(rid, 0)
        findings.append({
            "id": rid, "title": TITLES[rid], "points": pts,
            "severity": "high" if pts >= 20 else "medium" if pts >= 10 else "low" if pts > 0 else "info",
            "reason": REASONS.get(rid, ""), "evidence": [str(e) for e in evidence][:10],
            "group": group_of(rid), "step": STEPS.get(rid, DEFAULT_STEP), "rule_version": RULE_VERSIONS.get(rid, "1"),
        })

    fd, rd, pd = p["from_domain"], p["reply_to_domain"], p["return_path_domain"]
    if not (p["from_addr"] or p["subject"] or p["date"]):
        add("malformed_headers", ["No From, Subject or Date header found"])
    elif not p["from_addr"]:
        add("no_sender", ["From header missing or unparsable"])
    if rd and fd and reg_domain(rd) != reg_domain(fd):
        add("reply_to_mismatch", [f"From: {p['from_addr']} / Reply-To: {p['reply_to_addr']}"])
    if pd and fd and reg_domain(pd) != reg_domain(fd):
        add("return_path_mismatch", [f"From: {fd} / Return-Path: {pd}"])
    auth = p["auth"]
    if not auth:
        add("no_auth_results", ["No Authentication-Results / Received-SPF header"])
    else:
        if auth.get("spf") in ("fail", "softfail", "permerror", "temperror"):
            add("spf_fail", [f"spf={auth['spf']}"])
        if auth.get("dkim") in ("fail", "permerror"):
            add("dkim_fail", [f"dkim={auth['dkim']}"])
        if auth.get("dmarc") == "fail":
            add("dmarc_fail", [f"dmarc={auth['dmarc']}"])

    name = (p["from_name"] or "").lower()
    for kw, officials in BRANDS.items():
        if re.search(r"\b" + re.escape(kw) + r"\b", name) and reg_domain(fd) not in officials:
            add("display_name_impersonation", [f"Display name '{p['from_name']}' but domain is {fd}"])
            break
    sb = _brand_check(reg_domain(fd))
    if sb and sb[0] == "lookalike":
        add("sender_lookalike_domain", [f"{fd} resembles {sb[1]}"])
    elif sb:
        add("sender_brand_in_domain", [f"{fd} contains '{sb[1]}'"])

    hits = {k: [] for k in ("url_ip_host", "url_punycode", "url_shortener", "url_suspicious_tld", "url_userinfo",
                            "url_many_subdomains", "url_http", "link_text_mismatch", "url_brand_in_domain",
                            "url_lookalike_domain")}
    domains = []
    for item in p["urls"]:
        u, text = item["url"], item.get("text", "")
        host = _host(u)
        if not host:
            continue
        reg = reg_domain(host)
        domains.append(reg) if reg not in domains else None
        if _is_ip(host):
            hits["url_ip_host"].append(u)
        if "xn--" in host:
            hits["url_punycode"].append(host)
        if reg in SHORTENERS:
            hits["url_shortener"].append(u)
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            hits["url_suspicious_tld"].append(host)
        if "@" in urlsplit(u).netloc:
            hits["url_userinfo"].append(u)
        if len(host.split(".")) - len(reg.split(".")) >= 3:
            hits["url_many_subdomains"].append(host)
        if u.lower().startswith("http://"):
            hits["url_http"].append(u)
        m = re.search(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", text.lower())
        if m and reg_domain(m.group(1)) != reg:
            hits["link_text_mismatch"].append(f'text "{text[:60]}" -> {host}')
        bc = _brand_check(reg)
        if bc and bc[0] == "lookalike":
            hits["url_lookalike_domain"].append(f"{host} resembles {bc[1]}")
        elif bc:
            hits["url_brand_in_domain"].append(f"{host} contains '{bc[1]}'")
    for rid, ev in hits.items():
        if ev:
            add(rid, ev)

    body = f"{p['subject']} {p['text']}".lower()
    for rid, words in KEYWORDS.items():
        found = [k for k in words if re.search(r"\b" + re.escape(k) + r"\b", body)]
        if found:
            add(rid, found)

    att = {"att_yara_match": [], "att_type_mismatch": [], "att_dangerous": [], "att_double_ext": [], "att_macro": [], "att_archive": [], "att_html": []}
    for a in p["attachments"]:
        fn = a["filename"].lower()
        ext = fn.rsplit(".", 1)[-1] if "." in fn else ""
        if a.get("yara"):
            att["att_yara_match"].append(f"{a['filename']}: {', '.join(a['yara'])}")
        if a.get("detected_type") in ("pe", "elf") and ext not in DANGEROUS_EXT:
            att["att_type_mismatch"].append(f"{a['filename']} has {a['detected_type'].upper()} executable signature")
        if DOUBLE_EXT.search(fn):
            att["att_double_ext"].append(a["filename"])
        elif ext in DANGEROUS_EXT:
            att["att_dangerous"].append(a["filename"])
        elif ext in MACRO_EXT:
            att["att_macro"].append(a["filename"])
        elif ext in ARCHIVE_EXT:
            att["att_archive"].append(a["filename"])
        elif ext in HTML_EXT:
            att["att_html"].append(a["filename"])
    for rid, ev in att.items():
        if ev:
            add(rid, ev)

    raw = {}
    for f in findings:
        raw[f["group"]] = raw.get(f["group"], 0) + f["points"]
    group_scores = {g: {"raw": v, "counted": min(v, config.GROUP_CAPS.get(g, 100)), "capped": v > config.GROUP_CAPS.get(g, 100)}
                    for g, v in raw.items()}
    score = min(100, sum(g["counted"] for g in group_scores.values()))
    ids = {f["id"] for f in findings}
    steps = list(BASE_STEPS)
    for f in findings:
        if f["points"] > 0 and f["step"] not in steps:
            steps.insert(-2, f["step"])

    indicators = [{"type": "url", "value": i["url"]} for i in p["urls"]]
    indicators += [{"type": "url_domain", "value": d} for d in domains]
    indicators += [{"type": "attachment_sha256", "value": a["sha256"]} for a in p["attachments"] if a["size"]]
    for t, v in (("sender_addr", p["from_addr"]), ("sender_domain", fd), ("reply_to_domain", rd)):
        if v:
            indicators.append({"type": t, "value": v})
    return {
        "score": score, "category": _category(score, th), "thresholds": th, "group_scores": group_scores,
        "engine": {"version": __version__, "ruleset": ruleset_version()},
        "findings": sorted(findings, key=lambda f: -f["points"]),
        "indicators": indicators, "recommended_steps": steps, "limitations": LIMITATIONS,
        "note": "Heuristic score - not a probability. A low score does not prove an email is safe.",
    }
