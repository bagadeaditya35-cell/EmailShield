"""Safe .eml parser. Attachments are only hashed and measured - never executed or saved."""
import hashlib
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser

URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.I)
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
MAX_TEXT = 20000


class _HTMLExtract(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.links = [], []
        self._href, self._atext, self._skip = None, [], 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a" and a.get("href"):
            self._href, self._atext = a["href"], []
        elif tag in ("img", "iframe", "form"):
            src = a.get("src") or a.get("action")
            if src:
                self.links.append((src, ""))

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._atext).split())))
            self._href = None

    def handle_data(self, d):
        if self._skip:
            return
        self.text.append(d)
        if self._href is not None:
            self._atext.append(d)


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[1].lower().strip(">") if "@" in addr else ""


def _hdr(msg, name) -> str:
    try:
        return str(msg.get(name, "") or "")
    except Exception:
        return ""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def detect_type(data: bytes) -> str:
    """Identify content by magic bytes only (never executes anything)."""
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] == b"%PDF":
        return "pdf"
    if data[:8] == bytes.fromhex("D0CF11E0A1B11AE1"):
        return "ole"
    if data[:2] == b"PK":
        return "zip"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    return "unknown"


def parse_eml(raw: bytes, attachment_scanner=None) -> dict:
    if not raw or not raw.strip():
        raise ValueError("Empty file")
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    errors = []

    from_name, from_addr = parseaddr(_hdr(msg, "From"))
    _, reply_addr = parseaddr(_hdr(msg, "Reply-To"))
    _, rpath_addr = parseaddr(_hdr(msg, "Return-Path"))
    from_addr, reply_addr, rpath_addr = from_addr.lower(), reply_addr.lower(), rpath_addr.lower()

    auth = {}
    for h in (msg.get_all("Authentication-Results") or []) + (msg.get_all("Received-SPF") or []):
        text = str(h)
        for mech, result in AUTH_RE.findall(text):
            auth.setdefault(mech.lower(), result.lower())
        if text.lower().startswith(("pass", "fail", "softfail", "neutral", "none")):
            auth.setdefault("spf", text.split()[0].lower())

    plain, html_text, links = "", "", []
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        fname = part.get_filename()
        disp = (part.get_content_disposition() or "").lower()
        try:
            if fname or disp == "attachment":
                data = part.get_payload(decode=True) or b""
                attachments.append({
                    "filename": str(fname or "(unnamed)")[:255],
                    "content_type": ctype,
                    "size": len(data),
                    "sha256": sha256_hex(data),
                    "detected_type": detect_type(data),
                    "yara": [],
                })
                if attachment_scanner and data:
                    try:
                        attachments[-1]["yara"] = list(attachment_scanner(attachments[-1]["filename"], data))[:20]
                    except Exception as e:
                        errors.append(f"Scanner: {type(e).__name__}")
            elif ctype == "text/plain" and not plain:
                plain = part.get_content()
            elif ctype == "text/html":
                parser = _HTMLExtract()
                parser.feed(part.get_content())
                html_text += " ".join(parser.text)
                links += parser.links
        except Exception as e:  # malformed parts must never crash analysis
            errors.append(f"Part {ctype}: {type(e).__name__}")

    body = plain or html_text
    urls, seen = [], set()
    for u, t in links + [(m, "") for m in URL_RE.findall(plain or html_text)]:
        u = u.strip().rstrip(".,;:!?")
        if not re.match(r"https?://", u, re.I) or u in seen:
            continue
        seen.add(u)
        urls.append({"url": u[:2000], "text": t[:200]})

    return {
        "raw_sha256": sha256_hex(raw),
        "subject": _hdr(msg, "Subject")[:500],
        "from_name": from_name, "from_addr": from_addr, "from_domain": _domain(from_addr),
        "reply_to_addr": reply_addr, "reply_to_domain": _domain(reply_addr),
        "return_path_addr": rpath_addr, "return_path_domain": _domain(rpath_addr),
        "to": _hdr(msg, "To")[:500], "date": _hdr(msg, "Date"), "message_id": _hdr(msg, "Message-ID"),
        "received_hops": len(msg.get_all("Received") or []),
        "auth": auth,
        "text": body[:MAX_TEXT],
        "has_html": bool(html_text or links),
        "urls": urls,
        "attachments": attachments,
        "parse_errors": errors,
    }
