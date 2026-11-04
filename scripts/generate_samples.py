"""Generate SYNTHETIC .eml files for safe testing. Domains are fictional/inert; no real malware."""
import random
import sys
from email.message import EmailMessage
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "samples"
OUT.mkdir(parents=True, exist_ok=True)
AUTH_OK = "mx.example.net; spf=pass; dkim=pass; dmarc=pass"
AUTH_BAD = "mx.example.net; spf=fail; dkim=fail; dmarc=fail"


def make(name, frm, subj, text, html=None, auth=AUTH_OK, reply_to=None, rpath=None, atts=()):
    random.seed(name)  # reproducible MIME boundaries
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = frm, "student@example.org", subj
    m["Date"] = "Tue, 27 Oct 2026 09:30:00 +0530"
    m["Message-ID"] = f"<{name}@synthetic.test>"
    if auth:
        m["Authentication-Results"] = auth
    if reply_to:
        m["Reply-To"] = reply_to
    if rpath:
        m["Return-Path"] = rpath
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    for fn, data in atts:
        m.add_attachment(data, maintype="application", subtype="octet-stream", filename=fn)
    (OUT / f"{name}.eml").write_bytes(bytes(m))


make("01_benign_newsletter", "Campus News <news@university.example.org>", "October newsletter",
     "Hello, the library will be open late during exams. See https://university.example.org/library for hours.")
make("02_paypal_lookalike", "PayPal Support <security@paypa1.com>", "Urgent: verify your account",
     "Your account will be suspended. Log in at the link to confirm your password.",
     html='<p>Urgent action required.</p><a href="http://paypa1.com/secure/login">https://www.paypal.com/login</a>',
     auth=AUTH_BAD, reply_to="helpdesk@mail-collector.example.net")
make("03_sbi_ip_link", "SBI Alerts <alerts@sbi-kyc-update.top>", "KYC update immediately",
     "Dear customer, your KYC expires. Update your details now: http://192.0.2.45/sbi/kyc.php and enter OTP and card number.",
     auth=AUTH_BAD)
make("04_invoice_exe", "Accounts <billing@vendor-pay.example.net>", "Invoice overdue - pay now",
     "Please see the attached invoice. Payment overdue; wire transfer required.", auth=None,
     atts=[("invoice_2026.pdf.exe", b"SYNTHETIC-NOT-REAL-MALWARE-1")])
make("05_campaign_a", "HR Desk <hr@payroll-portal.example.net>", "Action required: salary revision",
     "Login to review: https://payroll-portal.example.net/review and confirm your account.",
     reply_to="collect@mail-collector.example.net", auth=AUTH_BAD)
make("06_campaign_b", "IT Helpdesk <it@payroll-portal.example.net>", "Password expires within 24 hours",
     "Your password will expire. Sign in: https://payroll-portal.example.net/review", auth=AUTH_BAD)
make("07_macro_doc", "Vendor <sales@supplier.example.com>", "Quote",
     "Quote attached.", atts=[("quote.xlsm", b"SYNTHETIC-MACRO-DOC")])
make("08_short_link", "Friend <friend@example.com>", "Check this out",
     "Look: https://bit.ly/abc123", auth=None)
make("10_disguised_exe", "Reports <reports@supplier.example.com>", "Monthly report",
     "Report attached.", atts=[("report.pdf", b"MZ\x90\x00SYNTHETIC-PE-MARKER-NOT-EXECUTABLE")])
make("11_xss_probe", "Tester <t@example.com>", "<script>alert(1)</script> & <img src=x onerror=alert(2)>",
     "Body with <b>html</b> and <script>alert(3)</script> text", auth=None)
(OUT / "09_malformed.eml").write_bytes(b"\x00\x01\x02 not really an email \xff\xfe")
print(f"Wrote 11 synthetic samples to {OUT}")
