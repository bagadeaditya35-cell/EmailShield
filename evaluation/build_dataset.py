"""Builds a labelled SYNTHETIC email dataset (harmless: fictional domains, inert marker bytes).
Label 1 = phishing/malicious-delivery, 0 = legitimate. Deterministic (fixed seed).
Written by the same author as the detection rules, so it is NOT an independent benchmark."""
import csv
import random
from email.message import EmailMessage
from pathlib import Path

OUT = Path(__file__).resolve().parent / "dataset"
OK = "mx.example.net; spf=pass; dkim=pass; dmarc=pass"
BAD = "mx.example.net; spf=fail; dkim=fail; dmarc=fail"
rng = random.Random(42)
rows = []


def mk(name, label, tag, frm, subj, body, html=None, auth=OK, reply_to=None, rpath=None, atts=()):
    random.seed(name)  # MIME boundaries use the global RNG; seeding makes files byte-reproducible
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = frm, "user@example.org", subj
    m["Date"] = "Tue, 27 Oct 2026 09:30:00 +0530"
    m["Message-ID"] = f"<{name}@synthetic.test>"
    if auth:
        m["Authentication-Results"] = auth
    if reply_to:
        m["Reply-To"] = reply_to
    if rpath:
        m["Return-Path"] = rpath
    m.set_content(body)
    if html:
        m.add_alternative(html, subtype="html")
    for fn, data in atts:
        m.add_attachment(data, maintype="application", subtype="octet-stream", filename=fn)
    OUT.mkdir(exist_ok=True)
    (OUT / f"{name}.eml").write_bytes(bytes(m))
    rows.append((f"{name}.eml", label, tag))


names = ["Asha", "Rohan", "Meera", "Karan", "Neha", "Vikram"]
orgs = ["northwind", "contoso-labs", "fabrikam-edu", "tailspin-co", "adatum-corp", "litware-inc"]

# ---------------- legitimate (label 0) ----------------
for i in range(12):
    o = orgs[i % 6]
    kind = i % 4
    subj, body = [
        ("Weekly newsletter", f"News from the team. Read more at https://www.{o}.example.org/news"),
        ("Meeting notes", "Attached are the notes. Please add comments by Friday."),
        ("Your order has shipped", f"Track it at https://shop.{o}.example.org/track/123"),
        ("Library hours", "Extended opening during exams. See the website for details."),
    ][kind]
    mk(f"ben_plain_{i:02d}", 0, "ordinary", f"{names[i % 6]} <{names[i % 6].lower()}@{o}.example.org>", subj, body)

# hard negatives: legitimate mail that trips heuristics
for i in range(3):
    o = orgs[i]
    mk(f"ben_hard_reset_{i}", 0, "hard-negative: legit password reset", f"Accounts <no-reply@accounts.google.com>",
       "Password reset requested", "Someone asked to reset your password. If this was you, log in at https://accounts.google.com/reset and verify your account. Urgent if not you.")
for i in range(4):
    o = orgs[i]
    mk(f"ben_hard_esp_{i}", 0, "hard-negative: billing via mail platform", f"Billing <billing@{o}.example.org>",
       "Invoice available - pay now", "Your invoice is ready. Pay now via the portal: https://pay.%s.example.org/inv/%d" % (o, 100 + i),
       reply_to=f"support@helpdesk-platform.example.net", rpath=f"bounce@mailer-platform.example.net")
for i in range(3):
    mk(f"ben_hard_fwd_{i}", 0, "hard-negative: forwarded mail failing SPF/DKIM", f"Colleague <colleague@{orgs[i]}.example.org>",
       "Fwd: schedule", "Forwarding the schedule below.", auth="mx.example.net; spf=fail; dkim=fail; dmarc=pass",
       reply_to=f"colleague@{orgs[i + 1]}.example.org")
for i in range(3):
    mk(f"ben_hard_att_{i}", 0, "hard-negative: macro/zip attachments from colleague", f"Finance <finance@{orgs[i]}.example.org>",
       "Budget workbook - action required", "Please review the attached budget workbook. Action required this week; refund figures included.",
       atts=[("budget.xlsm", b"SYNTHETIC-MACRO-DOC")] if i < 2 else [("photos.zip", b"PK\x03\x04SYNTHETIC")])
mk("ben_hard_short", 0, "hard-negative: shortener link", "Events <events@fabrikam-edu.example.org>", "Event RSVP", "RSVP here: https://bit.ly/rsvp-demo")
mk("ben_hard_noauth", 0, "hard-negative: exported without auth headers", "Asha <asha@northwind.example.org>", "Lunch?", "Lunch at noon?", auth=None)

# ---------------- malicious (label 1) ----------------
brands = [("PayPal", "paypa1.com"), ("Microsoft", "micr0soft.com"), ("Google", "g00gle.com"), ("Amazon", "amaz0n.com"), ("Netflix", "netfl1x.com"), ("Apple", "app1e.com")]
for i, (b, dom) in enumerate(brands):
    mk(f"mal_lookalike_{i}", 1, "easy: lookalike domain phish", f"{b} Support <security@{dom}>", f"{b}: verify your account immediately",
       f"Your account will be suspended. Log in to confirm your password: http://{dom}/login", auth=BAD)
for i in range(3):
    mk(f"mal_ip_{i}", 1, "easy: IP-address link", "Bank Alerts <alerts@sbi-kyc-update.top>", "KYC update immediately",
       f"Update your details now: http://203.0.113.{10 + i}/kyc.php and enter OTP and card number.", auth=BAD)
for i in range(3):
    mk(f"mal_exe_{i}", 1, "easy: double-extension executable", "Accounts <billing@vendor-pay.example.net>", "Invoice overdue - pay now",
       "Invoice attached. Payment overdue.", auth=None, atts=[(f"invoice_{i}.pdf.exe", b"SYNTHETIC-NOT-REAL-MALWARE")])
for i in range(2):
    mk(f"mal_disguised_{i}", 1, "medium: executable disguised as PDF", "Reports <reports@supplier.example.com>", "Monthly report",
       "Report attached.", atts=[(f"report{i}.pdf", b"MZ\x90\x00SYNTHETIC-PE-MARKER")])
for i in range(4):
    h = f"https://secure-login.{orgs[i]}-portal.example.net/verify"
    mk(f"mal_mismatch_{i}", 1, "medium: mismatched link text, clean auth", f"IT Desk <it@{orgs[i]}-portal.example.net>", "Sign in to keep your mailbox",
       "Your mailbox needs verification.", html=f'<p>Verify now:</p><a href="{h}">https://mail.{orgs[i]}.example.org/signin</a>')
for i in range(3):
    mk(f"mal_replyto_{i}", 1, "medium: reply-to hijack with urgency", f"HR <hr@{orgs[i]}.example.org>", "Urgent: salary revision",
       "Act now and confirm your account to receive the revised salary.", reply_to=f"collect{i}@mail-collector.example.net", auth=BAD)
for i in range(2):
    mk(f"mal_macro_{i}", 1, "medium: macro document with pressure", "Vendor <sales@supplier.example.com>", "Final notice: quote",
       "Final notice. Open the attached quote immediately.", atts=[("quote.docm", b"SYNTHETIC-MACRO")], auth=BAD)

# hard positives: phishing with little or no technical signal (expected misses)
mk("mal_hard_giftcard", 1, "hard-positive: BEC gift card, no links", "Director <director.office@example.org>", "Quick favour",
   "Are you available? I need you to buy gift card vouchers for a client today. Reply when ready.", auth=None)
mk("mal_hard_cleanlink", 1, "hard-positive: compromised account, clean link", "Meera <meera@northwind.example.org>", "Document for you",
   "Hi, please review the document: https://files.shared-docs.example.net/d/8f3a")
mk("mal_hard_https_verify", 1, "hard-positive: new domain, HTTPS, calm wording", "Support <support@account-services.example.net>", "Please verify your account",
   "We are updating records. Please verify your account at https://account-services.example.net/verify")
mk("mal_hard_callback", 1, "hard-positive: callback phishing, no link", "Billing <billing@orders-desk.example.net>", "Your renewal invoice",
   "Your renewal invoice for the subscription is attached to your account. Call +00 000 0000 to dispute the charge.")
mk("mal_hard_qr", 1, "hard-positive: QR-code image only", "Security <security@staff-portal.example.net>", "Scan to re-enable access",
   "Scan the attached code.", atts=[("code.png", b"\x89PNG\r\n\x1a\nSYNTHETIC")])
mk("mal_hard_zip_pw", 1, "hard-positive: password-protected archive", "Shipping <ship@parcel-desk.example.net>", "Parcel documents",
   "Documents attached. The archive password is 1234.", atts=[("docs.zip", b"PK\x03\x04SYNTHETIC")])

with open(OUT.parent / "labels.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["file", "label", "tag"])
    w.writerows(rows)
print(f"Wrote {len(rows)} samples ({sum(r[1] for r in rows)} malicious, {sum(1 - r[1] for r in rows)} legitimate)")
