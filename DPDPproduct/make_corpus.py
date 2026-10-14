#!/usr/bin/env python3
"""Generate a synthetic corpus with known PII counts (ground truth) + hard negatives.
All values are random/synthetic. Usage: python make_corpus.py [outdir] [seed]"""
import json
import os
import random
import shutil
import string
import sys
import zipfile
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pii_scan import verhoeff_check_digit, verhoeff_ok, luhn_ok  # noqa: E402

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")
rnd = random.Random(int(sys.argv[2]) if len(sys.argv) > 2 else 42)
truth = defaultdict(lambda: defaultdict(int))  # rel path -> type -> count

FIRST = ["Asha", "Ravi", "Meena", "Arjun", "Divya", "Karthik", "Lakshmi", "Suresh", "Anita", "Vijay"]
LAST = ["Nair", "Menon", "Iyer", "Pillai", "Sharma", "Reddy", "Das", "Kumar", "Varma", "Joseph"]


def name():
    return rnd.choice(FIRST) + " " + rnd.choice(LAST)


def aadhaar(fmt=None):
    base = str(rnd.randint(2, 9)) + "".join(rnd.choice(string.digits) for _ in range(10))
    n = base + verhoeff_check_digit(base)
    assert verhoeff_ok(n)
    fmt = fmt or rnd.choice(["plain", "space", "dash"])
    return {"plain": n, "space": " ".join([n[:4], n[4:8], n[8:]]), "dash": "-".join([n[:4], n[4:8], n[8:]])}[fmt]


def pan():
    return ("".join(rnd.choice(string.ascii_uppercase) for _ in range(3)) + rnd.choice("ABCFGHLJPTK")
            + rnd.choice(string.ascii_uppercase) + "".join(rnd.choice(string.digits) for _ in range(4))
            + rnd.choice(string.ascii_uppercase))


def card():
    prefix = rnd.choice(["4", "51", "52", "53", "60", "65"])
    body = prefix + "".join(rnd.choice(string.digits) for _ in range(15 - len(prefix)))
    for d in range(10):
        if luhn_ok(body + str(d)):
            n = body + str(d)
            break
    return rnd.choice([n, " ".join(n[i:i + 4] for i in range(0, 16, 4)), "-".join(n[i:i + 4] for i in range(0, 16, 4))])


def phone():
    n = rnd.choice("6789") + "".join(rnd.choice(string.digits) for _ in range(9))
    return rnd.choice([n, "+91 " + n[:5] + " " + n[5:], "+91" + n, n[:5] + "-" + n[5:], "0" + n])


def email(n=None):
    n = (n or name()).lower().replace(" ", ".")
    return n + "@" + rnd.choice(["gmail.com", "yahoo.co.in", "acme-corp.in", "outlook.com"])


def ifsc():
    return rnd.choice(["SBIN", "HDFC", "ICIC", "UTIB", "KKBK"]) + "0" + "".join(rnd.choice(string.digits + string.ascii_uppercase) for _ in range(6))


def acct():
    return "".join(rnd.choice(string.digits) for _ in range(rnd.randint(10, 16)))


def dob():
    return "%02d/%02d/%d" % (rnd.randint(1, 28), rnd.randint(1, 12), rnd.randint(1960, 2002))


def passport():
    return rnd.choice("ABCDEFGHJKLMNPRSTUVWXY") + str(rnd.randint(1, 9)) + "".join(rnd.choice(string.digits) for _ in range(6))


def voter():
    return "".join(rnd.choice(string.ascii_uppercase) for _ in range(3)) + "".join(rnd.choice(string.digits) for _ in range(7))


def upi():
    return rnd.choice(["asha.nair", "ravi123", "meena_s", "karthik.v"]) + "@" + rnd.choice(["okaxis", "ybl", "oksbi", "paytm"])


def path(rel):
    p = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    return p


def write(rel, text):
    with open(path(rel), "w", encoding="utf-8", newline="") as f:
        f.write(text)


def t(rel, typ, n=1):
    truth[rel][typ] += n


if os.path.exists(OUT):
    shutil.rmtree(OUT)

# ---- 1. CSV: HR master (Downloads) -- column-header context ----------------
rel = "Downloads/hr_employee_master.csv"
rows = ["Name,Aadhaar No,PAN,Mobile,Email,DOB,Bank Account,IFSC"]
for _ in range(40):
    nm = name()
    rows.append(",".join([nm, aadhaar(), pan(), phone(), email(nm), dob(), acct(), ifsc()]))
    for typ in ("aadhaar", "pan", "phone", "email", "dob", "bank_account", "ifsc"):
        t(rel, typ)
write(rel, "\n".join(rows) + "\n")

# ---- 2. XLSX (hand-built, numeric Aadhaar incl. scientific notation) -------
rel = "Downloads/salary_sheet.xlsx"


def col(i):
    return "ABCDEFG"[i]


hdr = ["Employee", "Aadhaar", "PAN", "Account No", "IFSC"]
sheet_rows = []
cells = "".join('<c r="%s1" t="inlineStr"><is><t>%s</t></is></c>' % (col(i), h) for i, h in enumerate(hdr))
sheet_rows.append('<row r="1">%s</row>' % cells)
for r in range(2, 17):
    a = aadhaar("plain")
    av = a
    if r == 5:  # one row stored in scientific notation, as Excel does for long numbers
        av = "%s.%sE11" % (a[0], a[1:])
    cells = ('<c r="A%d" t="inlineStr"><is><t>%s</t></is></c>' % (r, name())
             + '<c r="B%d"><v>%s</v></c>' % (r, av)
             + '<c r="C%d" t="inlineStr"><is><t>%s</t></is></c>' % (r, pan())
             + '<c r="D%d"><v>%s</v></c>' % (r, acct())
             + '<c r="E%d" t="inlineStr"><is><t>%s</t></is></c>' % (r, ifsc()))
    sheet_rows.append('<row r="%d">%s</row>' % (r, cells))
    for typ in ("aadhaar", "pan", "bank_account", "ifsc"):
        t(rel, typ)
ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
with zipfile.ZipFile(path(rel), "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>')
    z.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
    z.writestr("xl/workbook.xml", '<?xml version="1.0"?><workbook %s xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>' % ns)
    z.writestr("xl/_rels/workbook.xml.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>')
    z.writestr("xl/worksheets/sheet1.xml", '<?xml version="1.0"?><worksheet %s><sheetData>%s</sheetData></worksheet>' % (ns, "".join(sheet_rows)))


# ---- 3. DOCX offer letters --------------------------------------------------
def make_docx(rel, paras):
    body = "".join('<w:p><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>' % p for p in paras)
    with zipfile.ZipFile(path(rel), "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        z.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        z.writestr("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>%s</w:body></w:document>' % body)


for i in range(3):
    rel = "Downloads/offer_letter_%d.docx" % i
    nm = name()
    make_docx(rel, ["Offer of employment", "Dear %s," % nm,
                    "Please confirm your PAN: %s and mobile number %s." % (pan(), phone()),
                    "Your email on record is %s. Date of birth: %s." % (email(nm), dob()),
                    "We look forward to welcoming you."])
    for typ in ("pan", "phone", "email", "dob"):
        t(rel, typ)

# ---- 4. Free text: Aadhaar notes, cards, UPI --------------------------------
rel = "Downloads/scan_notes.txt"
lines = ["Meeting notes - onboarding", "",
         "Employee Aadhaar: %s" % aadhaar("space"),
         "UID number is %s (verified)" % aadhaar("plain"),
         "aadhar no - %s" % aadhaar("dash"),
         "Her aadhaar card number: %s." % aadhaar("space"),
         "Number found on form (no label): %s" % aadhaar("plain"),  # medium confidence expected
         "Call me on mobile %s tomorrow." % phone()]
for _ in range(5):
    t(rel, "aadhaar")
t(rel, "phone")
write(rel, "\n".join(lines) + "\n")

rel = "Downloads/customer_cards.txt"
lines = ["Refund log"]
for _ in range(6):
    lines.append("Customer %s paid with card %s" % (name(), card()))
    t(rel, "card")
for _ in range(3):
    lines.append("UPI handle: %s" % upi())
    t(rel, "upi")
lines.append("Contact phone: %s" % phone())
t(rel, "phone")
write(rel, "\n".join(lines) + "\n")

rel = "Downloads/kyc_details.json"
write(rel, json.dumps({"applicant": {"name": name(), "passport": "Passport No: " + passport(),
                                    "voter": "EPIC No: " + voter(), "dob": "DOB: " + dob(),
                                    "contact": {"email": "email: " + email()}}}, indent=1))
for typ in ("passport", "voter_id", "dob", "email"):
    t(rel, typ)

# ---- 5. Big log with PII straddling the 1 MiB read-chunk boundaries ---------
rel = "Desktop/app_server.log"
words = ["INFO", "request", "completed", "status=200", "user", "session", "cache", "hit", "latency", "ms", "GET", "/api/v1/items"]
text = "\n".join(" ".join(rnd.choice(words) for _ in range(12)) + " id=%d" % rnd.randint(10 ** 6, 10 ** 7) for _ in range(40000))
CH = 1 << 20
plants = [(CH - 9, " Aadhaar: %s " % aadhaar("space"), "aadhaar"),
          (2 * CH - 7, " PAN: %s " % pan(), "pan"),
          (500000, " email: %s " % email(), "email"),
          (3 * CH - 20, " card %s " % card(), "card")]
shift = 0
for off, s, typ in plants:
    text = text[:off + shift] + s + text[off + shift:]
    shift += len(s)
    t(rel, typ)
write(rel, text + "\n")
print("log size: %d bytes" % len(text))

rel = "Desktop/hr_notes.txt"
write(rel, "Reminder: renew Passport %s before travel.\nDate of birth: %s for the new joiner.\n" % (passport(), dob()))
t(rel, "dob")  # 'Passport <no>' pattern requires 'passport' prefix directly -> see below
# "Passport %s" matches the passport pattern (keyword + number)
t(rel, "passport")

# ---- 6. HR share (approved location) ----------------------------------------
rel = "HR_Share/payroll_march.csv"
rows = ["Employee,Aadhaar,PAN,Account No,IFSC"]
for _ in range(10):
    rows.append(",".join([name(), aadhaar(), pan(), acct(), ifsc()]))
    for typ in ("aadhaar", "pan", "bank_account", "ifsc"):
        t(rel, typ)
write(rel, "\n".join(rows) + "\n")

# ---- 7. Hard negatives (should produce nothing, except noted FPs) -----------
neg = ["Invoice and reference numbers (all fail checksums):"]
for _ in range(8):
    while True:
        n = str(rnd.randint(2, 8)) + "".join(rnd.choice(string.digits) for _ in range(11))
        if not verhoeff_ok(n):
            break
    neg.append("Invoice No: %s" % n)
for _ in range(5):
    while True:
        n = str(rnd.choice("3456")) + "".join(rnd.choice(string.digits) for _ in range(15))
        if not luhn_ok(n):
            break
    neg.append("Txn ref: %s" % n)
neg += ["ORD-2026-00012345", "Build 10.2.3.4567 on host 192.168.1.100", "epoch=1759742000 ts=1696583211",
        "uuid 123e4567-e89b-12d3-a456-426614174000", "PAN-like product codes: ABCDE1234F XYZQR5678T (4th letter invalid)",
        "lowercase code sbin0001234", "user@localhost", "order qty 5012345678 units", "release date 12/05/1990 shipped",
        "Shipment ref: 9123456780", "Shipment ref: 8123456789", "Shipment ref: 7123456780"]
rel = "Misc/hard_negatives.txt"
write(rel, "\n".join(neg) + "\n")
# Note: the 3 'Shipment ref' 10-digit numbers look like Indian mobiles -> expected LOW-confidence phone FPs.
write("Misc/clean_report.txt", "Quarterly summary: revenue grew 12% while costs fell 3%.\n" * 50)
write("Misc/clean_data.csv", "sku,qty,price\n" + "\n".join("SKU%04d,%d,%d.50" % (i, i % 40, 100 + i) for i in range(200)) + "\n")

# ---- 8. Files the scanner cannot read (must be reported, never silently passed)
with open(path("Misc/setup.exe"), "wb") as f:
    f.write(b"MZ" + os.urandom(1000))
with open(path("Misc/legacy.xls"), "wb") as f:
    f.write(b"\xd0\xcf\x11\xe0" + os.urandom(1000))
with open(path("Misc/encrypted.docx"), "wb") as f:
    f.write(b"\xd0\xcf\x11\xe0" + os.urandom(1000))
with open(path("Misc/scan_image.pdf"), "wb") as f:
    f.write(b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n")

manifest = {k: dict(v) for k, v in truth.items()}
with open(os.path.join(os.path.dirname(OUT.rstrip("/")) or ".", "manifest.json"), "w") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
print("corpus written to", OUT, "| files with ground truth:", len(manifest),
      "| total planted:", sum(sum(v.values()) for v in manifest.values()))
