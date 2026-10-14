#!/usr/bin/env python3
"""Generate a larger synthetic benchmark tree (speed testing, not accuracy).
All values are random/synthetic. Usage: python make_bench.py [outdir] [scale]

Contents per scale unit: multi-page Flate-compressed PDFs (prose + some PII),
PII-dense CSV exports, a log file, prose text files, docx and xlsx documents.
"""
import os
import random
import shutil
import string
import sys
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pii_scan import verhoeff_check_digit, luhn_ok  # noqa: E402

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "bench")
SCALE = int(sys.argv[2]) if len(sys.argv) > 2 else 10
rnd = random.Random(7)

FIRST = ["Asha", "Ravi", "Meena", "Arjun", "Divya", "Karthik", "Lakshmi", "Suresh", "Anita", "Vijay"]
LAST = ["Nair", "Menon", "Iyer", "Pillai", "Sharma", "Reddy", "Das", "Kumar", "Varma", "Joseph"]
PROSE = ("the proposed method improves accuracy on benchmark datasets while the network model "
         "reduces latency results section figure table analysis experiment baseline training "
         "evaluation metric dataset sample cohort survey response quarterly revenue forecast").split()


def name():
    return rnd.choice(FIRST) + " " + rnd.choice(LAST)


def aadhaar():
    b = str(rnd.randint(2, 9)) + "".join(rnd.choice(string.digits) for _ in range(10))
    n = b + verhoeff_check_digit(b)
    return "%s %s %s" % (n[:4], n[4:8], n[8:])


def pan():
    return "".join(rnd.choice(string.ascii_uppercase) for _ in range(3)) + "P" + \
        rnd.choice(string.ascii_uppercase) + "%04d" % rnd.randint(0, 9999) + rnd.choice(string.ascii_uppercase)


def phone():
    return "+91 %d%04d %05d" % (rnd.randint(6, 9), rnd.randint(0, 9999), rnd.randint(0, 99999))


def card():
    while True:
        n = "4" + "".join(rnd.choice(string.digits) for _ in range(15))
        if luhn_ok(n):
            return " ".join(n[i:i + 4] for i in range(0, 16, 4))


def prose(nwords):
    return " ".join(rnd.choice(PROSE) for _ in range(nwords))


def pii_line():
    n = name()
    return rnd.choice([
        "Employee %s Aadhaar: %s" % (n, aadhaar()),
        "%s PAN %s" % (n, pan()),
        "Contact %s mobile %s" % (n, phone()),
        "Payment card %s for %s" % (card(), n),
        "Email: %s.%d@gmail.com" % (n.split()[0].lower(), rnd.randint(1, 999)),
    ])


# ---------------------------------------------------------------- PDF writer
def _pdf_escape(s):
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def write_pdf(path, pages):
    """pages: list of list-of-lines. Writes a valid PDF with Flate content streams."""
    objs = []

    def add(body):
        objs.append(body)
        return len(objs)

    font = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    pages_id = len(objs) + 1 + 2 * len(pages)  # reserve: each page = content + page obj
    kids = []
    for lines in pages:
        ops = ["BT /F1 9 Tf 11 TL 40 800 Td"]
        for ln in lines:
            ops.append("(%s) Tj T*" % _pdf_escape(ln))
        ops.append("ET")
        raw = zlib.compress("\n".join(ops).encode("latin-1"))
        c = add(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(raw) + raw + b"\nendstream")
        p = add(b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 595 842] /Contents %d 0 R "
                b"/Resources << /Font << /F1 %d 0 R >> >> >>" % (pages_id, c, font))
        kids.append(p)
    add(b"<< /Type /Pages /Kids [%s] /Count %d >>" % (b" ".join(b"%d 0 R" % k for k in kids), len(kids)))
    cat = add(b"<< /Type /Catalog /Pages %d 0 R >>" % pages_id)
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offs = []
    for i, body in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for o in offs:
        out += b"%010d 00000 n \n" % o
    out += b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, cat, xref)
    with open(path, "wb") as f:
        f.write(out)


# ---------------------------------------------------------------- office
def write_docx(path, paras):
    body = "".join("<w:p><w:r><w:t>%s</w:t></w:r></w:p>" % p.replace("&", "&amp;").replace("<", "&lt;") for p in paras)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        z.writestr("word/document.xml",
                   '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                   "<w:body>%s</w:body></w:document>" % body)


def _col(i):
    s = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


def write_xlsx(path, rows):
    shared, idx = [], {}

    def si(v):
        if v not in idx:
            idx[v] = len(shared)
            shared.append(v)
        return idx[v]

    xr = []
    for r, row in enumerate(rows, 1):
        cells = "".join('<c r="%s%d" t="s"><v>%d</v></c>' % (_col(c), r, si(v)) for c, v in enumerate(row))
        xr.append('<row r="%d">%s</row>' % (r, cells))
    ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        z.writestr("xl/sharedStrings.xml", '<?xml version="1.0"?><sst %s>%s</sst>' % (
            ns, "".join("<si><t>%s</t></si>" % s.replace("&", "&amp;").replace("<", "&lt;") for s in shared)))
        z.writestr("xl/worksheets/sheet1.xml", '<?xml version="1.0"?><worksheet %s><sheetData>%s</sheetData></worksheet>' % (ns, "".join(xr)))


def emp_rows(n):
    rows = [["Name", "Aadhaar", "PAN", "Mobile", "Email", "Card Number"]]
    for _ in range(n):
        nm = name()
        rows.append([nm, aadhaar(), pan(), phone(), "%s@example.in" % nm.replace(" ", ".").lower(), card()])
    return rows


def main():
    if os.path.exists(OUT):
        shutil.rmtree(OUT)
    for u in range(SCALE):
        d = os.path.join(OUT, "user%02d" % u, "Downloads")
        os.makedirs(d)
        for i in range(12):  # research-paper-like PDFs, mostly prose
            pages = [[prose(14) if rnd.random() > 0.02 else pii_line() for _ in range(65)]
                     for _ in range(rnd.randint(8, 30))]
            write_pdf(os.path.join(d, "paper_%02d.pdf" % i), pages)
        for i in range(3):  # PII-heavy PDFs (statements, KYC packs)
            pages = [[pii_line() if rnd.random() < 0.5 else prose(10) for _ in range(60)] for _ in range(6)]
            write_pdf(os.path.join(d, "statement_%02d.pdf" % i), pages)
        rows = emp_rows(3000)
        with open(os.path.join(d, "crm_export.csv"), "w", encoding="utf-8") as f:
            for r in rows:
                f.write(",".join(r) + "\n")
        write_xlsx(os.path.join(d, "employees.xlsx"), emp_rows(800))
        for i in range(4):
            write_docx(os.path.join(d, "letter_%d.docx" % i), [prose(40) for _ in range(60)] + [pii_line() for _ in range(5)])
        for i in range(8):
            with open(os.path.join(d, "notes_%d.txt" % i), "w", encoding="utf-8") as f:
                f.write("\n".join(prose(20) if rnd.random() > 0.05 else pii_line() for _ in range(2000)))
        with open(os.path.join(d, "app_server.log"), "w", encoding="utf-8") as f:
            for i in range(30000):
                f.write("2026-10-06 12:%02d:%02d INFO req=%d user=%s ip=10.0.%d.%d %s\n" % (
                    i // 60 % 60, i % 60, 100000 + i, rnd.choice(FIRST).lower(), rnd.randint(0, 255),
                    rnd.randint(0, 255), pii_line() if rnd.random() < 0.03 else "ok"))
        for i in range(10):  # unsupported files: must be skipped quickly
            with open(os.path.join(d, "tool_%d.exe" % i), "wb") as f:
                f.write(os.urandom(200_000))
    total = sum(os.path.getsize(os.path.join(dp, f)) for dp, _, fs in os.walk(OUT) for f in fs)
    nfiles = sum(len(fs) for _, _, fs in os.walk(OUT))
    print("bench written to %s | %d files | %.1f MB" % (OUT, nfiles, total / 1e6))


if __name__ == "__main__":
    main()
