#!/usr/bin/env python3
"""
pii_scan.py - endpoint PII discovery scanner (DPDP PoC)

* Standard library only (Python 3.8+), single file: easy to push through an EDR.
* Detects India-centric identifiers with checksum/format validation + context.
* Never stores file content. Reports counts, confidence, location and (optionally)
  masked samples. SHA-256 is recorded for files with findings so results can be
  correlated with the EDR's FIM hashes.
* Role profiles decide whether PII found in a location is expected or a violation.

Usage:
  python pii_scan.py --role hr --paths ~/Downloads ~/Desktop --output report.json
  python pii_scan.py --role general --status-file status.json     # for a live UI
"""
import argparse
import bisect
import csv
import datetime
import hashlib
import io
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import zipfile
import xml.etree.ElementTree as ET
from decimal import Decimal, InvalidOperation

VERSION = "0.3.0"

# --------------------------------------------------------------------------
# Validators
# --------------------------------------------------------------------------
_VD = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
       [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
       [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
       [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
       [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_VP = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
       [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
       [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
       [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]
_VINV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_ok(num: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _VD[c][_VP[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(num: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _VD[c][_VP[(i + 1) % 8][int(ch)]]
    return str(_VINV[c])


def luhn_ok(num: str) -> bool:
    total, alt = 0, False
    for ch in reversed(num):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def card_prefix_ok(d: str) -> bool:
    return d[0] in "3456" or d[:2] in ("81", "82") or d[:3] == "508"


# --------------------------------------------------------------------------
# Detectors
# --------------------------------------------------------------------------
RE_AADHAAR = re.compile(r"(?<!\d)(?<!\d[ -])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![ -]?\d)")
RE_PAN = re.compile(r"(?<![A-Za-z0-9])[A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z](?![A-Za-z0-9])")
RE_IFSC = re.compile(r"(?<![A-Za-z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Za-z0-9])")
RE_CARD = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?!\d)")
RE_PHONE = re.compile(r"(?<![\d+\-])(?:(?:\+91|0091|91|0)[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")
RE_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])")
RE_UPI = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._-]{2,}@(?:ok(?:axis|sbi|hdfcbank|icici)|ybl|ibl|axl|paytm|upi|apl|"
    r"sbi|hdfcbank|icici|axisbank|fbl|ikwik|airtel|jio|freecharge|barodampay|postbank)(?![\w.-])")
RE_BANK = re.compile(
    r"(?i)\b(?:a/?c|acc(?:ount)?|bank\s*acc(?:ount)?)\.?\s*(?:no\.?|number|num|#)?\s*[:\-#]?\s*(\d{9,18})(?!\d)")
RE_PASSPORT = re.compile(r"(?i)passport(?:\s*(?:no\.?|number|#))?\s*[:\-#]?\s*([A-PR-WY][1-9]\d{6})(?!\w)")
RE_VOTER = re.compile(r"(?i)(?:epic|voter\s*id|voter)(?:\s*(?:no\.?|number|#|card))?\s*[:\-#]?\s*([A-Z]{3}\d{7})(?!\w)")
RE_DOB = re.compile(
    r"(?i)(?:\bdob\b|d\.o\.b\.?|date\s+of\s+birth|birth\s*date)\s*[:\-]?\s*(\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4})")

CTX = {
    "aadhaar": re.compile(r"(?i)aadh?a+r|uidai|\buid\b"),
    "pan": re.compile(r"(?i)\bpan\b|permanent\s+account|income\s*tax"),
    "phone": re.compile(r"(?i)mobile|phone|\bph\b|contact|\bmob\b|\bcell\b|\btel\b|whatsapp|\bcall\b"),
    "email": re.compile(r"(?i)e-?mail|\bmail\b"),
    "ifsc": re.compile(r"(?i)ifsc"),
    "card": re.compile(r"(?i)card|credit|debit|visa|master\s*card|rupay|\bcvv\b|\bpayment\b"),
}
FREE_MAIL = re.compile(r"(?i)@(gmail|yahoo|outlook|hotmail|rediffmail|icloud|proton|live)\.")


def has_ctx(text, s, e, key):
    window = text[max(0, s - 40):s] + " " + text[e:e + 15]
    return CTX[key].search(window) is not None


def scan_text(text):
    """Return list of (type, confidence, value, start, end)."""
    # Claimed spans are kept sorted by start so the overlap test is a bisect over a
    # short window instead of a scan of every earlier hit (that was O(n^2) on
    # PII-dense files such as exports and logs).
    out, starts, ends = [], [], []
    longest = [0]

    def overlaps(s, e):
        i = bisect.bisect_left(starts, s - longest[0])
        j = bisect.bisect_left(starts, e)
        for k in range(i, j):
            if s < ends[k]:
                return True
        return False

    def add(t, c, v, s, e):
        out.append((t, c, v, s, e))
        k = bisect.bisect_left(starts, s)
        starts.insert(k, s)
        ends.insert(k, e)
        if e - s > longest[0]:
            longest[0] = e - s

    # 1. context-required identifiers
    for m in RE_BANK.finditer(text):
        s, e = m.span(1)
        near = text[max(0, s - 80):e + 80]
        conf = "high" if (RE_IFSC.search(near) or CTX["ifsc"].search(near)) else "medium"
        add("bank_account", conf, m.group(1), s, e)
    for m in RE_PASSPORT.finditer(text):
        add("passport", "medium", m.group(1), *m.span(1))
    for m in RE_VOTER.finditer(text):
        add("voter_id", "medium", m.group(1), *m.span(1))
    for m in RE_DOB.finditer(text):
        add("dob", "medium", m.group(1), *m.span(1))

    # 2. cards
    for m in RE_CARD.finditer(text):
        s, e = m.span()
        d = re.sub(r"\D", "", m.group())
        if 13 <= len(d) <= 19 and card_prefix_ok(d) and luhn_ok(d) and not overlaps(s, e):
            # Luhn passes ~10% of random digit strings, so context is needed for "high"
            add("card", "high" if has_ctx(text, s, e, "card") else "medium", d, s, e)

    # 3. UPI, email
    for m in RE_UPI.finditer(text):
        s, e = m.span()
        if not overlaps(s, e):
            add("upi", "medium", m.group(), s, e)
    for m in RE_EMAIL.finditer(text):
        s, e = m.span()
        if overlaps(s, e):
            continue
        if has_ctx(text, s, e, "email"):
            conf = "high"
        elif FREE_MAIL.search(m.group()):
            conf = "medium"
        else:
            conf = "low"
        add("email", conf, m.group(), s, e)

    # 4. Aadhaar (Verhoeff). Checksum alone passes ~10% of random 12-digit strings,
    #    so only context makes it "high".
    for m in RE_AADHAAR.finditer(text):
        s, e = m.span()
        d = re.sub(r"\D", "", m.group())
        if overlaps(s, e) or len(set(d)) < 3 or not verhoeff_ok(d):
            continue
        add("aadhaar", "high" if has_ctx(text, s, e, "aadhaar") else "medium", d, s, e)

    # 5. PAN, IFSC
    for m in RE_PAN.finditer(text):
        s, e = m.span()
        if not overlaps(s, e):
            add("pan", "high" if has_ctx(text, s, e, "pan") else "medium", m.group(), s, e)
    for m in RE_IFSC.finditer(text):
        s, e = m.span()
        if not overlaps(s, e):
            add("ifsc", "high" if has_ctx(text, s, e, "ifsc") else "medium", m.group(), s, e)

    # 6. phone (weakest pattern - many false hits without context)
    for m in RE_PHONE.finditer(text):
        s, e = m.span()
        if overlaps(s, e):
            continue
        raw = m.group()
        d = re.sub(r"\D", "", raw)
        ctx = has_ctx(text, s, e, "phone")
        if len(d) == 12 and d.startswith("91") and "+" not in raw and not ctx:
            continue  # bare 91xxxxxxxxxx without context: too ambiguous
        if ctx:
            conf = "high"
        elif raw.startswith("+91") or raw.startswith("0091"):
            conf = "medium"
        else:
            conf = "low"
        add("phone", conf, d[-10:], s, e)
    return out


# --------------------------------------------------------------------------
# Aggregation, masking, scoring
# --------------------------------------------------------------------------
CONF_W = {"high": 1.0, "medium": 0.5, "low": 0.1}
TYPE_W = {"aadhaar": 10, "card": 10, "pan": 8, "passport": 8, "bank_account": 8,
          "voter_id": 6, "upi": 4, "dob": 3, "ifsc": 2, "phone": 2, "email": 1}


def mask(v: str) -> str:
    if "@" in v:
        local, dom = v.split("@", 1)
        return local[:1] + "***@" + dom
    return "X" * max(0, len(v) - 4) + v[-4:]


class Agg:
    def __init__(self, want_samples=False):
        self.counts = {}
        self.uniq = {}
        self.samples = {}
        self.want_samples = want_samples

    def add(self, f):
        t, c, v = f[0], f[1], f[2]
        self.counts.setdefault(t, {"high": 0, "medium": 0, "low": 0})[c] += 1
        self.uniq.setdefault(t, set()).add(hashlib.sha1(v.encode()).hexdigest()[:12])
        if self.want_samples:
            lst = self.samples.setdefault(t, [])
            if len(lst) < 3:
                lst.append(mask(v))

    def result(self):
        types = {}
        for t, c in self.counts.items():
            types[t] = dict(c, count=sum(c.values()), unique=len(self.uniq[t]))
        return types


def score_types(types):
    total, distinct = 0.0, 0
    for t, c in types.items():
        w = c["high"] * CONF_W["high"] + c["medium"] * CONF_W["medium"] + c["low"] * CONF_W["low"]
        total += TYPE_W.get(t, 1) * min(w, 10)
        if c["high"] or c["medium"]:
            distinct += 1
    if distinct >= 5:
        total *= 2.0
    elif distinct >= 3:
        total *= 1.5
    return round(total, 1)


def tier(score):
    if score >= 100:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 10:
        return "medium"
    return "low" if score > 0 else "none"


# --------------------------------------------------------------------------
# Role profiles (override with --profile file.json)
# --------------------------------------------------------------------------
_DISALLOWED = ["downloads", "desktop", "temp", "tmp", "onedrive - personal",
               "dropbox", "google drive", "icloud", "/media/", "/mnt/", "\\usb"]
PROFILES = {
    "general": {"approved_fragments": [], "disallowed_fragments": _DISALLOWED,
                "default_scan": ["~/Desktop", "~/Documents", "~/Downloads"]},
    "hr": {"approved_fragments": ["hr_share", "hr-share", "hrshare"], "disallowed_fragments": _DISALLOWED,
           "default_scan": ["~/Desktop", "~/Documents", "~/Downloads"]},
    "finance": {"approved_fragments": ["finance_share", "finance-share"], "disallowed_fragments": _DISALLOWED,
                "default_scan": ["~/Desktop", "~/Documents", "~/Downloads"]},
}


def classify_location(path, profile):
    p = path.lower().replace("\\", "/")
    for frag in profile.get("approved_fragments", []):
        if frag.lower().replace("\\", "/") in p:
            return "expected_location"
    for frag in profile.get("disallowed_fragments", []):
        if frag.lower().replace("\\", "/") in p:
            return "violation"
    return "review"


# --------------------------------------------------------------------------
# File readers
# --------------------------------------------------------------------------
TEXT_EXT = {".txt", ".log", ".json", ".xml", ".md", ".html", ".htm", ".sql", ".yaml",
            ".yml", ".ini", ".conf", ".cfg", ".eml"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp", ".gif"}
CSV_EXT = {".csv": ",", ".tsv": "\t"}
XLSX_EXT = {".xlsx", ".xlsm"}
ZIPXML_EXT = {".docx": r"^word/(document|header\d*|footer\d*)\.xml$",
              ".pptx": r"^ppt/slides/slide\d+\.xml$"}
LEGACY_EXT = {".xls", ".doc", ".ppt"}
MAX_UNCOMPRESSED = 200 * 1024 * 1024


class Skip(Exception):
    def __init__(self, reason):
        self.reason = reason


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _open_text(path):
    fb = open(path, "rb")
    head = fb.read(4)
    fb.seek(0)
    enc = "utf-16" if head[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
    return io.TextIOWrapper(fb, encoding=enc, errors="replace", newline="")


def scan_plain(path, agg):
    CH, OV = 1 << 20, 128
    tail = ""
    with _open_text(path) as rd:
        while True:
            chunk = rd.read(CH)
            if not chunk:
                break
            text = tail + chunk
            for f in scan_text(text):
                if f[4] > len(tail):
                    agg.add(f)
            tail = text[-OV:]


def _column_profile(values):
    """Infer generic structure from a column without knowing its schema."""
    vals = [v.strip() for v in values if v and v.strip()]
    if not vals:
        return {"nonempty": 0}
    sample = vals[:1000]
    numeric = [re.sub(r"\D", "", v) for v in sample if re.fullmatch(r"[\s+()-]*\d[\d\s+()-]*", v)]
    lengths = [len(v) for v in sample]
    unique_ratio = len(set(sample)) / max(1, len(sample))
    numeric_ratio = len(numeric) / max(1, len(sample))
    consistent_len = len(set(lengths)) <= 2
    sequential = False
    if len(numeric) >= 4 and len(numeric) == len(sample):
        try:
            nums = [int(x) for x in numeric]
            diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
            sequential = all(0 < d <= 1000 for d in diffs)
        except ValueError:
            pass
    return {
        "nonempty": len(vals),
        "numeric_ratio": round(numeric_ratio, 3),
        "unique_ratio": round(unique_ratio, 3),
        "consistent_length": consistent_len,
        "sequential": sequential,
        "avg_length": round(sum(lengths) / len(lengths), 1),
    }


def _column_is_obviously_generated_identifier(profile):
    """Conservative suppression signal for machine-generated numeric IDs.

    This is deliberately generic: it does not know Wazuh, SIEM, CRM, etc.
    It only fires when a column strongly behaves like a sequential machine ID.
    """
    return (
        profile.get("nonempty", 0) >= 4
        and profile.get("numeric_ratio", 0) >= 0.95
        and profile.get("unique_ratio", 0) >= 0.90
        and profile.get("consistent_length")
        and profile.get("sequential")
    )


def _has_strong_financial_context(text):
    return re.search(
        r"(?i)credit\s*card|debit\s*card|card\s*(?:number|no\.?|#)|card_number|\bcvv\b|\bpan\b|expiry|expiration|visa|mastercard|master\s*card|rupay|amex",
        text or ""
    ) is not None


def scan_csv(path, delim, agg):
    """Scan arbitrary CSV/TSV data using discovered column structure.

    No vendor/SIEM schema is hardcoded. Column headers are context only;
    sampled values are also profiled so machine-generated IDs can be
    distinguished from genuine PII candidates.
    """
    try:
        csv.field_size_limit(sys.maxsize)
    except OverflowError:
        csv.field_size_limit(2 ** 31 - 1)

    # First pass: learn generic column behaviour from a bounded sample.
    samples = {}
    with _open_text(path) as rd:
        for row_no, row in enumerate(csv.reader(rd, delimiter=delim)):
            for i, cell in enumerate(row):
                if cell.strip() and len(samples.get(i, [])) < 1000:
                    samples.setdefault(i, []).append(cell)
            if row_no >= 1000:
                break
    profiles = {i: _column_profile(v) for i, v in samples.items()}

    header = None
    with _open_text(path) as rd:
        for row in csv.reader(rd, delimiter=delim):
            if header is None:
                header = row
                continue
            for i, cell in enumerate(row):
                if not cell.strip():
                    continue
                h = header[i].strip() if i < len(header) else ""
                context = "%s: %s" % (h, cell) if h else cell
                for f in scan_text(context):
                    # Only suppress a card candidate when the entire column
                    # strongly behaves like a sequential machine-generated ID
                    # and there is no strong financial context. This avoids
                    # hardcoding any particular application's field names.
                    if f[0] == "card" and _column_is_obviously_generated_identifier(profiles.get(i, {})):
                        if not _has_strong_financial_context(context):
                            continue
                    agg.add(f)


def _col_index(ref):
    letters = re.match(r"[A-Z]+", ref or "A").group()
    n = 0
    for ch in letters:
        n = n * 26 + ord(ch) - 64
    return n


def _norm_num(v):
    v = v.strip()
    if re.fullmatch(r"\d+\.0+", v):
        return v.split(".")[0]
    if re.fullmatch(r"[+-]?\d+(\.\d+)?[eE][+-]?\d+", v):
        try:
            return format(Decimal(v), "f").rstrip("0").rstrip(".") if "." in format(Decimal(v), "f") else format(Decimal(v), "f")
        except InvalidOperation:
            return v
    return v


def _check_zip(z):
    if sum(i.file_size for i in z.infolist()) > MAX_UNCOMPRESSED:
        raise Skip("too_large_uncompressed")


def scan_xlsx(path, agg):
    with zipfile.ZipFile(path) as z:
        _check_zip(z)
        names = z.namelist()
        shared = []
        if "xl/sharedStrings.xml" in names:
            for _, el in ET.iterparse(z.open("xl/sharedStrings.xml"), events=("end",)):
                if _local(el.tag) == "si":
                    shared.append("".join(t.text or "" for t in el.iter() if _local(t.tag) == "t"))
                    el.clear()
        for sn in sorted(n for n in names if re.match(r"^xl/worksheets/[^/]+\.xml$", n)):
            header, first = {}, True
            for _, row in ET.iterparse(z.open(sn), events=("end",)):
                if _local(row.tag) != "row":
                    continue
                vals = {}
                for c in row:
                    if _local(c.tag) != "c":
                        continue
                    t, v = c.get("t"), None
                    for ch in c:
                        ln = _local(ch.tag)
                        if ln == "v" and ch.text is not None:
                            if t == "s":
                                try:
                                    v = shared[int(ch.text)]
                                except (ValueError, IndexError):
                                    v = None
                            else:
                                v = ch.text if t in ("str", "inlineStr", "b", "e") else _norm_num(ch.text)
                        elif ln == "is":
                            v = "".join(x.text or "" for x in ch.iter() if _local(x.tag) == "t")
                    if v:
                        vals[_col_index(c.get("r"))] = v
                if first:
                    header, first = dict(vals), False
                for ci, val in vals.items():
                    h = header.get(ci, "")
                    for f in scan_text("%s: %s" % (h, val) if h and h != val else val):
                        agg.add(f)
                row.clear()


def scan_zipxml(path, member_re, agg):
    rx = re.compile(member_re)
    with zipfile.ZipFile(path) as z:
        _check_zip(z)
        for n in z.namelist():
            if not rx.match(n):
                continue
            for _, el in ET.iterparse(z.open(n), events=("end",)):
                if _local(el.tag) == "p":
                    txt = "".join(t.text or "" for t in el.iter() if _local(t.tag) == "t")
                    if txt.strip():
                        for f in scan_text(txt):
                            agg.add(f)


def _ocr_available():
    """Return True when both Pillow/pytesseract and the Tesseract binary exist."""
    try:
        import pytesseract  # noqa: F401
        from PIL import Image  # noqa: F401
    except ImportError:
        return False
    try:
        import pytesseract
        return bool(pytesseract.get_tesseract_version())
    except Exception:
        return False


def _ocr_image(image):
    try:
        import pytesseract
        return pytesseract.image_to_string(image) or ""
    except Exception as e:
        raise Skip("ocr_failed:" + type(e).__name__)


def scan_image(path, agg):
    try:
        from PIL import Image
    except ImportError:
        raise Skip("ocr_dependency_missing")
    if not _ocr_available():
        raise Skip("ocr_engine_missing")
    try:
        with Image.open(path) as img:
            text = _ocr_image(img)
    except Skip:
        raise
    except Exception as e:
        raise Skip("image_unreadable:" + type(e).__name__)
    if not text.strip():
        raise Skip("ocr_no_text")
    for f in scan_text(text):
        agg.add(f)


def scan_pdf(path, agg):
    texts = None
    try:
        try:
            import pymupdf as fitz  # PyMuPDF (optional): C-backed, far faster than pypdf
        except ImportError:
            import fitz
        try:
            doc = fitz.open(path)
        except Exception:
            raise Skip("pdf_unreadable_or_corrupt")
        try:
            if doc.is_encrypted and not doc.authenticate(""):
                raise Skip("encrypted")
            texts = [page.get_text() or "" for page in doc]
        finally:
            doc.close()
    except ImportError:
        pass
    if texts is None:
        texts = _pdf_text_fallback(path)
    if texts is not None and sum(len(t.strip()) for t in texts) >= 20:
        for t in texts:
            for f in scan_text(t):
                agg.add(f)
        return
    _pdf_ocr(path, agg, texts)


def _pdf_text_fallback(path):
    texts = None
    try:
        import pypdf  # optional
        try:
            r = pypdf.PdfReader(path)
            if r.is_encrypted:
                raise Skip("encrypted")
            texts = [(p.extract_text() or "") for p in r.pages]
        except Skip:
            raise
        except Exception:
            raise Skip("pdf_unreadable_or_corrupt")
    except ImportError:
        exe = shutil.which("pdftotext")
        if exe:
            res = subprocess.run([exe, "-layout", path, "-"], capture_output=True, timeout=120)
            if res.returncode != 0:
                raise Skip("pdf_unreadable_or_encrypted")
            texts = [res.stdout.decode("utf-8", "replace")]
    return texts


def _pdf_ocr(path, agg, texts):
    # Image-only/scanned PDF: fall back to OCR if available. PyMuPDF is used
    # only for rendering; OCR remains optional and isolated from detection.
    if not _ocr_available():
        if texts is None:
            raise Skip("pdf_no_extractor")
        raise Skip("pdf_no_text_layer_ocr_needed")

    try:
        import fitz  # PyMuPDF
        import pytesseract
        doc = fitz.open(path)
        try:
            if doc.is_encrypted and not doc.authenticate(""):
                raise Skip("encrypted")
            found_text = False
            for page in doc:
                pix = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
                from PIL import Image
                img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                text = pytesseract.image_to_string(img) or ""
                if text.strip():
                    found_text = True
                    for f in scan_text(text):
                        agg.add(f)
            if not found_text:
                raise Skip("ocr_no_text")
        finally:
            doc.close()
    except Skip:
        raise
    except ImportError:
        raise Skip("ocr_dependency_missing")
    except Exception as e:
        raise Skip("ocr_failed:" + type(e).__name__)


def scan_file(path, ext, agg):
    if ext in TEXT_EXT:
        scan_plain(path, agg)
    elif ext in CSV_EXT:
        scan_csv(path, CSV_EXT[ext], agg)
    elif ext in XLSX_EXT or ext in ZIPXML_EXT:
        with open(path, "rb") as fb:
            head = fb.read(4)
        if head[:4] == b"\xd0\xcf\x11\xe0":
            raise Skip("encrypted_office")
        if not zipfile.is_zipfile(path):
            raise Skip("corrupt_or_unreadable")
        if ext in XLSX_EXT:
            scan_xlsx(path, agg)
        else:
            scan_zipxml(path, ZIPXML_EXT[ext], agg)
    elif ext == ".pdf":
        scan_pdf(path, agg)
    elif ext in IMAGE_EXT:
        scan_image(path, agg)
    elif ext in LEGACY_EXT:
        raise Skip("legacy_office_not_supported")
    else:
        raise Skip("unsupported_type")


SUPPORTED = TEXT_EXT | set(CSV_EXT) | XLSX_EXT | set(ZIPXML_EXT) | {".pdf"} | IMAGE_EXT
EXCLUDE_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "site-packages", "$recycle.bin"}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# --------------------------------------------------------------------------
# Scan driver
# --------------------------------------------------------------------------
def _lower_priority():
    try:
        if hasattr(os, "nice"):
            os.nice(10)
        elif os.name == "nt":
            import ctypes
            ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), 0x4000)
    except Exception:
        pass


def run_scan(paths, role="general", profile=None, max_mb=50, throttle_ms=0, samples=False,
             status_file=None, cache_file=None, progress=False, stop_event=None):
    profile = profile or PROFILES.get(role, PROFILES["general"])
    started = time.time()
    cache = {}
    if cache_file and os.path.exists(cache_file):
        try:
            cache = json.load(open(cache_file))
        except Exception:
            cache = {}
    new_cache = {}
    stats = {"files_seen": 0, "files_scanned": 0, "files_with_pii": 0, "cache_hits": 0}
    skipped_reasons, skipped_notable, findings = {}, [], []
    missing_paths = []
    unsupported_ext = {}
    type_totals = {}
    last_status = [0.0]

    def write_status(state, current=""):
        if not status_file:
            return
        now = time.time()
        if state == "running" and now - last_status[0] < 0.25:
            return
        last_status[0] = now
        payload = {"state": state, "current_file": str(current), "elapsed_s": round(now - started, 1),
                   **stats, "findings_by_type": type_totals}
        if callable(status_file):
            try:
                status_file(payload)
            except Exception:
                pass
            return
        tmp = status_file + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8", errors="replace") as f:
                json.dump(payload, f)
            os.replace(tmp, status_file)
        except Exception:
            pass

    for root_path in paths:
        if stop_event and stop_event.is_set():
            break
        root_path = os.path.expanduser(root_path)
        if not os.path.exists(root_path):
            home = os.path.expanduser("~")
            one_drive = os.path.join(home, "OneDrive")
            if os.path.exists(one_drive):
                rel = os.path.relpath(root_path, home)
                od_path = os.path.join(one_drive, rel)
                if os.path.exists(od_path):
                    root_path = od_path
        if not os.path.exists(root_path):
            missing_paths.append(root_path)
            sys.stderr.write("WARNING: path not found, skipped: %s\n" % root_path)
            continue
        for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
            if stop_event and stop_event.is_set():
                break
            dirnames[:] = [d for d in dirnames if d.lower() not in EXCLUDE_DIRS]
            for fn in filenames:
                if stop_event and stop_event.is_set():
                    break
                path = os.path.join(dirpath, fn)
                stats["files_seen"] += 1
                ext = os.path.splitext(fn)[1].lower()
                try:
                    write_status("running", path)
                    if fn.startswith("~$"):
                        raise Skip("office_lock_file")
                    st = os.stat(path)
                    if os.path.islink(path):
                        raise Skip("symlink")
                    if ext not in SUPPORTED and ext not in LEGACY_EXT:
                        raise Skip("unsupported_type")
                    if st.st_size > max_mb * 1024 * 1024:
                        raise Skip("too_large")
                    key = path
                    c = cache.get(key)
                    if c and c["size"] == st.st_size and c["mtime"] == st.st_mtime:
                        types, sample = c["types"], c.get("samples", {})
                        stats["cache_hits"] += 1
                    else:
                        agg = Agg(samples)
                        scan_file(path, ext, agg)
                        types, sample = agg.result(), agg.samples
                    new_cache[key] = {"size": st.st_size, "mtime": st.st_mtime, "types": types, "samples": sample}
                    stats["files_scanned"] += 1
                    if types:
                        sc = score_types(types)
                        reportable = any(v["high"] or v["medium"] for v in types.values())
                        if reportable:
                            stats["files_with_pii"] += 1
                        for t, v in types.items():
                            tt = type_totals.setdefault(t, {"high": 0, "medium": 0, "low": 0})
                            for k in ("high", "medium", "low"):
                                tt[k] += v[k]
                        findings.append({
                            "path": path, "size": st.st_size,
                            "modified": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
                            "sha256": sha256_file(path), "types": types, "score": sc, "tier": tier(sc),
                            "location_class": classify_location(path, profile) if reportable else "n/a",
                            **({"samples": sample} if samples else {}),
                        })
                except Skip as s:
                    skipped_reasons[s.reason] = skipped_reasons.get(s.reason, 0) + 1
                    if s.reason == "unsupported_type":
                        k = ext or "(no extension)"
                        unsupported_ext[k] = unsupported_ext.get(k, 0) + 1
                    if s.reason not in ("unsupported_type", "symlink", "office_lock_file") and len(skipped_notable) < 200:
                        skipped_notable.append({"path": path, "reason": s.reason})
                except Exception as e:  # never let one bad file stop the scan
                    r = "error:" + type(e).__name__
                    skipped_reasons[r] = skipped_reasons.get(r, 0) + 1
                    if len(skipped_notable) < 200:
                        skipped_notable.append({"path": path, "reason": r})
                if progress:
                    sys.stderr.write("\r[%d files] %s" % (stats["files_seen"], path[-90:].ljust(90)))
                if throttle_ms:
                    time.sleep(throttle_ms / 1000.0)
    if cache_file:
        json.dump(new_cache, open(cache_file, "w"))
    write_status("done")
    findings.sort(key=lambda x: -x["score"])
    tiers, loc = {}, {}
    for f in findings:
        if f["location_class"] != "n/a":
            tiers[f["tier"]] = tiers.get(f["tier"], 0) + 1
            loc[f["location_class"]] = loc.get(f["location_class"], 0) + 1
    return {
        "meta": {"scanner_version": VERSION, "host": socket.gethostname(),
                 "os": platform.platform(), "role": role, "paths": paths,
                 "started": datetime.datetime.fromtimestamp(started).isoformat(timespec="seconds"),
                 "duration_s": round(time.time() - started, 1),
                 "ocr_available": _ocr_available(),
                 "note": "Endpoint PII posture only; not a DPDP compliance verdict. "
                         "Scores/tiers are tunable heuristics. No file content is stored. "
                         "OCR is used as a fallback for image-only PDFs and supported image files when available."},
        "summary": {**stats, "by_tier": tiers, "by_location_class": loc,
                    "findings_by_type": type_totals, "skipped_by_reason": skipped_reasons,
                    "unsupported_by_extension": dict(sorted(unsupported_ext.items(), key=lambda kv: -kv[1])[:20])},
        "findings": findings, "skipped_notable": skipped_notable,
        "missing_paths": missing_paths,
    }


def main():
    ap = argparse.ArgumentParser(description="Endpoint PII discovery scanner (DPDP PoC)")
    ap.add_argument("--paths", nargs="*", help="folders to scan (default: role profile default_scan)")
    ap.add_argument("--role", default="general", help="role profile name (general, hr, finance)")
    ap.add_argument("--profile", help="JSON file overriding/adding role profiles")
    ap.add_argument("--output", default="pii_report.json")
    ap.add_argument("--samples", action="store_true", help="include MASKED samples (default off)")
    ap.add_argument("--max-mb", type=int, default=50)
    ap.add_argument("--throttle-ms", type=int, default=0, help="sleep between files")
    ap.add_argument("--cache", help="cache file; unchanged files (size+mtime) are not rescanned")
    ap.add_argument("--status-file", help="live status JSON (for a UI to poll)")
    ap.add_argument("--progress", action="store_true")
    a = ap.parse_args()
    if a.profile:
        PROFILES.update(json.load(open(a.profile)))
    if a.role not in PROFILES:
        sys.exit("unknown role %r; known: %s" % (a.role, ", ".join(PROFILES)))
    _lower_priority()
    prof = PROFILES[a.role]
    paths = a.paths or prof["default_scan"]
    rep = run_scan(paths, a.role, prof, a.max_mb, a.throttle_ms, a.samples, a.status_file, a.cache, a.progress)
    with open(a.output, "w") as f:
        json.dump(rep, f, indent=2)
    s = rep["summary"]
    if a.progress:
        sys.stderr.write("\n")
    print("Scanned %d files (%d seen) in %ss | files with PII: %d | by tier: %s | locations: %s"
          % (s["files_scanned"], s["files_seen"], rep["meta"]["duration_s"], s["files_with_pii"],
             s["by_tier"], s["by_location_class"]))
    print("Skipped:", s["skipped_by_reason"])
    print("Unsupported types (top):", s["unsupported_by_extension"])
    if s["skipped_by_reason"].get("pdf_no_extractor"):
        print("NOTE: PDFs were NOT scanned because no PDF text extractor was available. Install: pip install pypdf")
    if any(k in s["skipped_by_reason"] for k in ("pdf_no_text_layer_ocr_needed", "ocr_dependency_missing", "ocr_engine_missing")):
        print("NOTE: OCR was needed/available only partially. For OCR support install: pip install pypdf pymupdf pillow pytesseract and install the Tesseract OCR engine.")
    if rep["missing_paths"]:
        print("WARNING: %d path(s) did not exist and were NOT scanned: %s"
              % (len(rep["missing_paths"]), rep["missing_paths"]))
    print("Report:", a.output)


if __name__ == "__main__":
    main()