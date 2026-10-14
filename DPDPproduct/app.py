#!/usr/bin/env python3
"""
app.py — RiskNox PII Scanner UI
Self-contained launcher. Place next to pii_scan.py and run:
  python app.py
Browser opens automatically at http://localhost:5000
No external dependencies required (Flask is optional).
"""
import atexit
import io
import json
import os
import shutil
import socketserver
import sys
import tempfile
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# ─── Bootstrap ────────────────────────────────────────────────────────────────
BASE = Path(__file__).parent.resolve()
sys.path.insert(0, str(BASE))
try:
    import pii_scan
except ImportError as _e:
    print(f"ERROR: Cannot import pii_scan — {_e}")
    print(f"       Make sure pii_scan.py is in the same folder: {BASE}")
    sys.exit(1)

# ─── Global state ─────────────────────────────────────────────────────────────
_lock = threading.Lock()
_scan_state = "idle"          # idle | scanning | done | error
_scan_error = None
_scan_thread = None
_stop_evt = threading.Event()
_live_status = {"state": "idle", "current_file": ""}
_results = None               # cumulated results dict
_temp_dir = tempfile.mkdtemp(prefix="risknox_pii_")


@atexit.register
def _cleanup():
    shutil.rmtree(_temp_dir, ignore_errors=True)


# ─── Data helpers ──────────────────────────────────────────────────────────────
def _make_empty_results():
    return {
        "meta": {},
        "summary": {
            "files_seen": 0, "files_scanned": 0, "files_with_pii": 0,
            "cache_hits": 0, "by_tier": {}, "by_location_class": {},
            "findings_by_type": {}, "skipped_by_reason": {}, "unsupported_by_extension": {}
        },
        "findings": [], "skipped_notable": [], "missing_paths": []
    }


def _merge_into(base, new_r):
    """Accumulate new_r into base (mutates base in place)."""
    base["findings"].extend(new_r.get("findings", []))
    base["findings"].sort(key=lambda x: -x.get("score", 0))
    ns = new_r.get("summary", {})
    bs = base["summary"]
    for k in ("files_seen", "files_scanned", "files_with_pii", "cache_hits"):
        bs[k] = bs.get(k, 0) + ns.get(k, 0)
    for t, v in ns.get("findings_by_type", {}).items():
        if t not in bs["findings_by_type"]:
            bs["findings_by_type"][t] = {"high": 0, "medium": 0, "low": 0}
        for c in ("high", "medium", "low"):
            bs["findings_by_type"][t][c] += v.get(c, 0)
    for tk, cnt in ns.get("by_tier", {}).items():
        bs["by_tier"][tk] = bs["by_tier"].get(tk, 0) + cnt
    for lk, cnt in ns.get("by_location_class", {}).items():
        bs["by_location_class"][lk] = bs["by_location_class"].get(lk, 0) + cnt
    for rk, cnt in ns.get("skipped_by_reason", {}).items():
        bs["skipped_by_reason"][rk] = bs["skipped_by_reason"].get(rk, 0) + cnt
    base["skipped_notable"].extend(new_r.get("skipped_notable", []))
    base["missing_paths"].extend(new_r.get("missing_paths", []))
    if new_r.get("meta"):
        base["meta"] = new_r["meta"]


# ─── Multipart parser (stdlib, no cgi dependency) ─────────────────────────────
def _parse_multipart(content_type, body_bytes):
    """Return dict: {field_name: (filename_or_None, bytes_data)}"""
    boundary = None
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("boundary="):
            boundary = part[9:].strip('"').strip("'")
            break
    if not boundary:
        return {}
    sep = ("--" + boundary).encode()
    end = ("--" + boundary + "--").encode()
    result = {}
    chunks = body_bytes.split(sep)
    for chunk in chunks:
        chunk = chunk.strip(b"\r\n")
        if not chunk or chunk == b"--":
            continue
        if end in chunk:
            chunk = chunk[: chunk.index(end)]
        if b"\r\n\r\n" not in chunk:
            continue
        header_part, data = chunk.split(b"\r\n\r\n", 1)
        if data.endswith(b"\r\n"):
            data = data[:-2]
        headers = {}
        for line in header_part.decode("utf-8", "replace").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        cd = headers.get("content-disposition", "")
        name, filename = None, None
        for seg in cd.split(";"):
            seg = seg.strip()
            if seg.lower().startswith("name="):
                name = seg[5:].strip('"')
            elif seg.lower().startswith("filename="):
                filename = seg[9:].strip('"')
        if name:
            result[name] = (filename, data)
    return result


def _on_scan_status(payload):
    global _live_status
    with _lock:
        _live_status = dict(payload)


def _run_system_scan(paths, role, max_mb):
    global _scan_state, _scan_error, _results, _live_status
    try:
        with _lock:
            _scan_state = "scanning"
            _scan_error = None
            _live_status = {
                "state": "running", "current_file": "Initializing scan…",
                "files_seen": 0, "files_scanned": 0,
                "files_with_pii": 0, "cache_hits": 0,
                "findings_by_type": {}
            }
        prof = pii_scan.PROFILES.get(role, pii_scan.PROFILES["general"])
        result = pii_scan.run_scan(
            paths=paths, role=role, profile=prof,
            max_mb=max_mb, throttle_ms=0, samples=False,
            status_file=_on_scan_status,
            stop_event=_stop_evt,
        )
        with _lock:
            if _results is None:
                _results = _make_empty_results()
            _merge_into(_results, result)
            _scan_state = "done"
            _live_status = {"state": "done", "current_file": ""}
    except Exception as exc:
        import traceback
        traceback.print_exc()
        with _lock:
            _scan_state = "error"
            _scan_error = str(exc)
            _live_status = {"state": "done", "current_file": ""}


def _scan_upload(filepath, original_name):
    """Scan a single uploaded file, merge into cumulated results."""
    import datetime
    global _results
    ext = os.path.splitext(original_name)[1].lower()
    agg = pii_scan.Agg(want_samples=False)
    skip_reason = None
    try:
        pii_scan.scan_file(filepath, ext, agg)
    except pii_scan.Skip as s:
        skip_reason = s.reason
    except Exception as e:
        skip_reason = f"error:{type(e).__name__}"
    if skip_reason:
        return None, skip_reason
    types = agg.result()
    sc = pii_scan.score_types(types) if types else 0
    t = pii_scan.tier(sc) if types else "none"
    st = os.stat(filepath)
    sha = pii_scan.sha256_file(filepath)
    finding = {
        "path": original_name + "  [uploaded]",
        "size": st.st_size,
        "modified": datetime.datetime.now().isoformat(timespec="seconds"),
        "sha256": sha, "types": types, "score": sc, "tier": t,
        "location_class": "review" if types else "n/a",
    }
    mini = {
        "meta": {},
        "summary": {
            "files_seen": 1, "files_scanned": 1,
            "files_with_pii": 1 if types else 0, "cache_hits": 0,
            "by_tier": {t: 1} if types else {},
            "by_location_class": {"review": 1} if types else {},
            "findings_by_type": types,
            "skipped_by_reason": {}, "unsupported_by_extension": {}
        },
        "findings": [finding] if types else [],
        "skipped_notable": [], "missing_paths": []
    }
    with _lock:
        if _results is None:
            _results = _make_empty_results()
        _merge_into(_results, mini)
    return finding, None


# ─── API handlers ─────────────────────────────────────────────────────────────
def api_get_status():
    with _lock:
        state, err = _scan_state, _scan_error
        status = dict(_live_status)
    return {"scan_state": state, "error": err, "status": status}


def api_get_results():
    with _lock:
        r = _results
    return r if r is not None else {"error": "No results yet"}


def api_scan_start(body):
    global _scan_state, _scan_thread
    with _lock:
        # Block only if a thread is genuinely still running.
        thread_alive = _scan_thread is not None and _scan_thread.is_alive()
        if thread_alive:
            return {"ok": False, "error": "A scan is already in progress. Wait for it to finish."}
        # Safe to start — reset any stale state
        _scan_state = "idle"
        _scan_error = None

    role = body.get("role", "general")
    if role not in pii_scan.PROFILES:
        role = "general"
    paths = body.get("paths") or pii_scan.PROFILES[role].get(
        "default_scan", ["~/Desktop", "~/Documents", "~/Downloads"])
    max_mb = int(body.get("max_mb", 50))

    _stop_evt.clear()
    t = threading.Thread(target=_run_system_scan, args=(paths, role, max_mb), daemon=True)
    with _lock:
        _scan_state = "scanning"
        _scan_thread = t
    t.start()
    return {"ok": True}


def api_scan_stop():
    global _scan_state
    _stop_evt.set()
    with _lock:
        _scan_state = "done"
        _live_status["state"] = "done"
    return {"ok": True}


def api_scan_file(raw_bytes, filename):
    safe_name = filename.replace("/", "_").replace("\\", "_")
    dest = os.path.join(_temp_dir, "upload_" + safe_name)
    with open(dest, "wb") as f:
        f.write(raw_bytes)
    finding, err = _scan_upload(dest, filename)
    if err:
        return {"skip_reason": err}
    return {"ok": True, "finding": finding}


# ─── HTTP Server ───────────────────────────────────────────────────────────────
def _j(data):
    return json.dumps(data, default=str).encode("utf-8")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress request noise

    def _send_json(self, data, status=200):
        body = _j(data)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/":
            self._send_html(HTML)
        elif p == "/api/status":
            self._send_json(api_get_status())
        elif p == "/api/results":
            self._send_json(api_get_results())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        p = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", 0))

        if p == "/api/scan/start":
            body = json.loads(self.rfile.read(length))
            self._send_json(api_scan_start(body))

        elif p == "/api/scan/file":
            ctype = self.headers.get("Content-Type", "")
            raw = self.rfile.read(length)
            parts = _parse_multipart(ctype, raw)
            if "file" in parts:
                filename, data = parts["file"]
                self._send_json(api_scan_file(data, filename or "upload.bin"))
            else:
                self._send_json({"error": "No file field found in upload"}, 400)

        elif p == "/api/scan/stop":
            self._send_json(api_scan_stop())

        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


class _ThreadedServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ─── Embedded UI ──────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>RiskNox PII Scanner</title>
<meta name="description" content="Endpoint PII discovery scanner — DPDP compliance posture tool by RiskNox">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#090909;--bg-card:#111111;--bg-el:#181818;--bg-in:#0d0d0d;
  --border:#222;--border-h:#333;
  --orange:#FF6B1A;--orange-dim:#cc5514;
  --og:rgba(255,107,26,.10);--og2:rgba(255,107,26,.22);
  --text:#EEEEEE;--muted:#666;--dim:#2c2c2c;
  --crit:#FF3B3B;--high:#FF8C00;--med:#F5C842;--low:#4ECA6A;
  --r:10px;--rl:16px;--sh:0 4px 32px rgba(0,0,0,.6);--tr:.2s cubic-bezier(.4,0,.2,1)
}
html{font-size:14px;scroll-behavior:smooth}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;
  background-image:linear-gradient(rgba(255,107,26,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,107,26,.025) 1px,transparent 1px);
  background-size:48px 48px;pointer-events:none;z-index:0}

/* ── NAV ── */
.nav{position:fixed;top:0;left:0;right:0;z-index:100;height:58px;
  background:rgba(9,9,9,.9);backdrop-filter:blur(20px);
  border-bottom:1px solid var(--border);
  display:flex;align-items:center;padding:0 24px;gap:14px}
.logo{width:38px;height:38px;border-radius:9px;flex-shrink:0;
  background:linear-gradient(135deg,#FF6B1A,#ff3d00);
  display:flex;align-items:center;justify-content:center;
  font-size:19px;font-weight:800;color:#fff;letter-spacing:-1px;
  box-shadow:0 0 20px rgba(255,107,26,.4)}
.brand{font-size:15px;font-weight:700;color:var(--text)}
.brand-sub{font-size:11px;color:var(--muted);margin-left:3px}
.spacer{flex:1}
.badge{display:flex;align-items:center;gap:8px;padding:6px 14px;border-radius:20px;
  background:var(--bg-card);border:1px solid var(--border);font-size:11px;font-weight:600;letter-spacing:.05em}
.dot{width:8px;height:8px;border-radius:50%;background:var(--muted);transition:var(--tr)}
.dot.scanning{background:var(--orange);animation:pdot 1.2s ease infinite}
.dot.done{background:var(--low)}
.dot.error{background:var(--crit)}
@keyframes pdot{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.65)}}
.btn-stop{display:none;padding:6px 16px;border-radius:6px;background:rgba(255,59,59,.1);
  border:1px solid var(--crit);color:var(--crit);font-size:11px;font-weight:600;cursor:pointer;
  transition:var(--tr);font-family:inherit}
.btn-stop:hover{background:rgba(255,59,59,.22)}
.btn-stop.on{display:block}
.nav-ocr{font-size:10px;color:var(--muted);padding:5px 10px;border-radius:6px;
  background:var(--bg-card);border:1px solid var(--border)}

/* ── LAYOUT ── */
.main{display:grid;grid-template-columns:360px 1fr;gap:18px;
  padding:76px 22px 24px;min-height:100vh;position:relative;z-index:1}
@media(max-width:860px){.main{grid-template-columns:1fr}}

/* ── PANEL ── */
.pnl{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--rl);overflow:hidden}
.ph{padding:14px 18px 12px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:10px}
.pico{width:28px;height:28px;border-radius:6px;background:var(--og);
  display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0}
.ptitle{font-size:11px;font-weight:600;letter-spacing:.09em;text-transform:uppercase;color:var(--muted)}
.pb{padding:18px}

/* ── FORM ── */
label{font-size:11px;color:var(--muted);display:block;margin-bottom:5px;font-weight:500}
select,input[type=number],input[type=text]{
  width:100%;background:var(--bg-in);border:1px solid var(--border);border-radius:8px;
  color:var(--text);padding:9px 12px;font-size:12px;font-family:inherit;
  outline:none;transition:var(--tr);-webkit-appearance:none}
select{cursor:pointer;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='11' height='11' viewBox='0 0 12 12'%3E%3Cpath fill='%23666' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
  background-repeat:no-repeat;background-position:right 12px center;padding-right:32px}
select:focus,input:focus{border-color:var(--orange);box-shadow:0 0 0 3px var(--og)}
.fg{margin-bottom:16px}

/* ── PATHS ── */
.paths-list{display:flex;flex-direction:column;gap:5px;margin-bottom:8px}
.pi{display:flex;align-items:center;gap:8px;background:var(--bg-in);border:1px solid var(--border);
  border-radius:7px;padding:7px 11px;transition:var(--tr)}
.pi:hover{border-color:var(--border-h)}
.pi span{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--muted)}
.pi-rm{width:18px;height:18px;border-radius:4px;border:none;background:transparent;
  cursor:pointer;color:var(--dim);font-size:15px;display:flex;align-items:center;
  justify-content:center;transition:var(--tr);flex-shrink:0;line-height:1}
.pi-rm:hover{background:rgba(255,59,59,.15);color:var(--crit)}
.btn-add{width:100%;padding:8px;border-radius:7px;border:1px dashed var(--border);
  background:transparent;color:var(--muted);cursor:pointer;font-size:11px;
  transition:var(--tr);font-family:inherit}
.btn-add:hover{border-color:var(--orange);color:var(--orange);background:var(--og)}

/* ── PRIMARY BUTTON ── */
.btn-pri{width:100%;padding:12px;border-radius:9px;border:none;
  background:linear-gradient(135deg,var(--orange),#ff3d00);
  color:#fff;font-size:13px;font-weight:700;cursor:pointer;
  transition:var(--tr);position:relative;overflow:hidden;font-family:inherit;letter-spacing:.03em}
.btn-pri::before{content:'';position:absolute;inset:0;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.12),transparent);
  transform:translateX(-100%);transition:transform .55s ease}
.btn-pri:hover::before{transform:translateX(100%)}
.btn-pri:hover{transform:translateY(-1px);box-shadow:0 8px 28px rgba(255,107,26,.35)}
.btn-pri:active{transform:translateY(0)}
.btn-pri:disabled{opacity:.45;cursor:not-allowed;transform:none}

/* ── DIVIDER ── */
.div{display:flex;align-items:center;gap:10px;margin:18px 0;
  color:var(--dim);font-size:10px;font-weight:600;letter-spacing:.12em}
.div::before,.div::after{content:'';flex:1;height:1px;background:var(--border)}

/* ── UPLOAD ZONE ── */
.upzone{border:2px dashed var(--border);border-radius:12px;padding:26px 18px;
  text-align:center;cursor:pointer;transition:var(--tr);position:relative;
  overflow:hidden;background:var(--bg-in)}
.upzone:hover,.upzone.over{border-color:var(--orange);background:var(--og);transform:scale(1.01)}
.upzone.over::after{content:'';position:absolute;inset:0;
  background:var(--og);animation:zpulse .5s ease infinite alternate}
@keyframes zpulse{from{opacity:.4}to{opacity:1}}
.up-icon{font-size:26px;margin-bottom:8px}
.up-title{font-size:12px;font-weight:600;margin-bottom:4px}
.up-sub{font-size:10px;color:var(--muted);line-height:1.7}
.up-sub span{color:var(--orange)}
.up-info{display:none;align-items:center;gap:9px;background:var(--bg-el);
  border-radius:7px;padding:9px 12px;margin-top:10px;text-align:left}
.up-info.on{display:flex}
.up-fname{font-size:11px;font-family:'JetBrains Mono',monospace;flex:1;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.up-fsize{font-size:10px;color:var(--muted);flex-shrink:0}
.btn-scanfile{display:none;width:100%;margin-top:9px;padding:10px;border-radius:8px;
  border:1px solid var(--orange);background:var(--og);color:var(--orange);
  font-size:12px;font-weight:600;cursor:pointer;transition:var(--tr);font-family:inherit}
.btn-scanfile:hover{background:var(--orange);color:#fff}
.btn-scanfile.on{display:block}
#finput{display:none}

/* ── PROGRESS ── */
.prog-wrap{display:none}
.prog-wrap.on{display:block}
.prog-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}
.prog-pct{font-size:32px;font-weight:800;color:var(--orange);font-variant-numeric:tabular-nums}
.prog-el{font-size:11px;color:var(--muted);font-family:'JetBrains Mono',monospace}
.pbar-wrap{height:6px;background:var(--bg-el);border-radius:99px;overflow:hidden;margin-bottom:18px}
.pbar{height:100%;border-radius:99px;background:linear-gradient(90deg,var(--orange),#ff3d00);
  transition:width .9s cubic-bezier(.4,0,.2,1);width:0%;position:relative}
.pbar::after{content:'';position:absolute;right:0;top:0;bottom:0;width:50px;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.28));animation:shim 1.5s infinite}
@keyframes shim{0%{opacity:1}50%{opacity:0}100%{opacity:1}}
.sg{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-bottom:14px}
.sc{background:var(--bg-el);border:1px solid var(--border);border-radius:8px;padding:11px}
.sl{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.09em;margin-bottom:3px}
.sv{font-size:22px;font-weight:700;font-variant-numeric:tabular-nums}
.sv.pii{color:var(--orange)}
.cf-lbl{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.09em;margin-bottom:5px}
.cf-path{font-size:10px;color:var(--muted);font-family:'JetBrains Mono',monospace;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
  background:var(--bg-in);border:1px solid var(--border);border-radius:6px;padding:7px 10px}
.live-types{display:flex;flex-wrap:wrap;gap:5px;margin-top:10px}

/* ── IDLE ── */
.idle{padding:50px 20px;text-align:center;color:var(--muted)}
.idle-icon{font-size:40px;margin-bottom:14px}

/* ── RESULTS ── */
.res-wrap{display:none}
.res-wrap.on{display:block}

/* Summary cards */
.scards{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;padding:18px 18px 0}
@media(max-width:1100px){.scards{grid-template-columns:repeat(2,1fr)}}
.scard{border-radius:12px;padding:15px 14px;border:1px solid var(--border);
  animation:fsup .4s ease both;opacity:0}
.scard:nth-child(1){animation-delay:.04s}.scard:nth-child(2){animation-delay:.09s}
.scard:nth-child(3){animation-delay:.14s}.scard:nth-child(4){animation-delay:.19s}
.scard:nth-child(5){animation-delay:.24s}.scard:nth-child(6){animation-delay:.29s}
.scard:nth-child(7){animation-delay:.34s}
@keyframes fsup{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
.scard.crit{background:rgba(255,59,59,.07);border-color:rgba(255,59,59,.22)}
.scard.hi{background:rgba(255,140,0,.07);border-color:rgba(255,140,0,.22)}
.scard.md{background:rgba(245,200,66,.07);border-color:rgba(245,200,66,.22)}
.scard.lo{background:rgba(78,202,106,.07);border-color:rgba(78,202,106,.22)}
.scard.inf{background:var(--bg-el)}
.sci{font-size:18px;margin-bottom:7px}
.scv{font-size:26px;font-weight:800;font-variant-numeric:tabular-nums}
.scv.crit{color:var(--crit)}.scv.hi{color:var(--high)}.scv.md{color:var(--med)}
.scv.lo{color:var(--low)}.scv.inf{color:var(--text)}
.sclbl{font-size:10px;color:var(--muted);margin-top:2px}
.info-row{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;padding:10px 18px 18px}

/* ── SECTION TITLE ── */
.stitle{font-size:10px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;
  color:var(--muted);padding:14px 18px 12px;border-bottom:1px solid var(--border)}

/* ── PII BREAKDOWN ── */
.pii-grid{display:grid;grid-template-columns:160px 1fr;gap:20px;padding:18px;align-items:start}
.donut-wrap{position:relative;width:140px;height:140px;flex-shrink:0}
.donut-svg{width:140px;height:140px;transform:rotate(-90deg)}
.donut-cx{position:absolute;inset:0;display:flex;flex-direction:column;
  align-items:center;justify-content:center}
.donut-n{font-size:22px;font-weight:800}
.donut-l{font-size:9px;color:var(--muted)}
.pii-list{display:flex;flex-direction:column;gap:7px}
.pii-row{display:flex;align-items:center;gap:8px}
.pdot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.pname{font-size:11px;flex:1;text-transform:capitalize}
.pbar-w{width:80px;height:4px;background:var(--bg-el);border-radius:99px;overflow:hidden}
.pbar-f{height:100%;border-radius:99px;transition:width .8s ease}
.pcount{font-size:10px;color:var(--muted);min-width:28px;text-align:right;font-variant-numeric:tabular-nums}

/* Conf table */
.ctbl{width:100%;border-collapse:collapse}
.ctbl th{text-align:left;font-size:9px;font-weight:600;letter-spacing:.09em;
  text-transform:uppercase;color:var(--muted);padding:8px 14px;border-bottom:1px solid var(--border)}
.ctbl th.r{text-align:right}
.ctbl td{padding:9px 14px;border-bottom:1px solid var(--border);font-size:11px}
.ctbl tr:last-child td{border-bottom:none}
.ctbl tr:hover td{background:var(--bg-el)}
.ch{color:var(--crit);font-weight:600}.cm{color:var(--med)}.cl{color:var(--muted)}
.cname{text-transform:capitalize;font-weight:500}
.ctot{text-align:right;font-variant-numeric:tabular-nums;font-weight:600}

/* Location bar */
.loc-body{padding:18px}
.loc-items{display:flex;gap:18px;margin-bottom:12px}
.loc-it{display:flex;align-items:center;gap:6px;font-size:11px}
.loc-dot{width:8px;height:8px;border-radius:2px;flex-shrink:0}
.loc-dot.v{background:var(--crit)}.loc-dot.rv{background:var(--med)}.loc-dot.ex{background:var(--low)}
.loc-stack{height:8px;border-radius:99px;overflow:hidden;display:flex}
.ls{transition:width .8s ease}
.ls.v{background:var(--crit)}.ls.rv{background:var(--med)}.ls.ex{background:var(--low)}

/* Findings toolbar */
.ftbar{display:flex;gap:8px;align-items:center;padding:14px 18px;flex-wrap:wrap;border-bottom:1px solid var(--border)}
.sw{position:relative;flex:1;min-width:160px}
.si{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:12px;pointer-events:none}
.fsearch{width:100%;background:var(--bg-in);border:1px solid var(--border);border-radius:7px;
  color:var(--text);padding:7px 11px 7px 32px;font-size:11px;font-family:inherit;
  outline:none;transition:var(--tr)}
.fsearch:focus{border-color:var(--orange);box-shadow:0 0 0 3px var(--og)}
.fbtn{padding:6px 11px;border-radius:5px;border:1px solid var(--border);
  background:var(--bg-in);color:var(--muted);font-size:10px;cursor:pointer;
  transition:var(--tr);font-family:inherit;font-weight:500}
.fbtn.act{border-color:var(--orange);background:var(--og);color:var(--orange)}
.expbtn{padding:6px 13px;border-radius:5px;border:1px solid var(--border);
  background:var(--bg-in);color:var(--muted);font-size:10px;cursor:pointer;
  transition:var(--tr);font-family:inherit;font-weight:500;display:flex;align-items:center;gap:5px}
.expbtn:hover{border-color:var(--orange);color:var(--orange)}

/* Findings table */
.ftw{overflow-x:auto}
.ft{width:100%;border-collapse:collapse}
.ft th{text-align:left;padding:9px 14px;font-size:9px;font-weight:600;
  letter-spacing:.09em;text-transform:uppercase;color:var(--muted);
  border-bottom:1px solid var(--border);white-space:nowrap;cursor:pointer;
  user-select:none;transition:var(--tr)}
.ft th:hover{color:var(--orange)}
.ft td{padding:11px 14px;border-bottom:1px solid var(--border);font-size:11px;vertical-align:middle}
.ft tr:last-child td{border-bottom:none}
.ft tr.dr:hover td{background:var(--bg-el);cursor:pointer}
.tbadge{display:inline-flex;align-items:center;padding:3px 8px;border-radius:20px;
  font-size:9px;font-weight:700;letter-spacing:.07em;text-transform:uppercase}
.tbadge.critical{background:rgba(255,59,59,.14);color:var(--crit);border:1px solid rgba(255,59,59,.28)}
.tbadge.high{background:rgba(255,140,0,.14);color:var(--high);border:1px solid rgba(255,140,0,.28)}
.tbadge.medium{background:rgba(245,200,66,.11);color:var(--med);border:1px solid rgba(245,200,66,.28)}
.tbadge.low{background:rgba(78,202,106,.11);color:var(--low);border:1px solid rgba(78,202,106,.28)}
.tbadge.none{background:var(--bg-el);color:var(--muted);border:1px solid var(--border)}
.fpath{font-family:'JetBrains Mono',monospace;font-size:10px;max-width:260px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lbadge{font-size:9px;padding:2px 7px;border-radius:4px;font-weight:600}
.lbadge.violation{color:var(--crit);background:rgba(255,59,59,.1)}
.lbadge.review{color:var(--med);background:rgba(245,200,66,.1)}
.lbadge.expected{color:var(--low);background:rgba(78,202,106,.1)}
.lbadge.na{color:var(--muted);background:var(--bg-el)}
.sval{font-weight:700;font-variant-numeric:tabular-nums;font-size:13px}

/* Expandable row */
.exrow td{padding:0!important;border-bottom:1px solid var(--border)}
.exc{max-height:0;overflow:hidden;transition:max-height .3s ease}
.exc.open{max-height:380px}
.exi{padding:14px 18px}
.ex-types{display:flex;flex-wrap:wrap;gap:7px}
.etchip{padding:6px 11px;border-radius:6px;font-size:10px;
  background:var(--bg-el);border:1px solid var(--border);
  display:flex;gap:7px;align-items:center}
.etname{font-weight:600;text-transform:capitalize}
.etc span{font-variant-numeric:tabular-nums}
.ex-meta{margin-top:9px;font-size:9px;color:var(--muted);display:flex;gap:18px;flex-wrap:wrap}
.ex-meta code{font-family:'JetBrains Mono',monospace}

/* Toast */
.tostw{position:fixed;bottom:22px;right:22px;z-index:200;display:flex;flex-direction:column;gap:7px}
.tost{background:var(--bg-el);border:1px solid var(--border);border-radius:10px;
  padding:11px 16px;font-size:11px;box-shadow:var(--sh);
  display:flex;align-items:center;gap:9px;animation:tin .3s ease;min-width:240px}
.tost.err{border-color:var(--crit)}.tost.ok{border-color:var(--low)}
@keyframes tin{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}

/* Empty */
.empty{text-align:center;padding:38px 18px;color:var(--muted);font-size:12px}
.empty-i{font-size:34px;margin-bottom:10px}

/* Scrollbar */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border-h);border-radius:3px}
</style>
</head>
<body>

<!-- NAV -->
<nav class="nav">
  <div class="logo">R</div>
  <div>
    <span class="brand">RiskNox</span>
    <span class="brand-sub">PII Scanner</span>
  </div>
  <div class="spacer"></div>
  <div class="nav-ocr" id="nav-ocr" title="OCR support status">OCR: checking…</div>
  <div class="badge">
    <div class="dot" id="dot"></div>
    <span id="stxt">IDLE</span>
  </div>
  <button class="btn-stop" id="btn-stop" onclick="stopScan()">⬛ Stop</button>
</nav>

<!-- MAIN GRID -->
<div class="main">

  <!-- LEFT COLUMN -->
  <div style="display:flex;flex-direction:column;gap:15px">

    <!-- Config -->
    <div class="pnl" id="cfg-pnl">
      <div class="ph"><div class="pico">⚙️</div><div class="ptitle">Scan Configuration</div></div>
      <div class="pb">
        <div class="fg">
          <label for="role">Role Profile</label>
          <select id="role">
            <option value="general">General — Desktop, Documents, Downloads</option>
            <option value="hr">HR — includes HR share paths</option>
            <option value="finance">Finance — includes Finance share paths</option>
          </select>
        </div>
        <div class="fg">
          <label>Paths to Scan</label>
          <div class="paths-list" id="plist"></div>
          <button class="btn-add" onclick="addPath()">＋ Add custom path</button>
        </div>
        <div class="fg">
          <label for="maxmb">Max File Size (MB)</label>
          <input type="number" id="maxmb" value="50" min="1" max="500">
        </div>
        <button class="btn-pri" id="btn-start" onclick="startScan()">▶ &nbsp;Start System Scan</button>
      </div>
    </div>

    <!-- Upload -->
    <div class="pnl">
      <div class="ph"><div class="pico">📁</div><div class="ptitle">Scan a File</div></div>
      <div class="pb">
        <div class="upzone" id="upzone"
             ondragover="onOver(event)" ondragleave="onLeave(event)" ondrop="onDrop(event)"
             onclick="document.getElementById('finput').click()">
          <div class="up-icon">📂</div>
          <div class="up-title">Drop a file here to scan it</div>
          <div class="up-sub">Supports: <span>.pdf .xlsx .docx .csv .tsv .txt .json .xml .log .eml .yaml .sql .png .jpg .jpeg</span></div>
        </div>
        <input type="file" id="finput" onchange="onFileSel(event)">
        <div class="up-info" id="upinfo">
          <span>📄</span>
          <span class="up-fname" id="upname">—</span>
          <span class="up-fsize" id="upsize">—</span>
        </div>
        <button class="btn-scanfile" id="btn-sf" onclick="scanFile()">🔍 Scan This File</button>
      </div>
    </div>

  </div>

  <!-- RIGHT COLUMN -->
  <div style="display:flex;flex-direction:column;gap:15px">

    <!-- Idle -->
    <div class="pnl" id="idle-pnl">
      <div class="idle">
        <div class="idle-icon">🔍</div>
        <div style="font-size:15px;font-weight:700;color:var(--text);margin-bottom:10px">Ready to Scan</div>
        <div>Configure your scan on the left and click<br><strong>Start System Scan</strong> — or drop a file to scan it instantly.</div>
        <div style="margin-top:18px;font-size:10px;color:var(--dim);line-height:1.9">
          Detects: Aadhaar · PAN · Passport · Bank Account · IFSC<br>
          Credit/Debit Card · UPI · Voter ID · DOB · Phone · Email
        </div>
      </div>
    </div>

    <!-- Progress -->
    <div class="pnl" id="prog-pnl" style="display:none">
      <div class="ph"><div class="pico" id="scan-spin">🔍</div><div class="ptitle">Live Progress</div></div>
      <div class="pb">
        <div class="prog-wrap on" id="prog-wrap">
          <div class="prog-hdr">
            <div class="prog-pct" id="ppct">0%</div>
            <div class="prog-el" id="pel">0s elapsed</div>
          </div>
          <div class="pbar-wrap"><div class="pbar" id="pbar"></div></div>
          <div class="sg">
            <div class="sc"><div class="sl">Files Seen</div><div class="sv" id="s-seen">0</div></div>
            <div class="sc"><div class="sl">Scanned</div><div class="sv" id="s-scan">0</div></div>
            <div class="sc"><div class="sl">Files with PII</div><div class="sv pii" id="s-pii">0</div></div>
            <div class="sc"><div class="sl">Cache Hits</div><div class="sv" id="s-cache">0</div></div>
          </div>
          <div class="cf-lbl">Currently Scanning</div>
          <div class="cf-path" id="cfile">—</div>
          <div class="cf-lbl" style="margin-top:12px">PII Detected So Far</div>
          <div class="live-types" id="live-types"></div>
        </div>
      </div>
    </div>

    <!-- Results -->
    <div class="res-wrap" id="res-wrap">

      <!-- Tier cards -->
      <div class="pnl" style="margin-bottom:14px">
        <div class="ph"><div class="pico">🎯</div><div class="ptitle">Risk Summary</div></div>
        <div class="scards" id="scards">
          <div class="scard crit"><div class="sci">🔴</div><div class="scv crit" id="r-crit">0</div><div class="sclbl">Critical Files</div></div>
          <div class="scard hi"><div class="sci">🟠</div><div class="scv hi" id="r-hi">0</div><div class="sclbl">High Risk</div></div>
          <div class="scard md"><div class="sci">🟡</div><div class="scv md" id="r-md">0</div><div class="sclbl">Medium Risk</div></div>
          <div class="scard lo"><div class="sci">🟢</div><div class="scv lo" id="r-lo">0</div><div class="sclbl">Low Risk</div></div>
        </div>
        <div class="info-row">
          <div class="scard inf" style="opacity:0;animation:fsup .4s .26s ease both"><div class="sci">📁</div><div class="scv inf" id="r-scanned">0</div><div class="sclbl">Files Scanned</div></div>
          <div class="scard inf" style="opacity:0;animation:fsup .4s .32s ease both"><div class="sci">🚨</div><div class="scv inf" id="r-wpii">0</div><div class="sclbl">Files with PII</div></div>
          <div class="scard inf" style="opacity:0;animation:fsup .4s .38s ease both"><div class="sci">⏱</div><div class="scv inf" id="r-dur">—</div><div class="sclbl">Duration (s)</div></div>
        </div>
      </div>

      <!-- PII Breakdown -->
      <div class="pnl" style="margin-bottom:14px">
        <div class="stitle">PII Type Breakdown</div>
        <div class="pii-grid">
          <div>
            <div class="donut-wrap">
              <svg class="donut-svg" viewBox="0 0 140 140" id="donut"></svg>
              <div class="donut-cx">
                <div class="donut-n" id="dtot">0</div>
                <div class="donut-l">total PII</div>
              </div>
            </div>
          </div>
          <div class="pii-list" id="piil"></div>
        </div>
        <div style="border-top:1px solid var(--border)">
          <table class="ctbl">
            <thead><tr>
              <th>Type</th>
              <th><span style="color:var(--crit)">●</span> High</th>
              <th><span style="color:var(--med)">●</span> Medium</th>
              <th><span style="color:var(--muted)">●</span> Low</th>
              <th class="r">Total</th>
            </tr></thead>
            <tbody id="ctbody"></tbody>
          </table>
        </div>
      </div>

      <!-- Location Classification -->
      <div class="pnl" style="margin-bottom:14px">
        <div class="stitle">Location Classification</div>
        <div class="loc-body">
          <div class="loc-items" id="locitems"></div>
          <div class="loc-stack" id="locstack"></div>
        </div>
      </div>

      <!-- Findings Table -->
      <div class="pnl">
        <div class="stitle">Findings</div>
        <div class="ftbar">
          <div class="sw">
            <span class="si">🔍</span>
            <input class="fsearch" id="fsearch" placeholder="Search path or PII type…" oninput="filterF()">
          </div>
          <button class="fbtn act" data-t="all" onclick="setTier(this)">All</button>
          <button class="fbtn" data-t="critical" onclick="setTier(this)">🔴 Critical</button>
          <button class="fbtn" data-t="high" onclick="setTier(this)">🟠 High</button>
          <button class="fbtn" data-t="medium" onclick="setTier(this)">🟡 Medium</button>
          <button class="fbtn" data-t="low" onclick="setTier(this)">🟢 Low</button>
          <button class="expbtn" onclick="exportJ()">⬇ Export</button>
        </div>
        <div class="ftw">
          <table class="ft">
            <thead><tr>
              <th onclick="sortF('tier')">Risk ↕</th>
              <th onclick="sortF('path')">File ↕</th>
              <th onclick="sortF('size')">Size ↕</th>
              <th>PII Types</th>
              <th onclick="sortF('score')">Score ↕</th>
              <th>Location</th>
            </tr></thead>
            <tbody id="ftbody"></tbody>
          </table>
          <div class="empty" id="fempty" style="display:none">
            <div class="empty-i">✅</div>No findings match the current filter.
          </div>
        </div>
      </div>

    </div><!-- /res-wrap -->
  </div><!-- /right col -->
</div><!-- /main -->

<div class="tostw" id="tostw"></div>

<script>
// ── Constants ──────────────────────────────────────────────────────────────
const TIER_ORD = {critical:0,high:1,medium:2,low:3,none:4};
const COLORS = {
  aadhaar:'#FF6B1A', pan:'#FF3B3B', card:'#FF3B3B',
  passport:'#FF8C00', bank_account:'#FF4500',
  voter_id:'#F5C842', upi:'#A78BFA', dob:'#F472B6',
  ifsc:'#4ECA6A', phone:'#22D3EE', email:'#60A5FA'
};
const DC = '#6B7280';
const RPATHS = {
  general:['~/Desktop','~/Documents','~/Downloads'],
  hr:['~/Desktop','~/Documents','~/Downloads'],
  finance:['~/Desktop','~/Documents','~/Downloads']
};

// ── State ──────────────────────────────────────────────────────────────────
let _state='idle', _poll=null, _results=null, _all=[];
let _tier='all', _sk='score', _sasc=false, _upFile=null;
let _maxPct=0; // highwater-mark so progress never goes backwards

// ── Init ───────────────────────────────────────────────────────────────────
let _paths = [...RPATHS.general];
document.getElementById('role').addEventListener('change', e => {
  _paths = [...(RPATHS[e.target.value] || RPATHS.general)];
  renderPaths();
});
renderPaths();

// Check OCR + server state
(async () => {
  try {
    const s = await fetch('/api/status').then(r=>r.json());
    document.getElementById('nav-ocr').textContent =
      'OCR: ' + (s.status && s.status.ocr_available ? '✅ Available' : '⚠ Not available');
    if (s.scan_state === 'scanning') { setState('scanning'); startPoll(); }
    else if (s.scan_state === 'done') { await loadResults(); setState('done'); }
  } catch(e) {
    document.getElementById('nav-ocr').textContent = 'OCR: checking…';
  }
})();

// ── Path editor ────────────────────────────────────────────────────────────
function renderPaths() {
  const el = document.getElementById('plist');
  el.innerHTML = _paths.map((p,i) => `
    <div class="pi">
      <span title="${p}">${p}</span>
      <button class="pi-rm" onclick="rmPath(${i})" title="Remove">×</button>
    </div>`).join('');
}
function rmPath(i) { _paths.splice(i,1); renderPaths(); }
function addPath() {
  const p = prompt('Enter folder path to include:');
  if (p && p.trim()) { _paths.push(p.trim()); renderPaths(); }
}

// ── State machine ──────────────────────────────────────────────────────────
function setState(s) {
  _state = s;
  const dot = document.getElementById('dot');
  const txt = document.getElementById('stxt');
  const stop = document.getElementById('btn-stop');
  const start = document.getElementById('btn-start');
  const idle = document.getElementById('idle-pnl');
  const prog = document.getElementById('prog-pnl');
  const res = document.getElementById('res-wrap');
  dot.className = 'dot ' + s;
  txt.textContent = s.toUpperCase();
  if (s === 'scanning') {
    stop.classList.add('on'); start.disabled = true;
    idle.style.display = 'none'; prog.style.display = 'block'; res.classList.remove('on');
  } else if (s === 'done') {
    stop.classList.remove('on'); start.disabled = false;
    idle.style.display = 'none'; prog.style.display = 'none'; res.classList.add('on');
    stopPoll();
  } else if (s === 'error') {
    stop.classList.remove('on'); start.disabled = false;
    prog.style.display = 'none'; stopPoll();
  } else {
    stop.classList.remove('on'); start.disabled = false;
    idle.style.display = 'block'; prog.style.display = 'none';
  }
}

// ── Scan actions ───────────────────────────────────────────────────────────
async function startScan() {
  const role = document.getElementById('role').value;
  const maxMb = parseInt(document.getElementById('maxmb').value)||50;
  try {
    const r = await fetch('/api/scan/start',{
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({role, paths:_paths, max_mb:maxMb})
    }).then(r=>r.json());
    if (r.ok) {
      _maxPct = 0; // reset progress highwater mark for new scan
      // Reset progress UI
      document.getElementById('ppct').textContent = '0%';
      document.getElementById('pbar').style.width = '0%';
      document.getElementById('s-seen').textContent = '0';
      document.getElementById('s-scan').textContent = '0';
      document.getElementById('s-pii').textContent = '0';
      document.getElementById('s-cache').textContent = '0';
      document.getElementById('cfile').textContent = '\u2014';
      document.getElementById('live-types').innerHTML = '';
      setState('scanning'); startPoll(); toast('Scan started ('+role+' profile)','ok');
    } else {
      toast(r.error||'Failed to start scan','err');
    }
  } catch(e) { toast('Server error: '+e.message,'err'); }
}
async function stopScan() {
  await fetch('/api/scan/stop',{method:'POST'});
  toast('Scan stopping…','');
  setTimeout(()=>{ if(_state==='scanning') setState('idle'); }, 2000);
}

// ── Polling ────────────────────────────────────────────────────────────────
function startPoll() { if (_poll) return; _poll=setInterval(pollStatus,1500); pollStatus(); }
function stopPoll() { if (_poll){clearInterval(_poll);_poll=null;} }

async function pollStatus() {
  try {
    const d = await fetch('/api/status').then(r=>r.json());
    updateProg(d);
    if (d.scan_state==='done') { await loadResults(); setState('done'); }
    else if (d.scan_state==='error') { toast('Scan error: '+(d.error||'unknown'),'err'); setState('error'); }
  } catch(e){}
}

function updateProg(d) {
  const st = d.status||{};
  const seen=st.files_seen||0, scanned=st.files_scanned||0;
  const pii=st.files_with_pii||0, cache=st.cache_hits||0, el=st.elapsed_s||0;
  // Clamp to highwater mark — progress never goes backwards
  const raw = seen>0 ? Math.min(96, Math.round(scanned/seen*100)) : 0;
  _maxPct = Math.max(_maxPct, raw);
  document.getElementById('ppct').textContent = _maxPct+'%';
  document.getElementById('pbar').style.width = _maxPct+'%';
  document.getElementById('pel').textContent = el+'s elapsed';
  document.getElementById('s-seen').textContent = seen.toLocaleString();
  document.getElementById('s-scan').textContent = scanned.toLocaleString();
  document.getElementById('s-pii').textContent = pii.toLocaleString();
  document.getElementById('s-cache').textContent = cache.toLocaleString();
  document.getElementById('cfile').textContent = st.current_file||'—';
  const types = st.findings_by_type||{};
  const lt = document.getElementById('live-types');
  if (Object.keys(types).length) {
    lt.innerHTML = Object.entries(types).map(([t,v])=>{
      const tot=(v.high||0)+(v.medium||0)+(v.low||0);
      const c=COLORS[t]||DC;
      return `<span style="display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:20px;
        background:${c}18;border:1px solid ${c}44;font-size:10px;">
        <span style="width:6px;height:6px;border-radius:50%;background:${c};display:inline-block"></span>
        <span style="text-transform:capitalize;color:var(--text)">${t.replace(/_/g,' ')}</span>
        <span style="color:${c};font-weight:700">${tot}</span></span>`;
    }).join('');
  }
}

// ── Load results ───────────────────────────────────────────────────────────
async function loadResults() {
  try {
    const d = await fetch('/api/results').then(r=>r.json());
    if (d.error) { toast(d.error,'err'); return; }
    _results = d; _all = d.findings||[];
    renderResults(d);
  } catch(e) { toast('Failed to load results','err'); }
}

function renderResults(d) {
  const s = d.summary||{}, bt=s.by_tier||{}, m=d.meta||{};
  document.getElementById('r-crit').textContent=(bt.critical||0).toLocaleString();
  document.getElementById('r-hi').textContent=(bt.high||0).toLocaleString();
  document.getElementById('r-md').textContent=(bt.medium||0).toLocaleString();
  document.getElementById('r-lo').textContent=(bt.low||0).toLocaleString();
  document.getElementById('r-scanned').textContent=(s.files_scanned||0).toLocaleString();
  document.getElementById('r-wpii').textContent=(s.files_with_pii||0).toLocaleString();
  document.getElementById('r-dur').textContent=m.duration_s!=null?m.duration_s+'s':'—';
  renderPIIBreak(s.findings_by_type||{});
  renderLoc(s.by_location_class||{});
  renderFT();
}

// ── PII Breakdown ──────────────────────────────────────────────────────────
function renderPIIBreak(types) {
  const entries = Object.entries(types).sort((a,b)=>{
    return ((b[1].high||0)+(b[1].medium||0)+(b[1].low||0)) -
           ((a[1].high||0)+(a[1].medium||0)+(a[1].low||0));
  });
  const totals = entries.map(([,v])=>(v.high||0)+(v.medium||0)+(v.low||0));
  const grand = totals.reduce((a,b)=>a+b,0);
  document.getElementById('dtot').textContent = grand.toLocaleString();
  drawDonut(entries,totals,grand);
  const maxC = Math.max(...totals,1);
  document.getElementById('piil').innerHTML = entries.map(([t,v],i)=>{
    const c=COLORS[t]||DC, tot=totals[i], pct=Math.round(tot/maxC*100);
    return `<div class="pii-row">
      <div class="pdot" style="background:${c}"></div>
      <div class="pname">${t.replace(/_/g,' ')}</div>
      <div class="pbar-w"><div class="pbar-f" style="width:${pct}%;background:${c}"></div></div>
      <div class="pcount">${tot}</div>
    </div>`;
  }).join('');
  document.getElementById('ctbody').innerHTML = entries.length ? entries.map(([t,v],i)=>`
    <tr>
      <td class="cname">${t.replace(/_/g,' ')}</td>
      <td class="ch">${v.high||0}</td>
      <td class="cm">${v.medium||0}</td>
      <td class="cl">${v.low||0}</td>
      <td class="ctot">${totals[i]}</td>
    </tr>`)
  .join('') : '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:18px">No PII detected</td></tr>';
}

function drawDonut(entries, totals, grand) {
  const svg = document.getElementById('donut');
  svg.innerHTML = '';
  const bg = svgEl('circle',{cx:70,cy:70,r:46,fill:'none',stroke:'var(--bg-el)','stroke-width':16});
  svg.appendChild(bg);
  if (!grand) return;
  const circ = 2*Math.PI*54;
  let off = 0;
  entries.forEach(([t],i) => {
    const frac = totals[i]/grand;
    const dl = frac*circ, gap=circ-dl;
    const c = COLORS[t]||DC;
    const el = svgEl('circle',{cx:70,cy:70,r:54,fill:'none',stroke:c,
      'stroke-width':16,'stroke-dasharray':`${dl} ${gap}`,
      'stroke-dashoffset':-off*circ,'stroke-linecap':'butt'});
    el.style.transition='stroke-dasharray .8s ease';
    svg.appendChild(el);
    off += frac;
  });
}
function svgEl(tag, attrs) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  Object.entries(attrs).forEach(([k,v])=>el.setAttribute(k,v));
  return el;
}

// ── Location bar ───────────────────────────────────────────────────────────
function renderLoc(loc) {
  const v=loc.violation||0, r=loc.review||0, ex=loc.expected_location||0, tot=v+r+ex;
  document.getElementById('locitems').innerHTML = `
    <div class="loc-it"><div class="loc-dot v"></div><span style="color:var(--crit)">${v} Violation</span></div>
    <div class="loc-it"><div class="loc-dot rv"></div><span style="color:var(--med)">${r} Review</span></div>
    <div class="loc-it"><div class="loc-dot ex"></div><span style="color:var(--low)">${ex} Expected</span></div>`;
  if (tot>0) {
    const vp=(v/tot*100).toFixed(1), rp=(r/tot*100).toFixed(1), ep=(ex/tot*100).toFixed(1);
    document.getElementById('locstack').innerHTML=
      `<div class="ls v" style="width:${vp}%"></div>
       <div class="ls rv" style="width:${rp}%"></div>
       <div class="ls ex" style="width:${ep}%"></div>`;
  } else {
    document.getElementById('locstack').innerHTML='<div style="width:100%;height:100%;background:var(--bg-el);border-radius:99px"></div>';
  }
}

// ── Findings table ─────────────────────────────────────────────────────────
function renderFT() {
  const q = (document.getElementById('fsearch').value||'').toLowerCase();
  let rows = _all.filter(f => {
    if (_tier!=='all' && f.tier!==_tier) return false;
    if (q && !f.path.toLowerCase().includes(q) &&
        !Object.keys(f.types||{}).some(t=>t.includes(q))) return false;
    return true;
  });
  rows.sort((a,b)=>{
    let va=a[_sk], vb=b[_sk];
    if (_sk==='tier'){va=TIER_ORD[a.tier]||9;vb=TIER_ORD[b.tier]||9;}
    return _sasc?(va<vb?-1:va>vb?1:0):(va>vb?-1:va<vb?1:0);
  });
  const tbody=document.getElementById('ftbody'), empty=document.getElementById('fempty');
  if (!rows.length){tbody.innerHTML='';empty.style.display='block';return;}
  empty.style.display='none';
  tbody.innerHTML = rows.map((f,i)=>{
    const tkeys=Object.keys(f.types||{});
    const badges=tkeys.slice(0,3).map(t=>{
      const c=COLORS[t]||DC;
      return `<span style="display:inline-block;padding:2px 6px;border-radius:4px;font-size:9px;
        background:${c}1A;border:1px solid ${c}44;color:${c};text-transform:capitalize;margin:1px">${t.replace(/_/g,' ')}</span>`;
    }).join('')+(tkeys.length>3?`<span style="font-size:9px;color:var(--muted)"> +${tkeys.length-3}</span>`:'');
    const locCls=f.location_class==='expected_location'?'expected':(f.location_class==='n/a'?'na':f.location_class||'na');
    const locLbl=f.location_class==='expected_location'?'expected':(f.location_class||'n/a');
    const sc=f.score>=100?'var(--crit)':f.score>=40?'var(--high)':f.score>=10?'var(--med)':'var(--low)';
    const eid='ex'+i;
    const fname=f.path.split(/[/\\]/).pop();
    return `<tr class="dr" onclick="toggleEx('${eid}')">
      <td><span class="tbadge ${f.tier}">${f.tier.toUpperCase()}</span></td>
      <td><div class="fpath" title="${f.path}">${fname}<br><span style="font-size:9px;color:var(--muted)">${f.path}</span></div></td>
      <td style="white-space:nowrap;color:var(--muted)">${fmtSz(f.size)}</td>
      <td>${badges}</td>
      <td><span class="sval" style="color:${sc}">${f.score}</span></td>
      <td><span class="lbadge ${locCls}">${locLbl}</span></td>
    </tr>
    <tr class="exrow" id="${eid}"><td colspan="6"><div class="exc" id="${eid}-c">
      <div class="exi">
        <div style="font-size:9px;color:var(--muted);margin-bottom:9px;font-family:'JetBrains Mono',monospace">${f.path}</div>
        <div class="ex-types">${Object.entries(f.types||{}).map(([t,v])=>{
          const c=COLORS[t]||DC, tot=(v.high||0)+(v.medium||0)+(v.low||0);
          return `<div class="etchip" style="border-color:${c}44">
            <span class="etname" style="color:${c}">${t.replace(/_/g,' ')}</span>
            <span class="etc">
              <span style="color:var(--crit)">${v.high||0}H</span>
              <span style="color:var(--dim)"> · </span>
              <span style="color:var(--med)">${v.medium||0}M</span>
              <span style="color:var(--dim)"> · </span>
              <span style="color:var(--muted)">${v.low||0}L</span>
              <span style="color:var(--dim)"> = </span>
              <strong style="color:var(--text)">${tot}</strong>
            </span>
          </div>`;
        }).join('')}</div>
        <div class="ex-meta">
          <span>SHA-256: <code>${(f.sha256||'').slice(0,16)}…</code></span>
          <span>Modified: ${f.modified||'—'}</span>
          <span>Score: <strong style="color:var(--orange)">${f.score}</strong></span>
          <span>Size: ${fmtSz(f.size)}</span>
        </div>
      </div>
    </div></td></tr>`;
  }).join('');
}

function toggleEx(id) {
  const c=document.getElementById(id+'-c');
  if (!c) return;
  if (c.classList.contains('open')) { c.classList.remove('open'); }
  else {
    document.querySelectorAll('.exc.open').forEach(el=>el.classList.remove('open'));
    c.classList.add('open');
  }
}
function setTier(btn) {
  _tier=btn.dataset.t;
  document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('act'));
  btn.classList.add('act');
  renderFT();
}
function filterF() { renderFT(); }
function sortF(k) {
  if(_sk===k) _sasc=!_sasc; else {_sk=k;_sasc=false;}
  renderFT();
}
function exportJ() {
  if (!_results) return;
  const b=new Blob([JSON.stringify(_results,null,2)],{type:'application/json'});
  const u=URL.createObjectURL(b), a=document.createElement('a');
  a.href=u; a.download='pii_report.json'; a.click(); URL.revokeObjectURL(u);
}

// ── File Upload ────────────────────────────────────────────────────────────
function onOver(e) { e.preventDefault(); document.getElementById('upzone').classList.add('over'); }
function onLeave(e) { document.getElementById('upzone').classList.remove('over'); }
function onDrop(e) {
  e.preventDefault();
  document.getElementById('upzone').classList.remove('over');
  const f=e.dataTransfer.files[0]; if(f) setUF(f);
}
function onFileSel(e) { const f=e.target.files[0]; if(f) setUF(f); }
function setUF(f) {
  _upFile=f;
  document.getElementById('upinfo').classList.add('on');
  document.getElementById('upname').textContent=f.name;
  document.getElementById('upsize').textContent=fmtSz(f.size);
  document.getElementById('btn-sf').classList.add('on');
}
async function scanFile() {
  if(!_upFile) return;
  const btn=document.getElementById('btn-sf');
  btn.disabled=true; btn.textContent='⏳ Scanning…';
  const fd=new FormData(); fd.append('file',_upFile);
  try {
    const r=await fetch('/api/scan/file',{method:'POST',body:fd}).then(r=>r.json());
    if (r.error) toast('Error: '+r.error,'err');
    else if (r.skip_reason) toast('Skipped: '+r.skip_reason,'');
    else {
      toast('✅ File scanned: '+_upFile.name,'ok');
      await loadResults();
      setState('done');
    }
  } catch(e) { toast('Upload failed: '+e.message,'err'); }
  finally { btn.disabled=false; btn.textContent='🔍 Scan This File'; }
}

// ── Helpers ────────────────────────────────────────────────────────────────
function fmtSz(b) {
  if(!b) return '—';
  if(b<1024) return b+' B';
  if(b<1048576) return (b/1024).toFixed(1)+' KB';
  return (b/1048576).toFixed(1)+' MB';
}
function toast(msg,type) {
  const w=document.getElementById('tostw'), el=document.createElement('div');
  el.className='tost '+(type||'');
  const ic=type==='err'?'❌':type==='ok'?'✅':'ℹ️';
  el.innerHTML=`<span>${ic}</span><span>${msg}</span>`;
  w.appendChild(el);
  setTimeout(()=>{ el.style.opacity='0'; el.style.transform='translateY(8px)';
    el.style.transition='.3s'; setTimeout(()=>el.remove(),300); },3500);
}
</script>
</body>
</html>"""


# ─── Port finder ──────────────────────────────────────────────────────────────
def _find_port(start=5000, tries=12):
    import socket
    for p in range(start, start + tries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", p))
                return p
        except OSError:
            continue
    raise RuntimeError(f"No free port found in range {start}-{start+tries}")


# ─── Main ──────────────────────────────────────────────────────────────────────
def main():
    # Ensure UTF-8 output on Windows consoles
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    port = _find_port()
    url = f"http://127.0.0.1:{port}"
    server = _ThreadedServer(("127.0.0.1", port), _Handler)

    banner = f"""
╔══════════════════════════════════════════════════╗
║          RiskNox PII Scanner — UI Ready          ║
╠══════════════════════════════════════════════════╣
║  URL  :  {url:<40}║
║  Engine: pii_scan v{pii_scan.VERSION:<31}║
║  Press Ctrl-C to shut down                       ║
╚══════════════════════════════════════════════════╝
"""
    print(banner)

    # Open browser after brief warm-up delay
    threading.Timer(0.9, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[RiskNox] Shutting down - goodbye.")
        server.shutdown()


if __name__ == "__main__":
    main()
