#!/usr/bin/env python3
"""Compare two scanner reports (e.g. Python reference vs native exe) file-by-file.
Usage: python tools/parity.py ref_report.json new_report.json ROOT_DIR"""
import json
import os
import sys

ref, new, root = json.load(open(sys.argv[1])), json.load(open(sys.argv[2])), sys.argv[3]


def by_file(rep):
    return {os.path.relpath(f["path"], root).replace("\\", "/"):
            {t: (v["high"], v["medium"], v["low"], v["unique"]) for t, v in f["types"].items()} for f in rep["findings"]}


a, b = by_file(ref), by_file(new)
diffs = 0
for p in sorted(set(a) | set(b)):
    for t in sorted(set(a.get(p, {})) | set(b.get(p, {}))):
        x, y = a.get(p, {}).get(t), b.get(p, {}).get(t)
        if x != y:
            diffs += 1
            print("DIFF %-45s %-13s ref(h,m,l,uniq)=%s new=%s" % (p, t, x, y))
sa, sb = ref["summary"], new["summary"]
for k in ("files_seen", "files_scanned", "files_with_pii", "by_tier", "by_location_class", "skipped_by_reason"):
    if sa.get(k) != sb.get(k):
        print("SUMMARY %-18s ref=%s new=%s" % (k, sa.get(k), sb.get(k)))
print("files compared: %d | per-file/type differences: %d | ref %.1fs vs new %.1fs"
      % (len(set(a) | set(b)), diffs, ref["meta"]["duration_s"], new["meta"]["duration_s"]))
sys.exit(1 if diffs else 0)
