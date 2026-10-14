#!/usr/bin/env python3
"""Run the scanner over the synthetic corpus and compare against ground truth.
Usage: python evaluate.py [corpus_dir] [manifest.json]"""
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pii_scan  # noqa: E402

corpus = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "corpus")
manifest_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "manifest.json")
truth = json.load(open(manifest_path))

rep = pii_scan.run_scan([corpus], role="hr")
detected = {}  # rel path -> type -> {"high":n,"medium":n,"low":n}
for f in rep["findings"]:
    detected[os.path.relpath(f["path"], corpus).replace("\\", "/")] = f["types"]

LEVELS = {"all findings (>= low)": ("high", "medium", "low"),
          "reported (>= medium)": ("high", "medium"),
          "high confidence only": ("high",)}
types = sorted({t for v in truth.values() for t in v} | {t for d in detected.values() for t in d})
files = sorted(set(truth) | set(detected))

lines = []
for label, confs in LEVELS.items():
    tp, fp, fn = {}, {}, {}
    for rel in files:
        for t in types:
            exp = truth.get(rel, {}).get(t, 0)
            det = sum(detected.get(rel, {}).get(t, {}).get(c, 0) for c in confs)
            tp[t] = tp.get(t, 0) + min(exp, det)
            fp[t] = fp.get(t, 0) + max(0, det - exp)
            fn[t] = fn.get(t, 0) + max(0, exp - det)
    lines.append("\n### %s" % label)
    lines.append("%-14s %5s %4s %4s %9s %7s" % ("type", "TP", "FP", "FN", "precision", "recall"))
    T = [0, 0, 0]
    for t in types:
        p = tp[t] / (tp[t] + fp[t]) if tp[t] + fp[t] else float("nan")
        r = tp[t] / (tp[t] + fn[t]) if tp[t] + fn[t] else float("nan")
        lines.append("%-14s %5d %4d %4d %9.3f %7.3f" % (t, tp[t], fp[t], fn[t], p, r))
        T[0] += tp[t]; T[1] += fp[t]; T[2] += fn[t]
    lines.append("%-14s %5d %4d %4d %9.3f %7.3f" % ("TOTAL", *T, T[0] / max(1, T[0] + T[1]), T[0] / max(1, T[0] + T[2])))

# mismatches at the 'all findings' level
lines.append("\n### Per-file mismatches (all findings)")
bad = 0
for rel in files:
    for t in types:
        exp = truth.get(rel, {}).get(t, 0)
        c = {k: detected.get(rel, {}).get(t, {}).get(k, 0) for k in ("high", "medium", "low")}
        det = sum(c.values())
        if exp != det:
            bad += 1
            lines.append("  %-38s %-13s expected %3d  detected %3d  (conf: %s)" % (rel, t, exp, det, c))
if not bad:
    lines.append("  none")

# Verhoeff alone is a weak filter: measure it
rnd = random.Random(1)
n = 20000
passed = sum(pii_scan.verhoeff_ok(str(rnd.randint(2, 9)) + "".join(rnd.choice("0123456789") for _ in range(11))) for _ in range(n))
lines.append("\n### Sanity: random 12-digit numbers passing the Verhoeff checksum: %.1f%% (%d/%d)" % (100 * passed / n, passed, n))
lines.append("-> checksum alone cannot make an Aadhaar hit 'high'; context keywords/column headers are required.")

lines.append("\n### Skipped-file handling")
lines.append(json.dumps(rep["summary"]["skipped_by_reason"]))
out = "\n".join(lines)
print(out)
open(os.path.join(HERE, "evaluation.txt"), "w").write(out + "\n")
