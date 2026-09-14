#!/usr/bin/env python
"""CredData 子集上的误报/漏报诊断：为规则强化提供数据依据。

输出：
1. FP 最多的规则 + 样本（命中行原文）——用于收紧模式；
2. FN 最多的类别 + 样本（漏掉的真值行原文）——用于扩展覆盖。
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import creddata_bench as B  # noqa: E402

data_root = Path(".bench/CredData")
repos = B.available_repos(data_root)
meta_by_file = B.load_meta(data_root / "meta", repos)

records = json.load(open("output/raw_credwatch.json"))
flagged = defaultdict(set)
rule_of = {}
for r in records:
    flagged[r["file"]].add(int(r["line"]))
    rule_of[(r["file"], int(r["line"]))] = r.get("rule_id", "?")

fp_by_rule: dict[str, list] = defaultdict(list)
fn_by_cat: dict[str, list] = defaultdict(list)
n_fp = n_fn = 0

for rel, rows in meta_by_file.items():
    path = data_root / rel
    if not path.exists():
        continue
    try:
        text = path.read_bytes().decode("utf-8", errors="ignore")
    except OSError:
        continue
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    hits = flagged.get(rel, set())

    t_keys: set[int] = set()
    t_rows = []
    for r in rows:
        if (r["GroundTruth"] or "").upper() != "T":
            continue
        s = int(r["LineStart"] or 0)
        e = max(s, int(r["LineEnd"] or s))
        for ln in range(s, e + 1):
            t_keys.add(ln)
        t_rows.append((s, e, r))

    for ln in hits - t_keys:
        n_fp += 1
        rule = rule_of.get((rel, ln), "?")
        if ln - 1 < len(lines):
            fp_by_rule[rule].append((rel, ln, lines[ln - 1][:130]))

    for s, e, r in t_rows:
        if not (hits & set(range(s, e + 1))):
            n_fn += 1
            fn_by_cat[r["Category"]].append((rel, s, lines[s - 1][:130] if s - 1 < len(lines) else ""))

print(f"总 FP 行 {n_fp} | 总 FN 实例 {n_fn}")

print("\n========== FP TOP 规则（每条 6 个样本）==========")
for rule, lst in sorted(fp_by_rule.items(), key=lambda x: -len(x[1]))[:6]:
    print(f"\n--- {rule}: {len(lst)} FP ---")
    for rel, ln, text in lst[:6]:
        print(f"  {rel}:{ln} | {text.strip()!r}")

print("\n========== FN TOP 类别（每类 6 个样本）==========")
for cat, lst in sorted(fn_by_cat.items(), key=lambda x: -len(x[1]))[:8]:
    print(f"\n--- {cat}: {len(lst)} FN ---")
    for rel, s, text in lst[:6]:
        print(f"  {rel}:{s} | {text.strip()!r}")
