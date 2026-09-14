#!/usr/bin/env python
"""CredData 子集上的工具互补性分析（NC State 式）。

回答两个问题：
1. 不同工具命中的真值凭据实例交集有多大？（文献称 ggshield×gitleaks 仅 18%）
2. "最优两两组合 / 全部工具并集"能多覆盖多少真值？（支撑多层覆盖路线）

输入：各工具在 output/ 下的原始命中（credwatch 用 raw_credwatch.json）。
口径与 creddata_bench.py 完全一致：T 行范围内任一行被命中即视为该实例被覆盖。
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

# 真值凭据实例清单
trows = []
for rel, rows in meta_by_file.items():
    if not (data_root / rel).exists():
        continue
    for i, r in enumerate(rows):
        if (r["GroundTruth"] or "").upper() != "T":
            continue
        s = int(r["LineStart"] or 0)
        e = max(s, int(r["LineEnd"] or s))
        trows.append({
            "file": rel, "s": s, "e": e, "cat": r["Category"],
            "key": (rel, s, e, r.get("ValueStart", ""), r.get("ValueEnd", ""), r["Category"], i),
        })
print(f"真值凭据实例：{len(trows)} 条（{len(meta_by_file)} 个标注文件）")

# 各工具的命中行 {file: set(lines)}
def flagged_of(records):
    f = defaultdict(set)
    for r in records:
        f[r["file"]].add(int(r["line"]))
    return f

tools = {}
cw = json.load(open("output/raw_credwatch.json"))
tools["凭迹 CredWatch"] = flagged_of(cw)
tools["gitleaks 8.30.1"] = flagged_of(B.records_from_gitleaks(Path("output/gitleaks_creddata.json")))
tools["detect-secrets 1.5.0"] = flagged_of(B.records_from_detect_secrets(Path("output/detect_secrets_creddata.json")))
if Path("output/credsweeper_default.json").exists():
    tools["CredSweeper 1.18.3"] = flagged_of(B.records_from_credsweeper(Path("output/credsweeper_default.json")))

# 每个工具覆盖的真值实例 key 集合
matched = {}
for name, flagged in tools.items():
    s = set()
    for row in trows:
        rng = range(row["s"], row["e"] + 1)
        if flagged.get(row["file"], set()) & set(rng):
            s.add(row["key"])
    matched[name] = s
    print(f"{name:26s} 覆盖真值实例 {len(s):5d}（召回 {len(s)/len(trows):.4f}）")

names = list(matched)
print("\n=== 两两交集（Jaccard = 交/并）===")
print(f"{'组合':44s} {'A':>6s} {'B':>6s} {'交':>6s} {'A独有':>6s} {'B独有':>6s} {'Jaccard':>8s}")
for i in range(len(names)):
    for j in range(i + 1, len(names)):
        a, b = matched[names[i]], matched[names[j]]
        inter = len(a & b)
        union = len(a | b)
        print(f"{names[i]+' × '+names[j]:44s} {len(a):6d} {len(b):6d} {inter:6d} "
              f"{len(a-b):6d} {len(b-a):6d} {inter/union if union else 0:8.2%}")

# 组合覆盖
print("\n=== 组合覆盖 ===")
allu = set().union(*matched.values())
print(f"全部 {len(names)} 工具并集：{len(allu)}（{len(allu)/len(trows):.2%}）")
best_pair = max(
    ((names[i], names[j]) for i in range(len(names)) for j in range(i + 1, len(names))),
    key=lambda p: len(matched[p[0]] | matched[p[1]]))
bp = matched[best_pair[0]] | matched[best_pair[1]]
print(f"最优两两组合 {best_pair[0]} × {best_pair[1]}：{len(bp)}（{len(bp)/len(trows):.2%}）")

# 类别互补：凭迹覆盖而 gitleaks 未覆盖最多的类别
cw_only = matched["凭迹 CredWatch"] - matched["gitleaks 8.30.1"]
gl_only = matched["gitleaks 8.30.1"] - matched["凭迹 CredWatch"]
cat_cw = defaultdict(int)
cat_gl = defaultdict(int)
for row in trows:
    if row["key"] in cw_only:
        cat_cw[row["cat"]] += 1
    if row["key"] in gl_only:
        cat_gl[row["cat"]] += 1
print("\n=== 类别互补（凭迹独有 vs gitleaks 独有，Top8）===")
print(f"{'类别':30s} {'凭迹独有':>8s} {'gitleaks独有':>10s}")
cats = set(list(cat_cw)[:0]) | set(cat_cw) | set(cat_gl)
for c in sorted(cats, key=lambda c: -(cat_cw.get(c, 0) + cat_gl.get(c, 0)))[:8]:
    print(f"{c:30s} {cat_cw.get(c,0):8d} {cat_gl.get(c,0):10d}")

Path("output/overlap_report.json").write_text(json.dumps({
    "total_true": len(trows),
    "per_tool_covered": {n: len(s) for n, s in matched.items()},
    "pairwise": [
        {"a": names[i], "b": names[j],
         "inter": len(matched[names[i]] & matched[names[j]]),
         "union": len(matched[names[i]] | matched[names[j]])}
        for i in range(len(names)) for j in range(i + 1, len(names))
    ],
    "all_union": len(allu),
}, ensure_ascii=False, indent=2))
print("\n已写入 output/overlap_report.json")
