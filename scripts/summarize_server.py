#!/usr/bin/env python3
"""汇总服务器上三份评测结果。"""
import json

TOOLS = [
    ("credwatch", "凭迹 CredWatch", "output/creddata_credwatch_all.json"),
    ("gitleaks", "gitleaks 8.30.1", "output/creddata_gitleaks.json"),
    ("detect_secrets", "detect-secrets 1.5.0", "output/creddata_detect_secrets.json"),
]

rows = []
for key, label, path in TOOLS:
    d = json.load(open(path))
    rows.append((key, label, d))
    print("%-22s TP %5d  FP %5d  FN %5d  |  P %.4f  R %.4f  F1 %.4f" % (
        label, d["TP"], d["FP"], d["FN"], d["precision"], d["recall"], d["f1"]))

best = max(rows, key=lambda x: x[2]["f1"])
print("\nF1 最高:", best[1])

cw = dict(rows[0][2])
print("凭迹误报来源: F标注行 %d | X标注行 %d | 未标注行 %d" % (
    cw["FP_on_F_lines"], cw["FP_on_X_lines"], cw["FP_on_unannotated"]))
print("凭迹误报Top规则:")
for rid, n in list(cw["fp_top_rules"].items())[:6]:
    print("   %-32s %d" % (rid, n))
print("\n凭迹按类别召回(TP前8):")
for cat, v in list(cw["by_category"].items())[:8]:
    rec = v["TP"] / (v["TP"] + v["FN"]) if v["TP"] + v["FN"] else 0
    print("   %-30s TP %5d FN %5d | 召回 %.2f" % (cat, v["TP"], v["FN"], rec))
