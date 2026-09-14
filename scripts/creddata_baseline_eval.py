#!/usr/bin/env python
"""在 CredData 同一子集上评测**基线工具**（gitleaks），口径与 creddata_eval.py 完全一致。

用途：与凭迹在同一子集、同一判定规则下对比，避免"拿全量官方数字比子集数字"的不公平。

用法：
    python scripts/creddata_baseline_eval.py --tool gitleaks \
        --findings output/gitleaks_creddata.json --data-root .bench/CredData
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path


def normalize(path: str, data_root: Path) -> str:
    """把工具输出的文件路径归一化为 meta 口径的 'data/<repo>/...'。"""
    p = path.replace("\\", "/")
    marker = f"{data_root.as_posix()}/"
    if marker in p:
        return p.split(marker, 1)[1]
    if "/data/" in p:
        return "data/" + p.split("/data/", 1)[1]
    return p.lstrip("./")


def load_meta(meta_dir: Path) -> dict[str, list[dict]]:
    per_repo: dict[str, list[dict]] = {}
    for f in sorted(meta_dir.glob("*.csv")):
        rows = list(csv.DictReader(f.open(encoding="utf-8")))
        if rows:
            per_repo[f.stem] = rows
    return per_repo


def evaluate(data_root: Path, findings_path: Path) -> dict:
    per_repo = load_meta(data_root / "meta")

    raw = json.loads(findings_path.read_text(encoding="utf-8"))
    detected: dict[str, set[int]] = defaultdict(set)
    for item in raw:
        key = normalize(item["File"], data_root)
        start = int(item.get("StartLine") or 0)
        end = int(item.get("EndLine") or start)
        if start <= 0:
            continue
        for ln in range(start, max(start, end) + 1):
            detected[key].add(ln)

    stats = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    by_category = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0})
    scanned_files = skipped = scanned_lines = 0

    for repo, rows in per_repo.items():
        file_rows: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            file_rows[r["FilePath"]].append(r)
        for rel_path, gt_rows in file_rows.items():
            path = data_root / rel_path
            if not path.exists():
                skipped += 1
                continue
            try:
                text = path.read_bytes().decode("utf-8", errors="ignore")
            except OSError:
                skipped += 1
                continue
            scanned_files += 1
            n_lines = text.count("\n") + 1
            scanned_lines += n_lines

            flagged = detected.get(rel_path, set())

            t_lines: dict[int, str] = {}
            cat_of: dict[int, str] = {}
            for r in gt_rows:
                start = int(r["LineStart"] or 0)
                end = int(r["LineEnd"] or start)
                for ln in range(start, max(start, end) + 1):
                    t_lines[ln] = (r["GroundTruth"] or "").upper()
                    cat_of[ln] = r["Category"] or "Other"

            gt_set = set(t_lines)
            for ln in sorted(gt_set):
                label = t_lines[ln]
                if label == "X":
                    continue
                hit = ln in flagged
                cat = cat_of.get(ln, "Other")
                if label == "T":
                    if hit:
                        stats["TP"] += 1
                        by_category[cat]["TP"] += 1
                    else:
                        stats["FN"] += 1
                        by_category[cat]["FN"] += 1
                else:
                    if hit:
                        stats["FP"] += 1
                        by_category[cat]["FP"] += 1
            for ln in flagged:
                if ln in gt_set and (t_lines[ln] == "T" or t_lines[ln] == "X" or t_lines[ln] == "F"):
                    continue
                stats["FP"] += 1
                by_category["Other/未标注行"]["FP"] += 1

            stats["TN"] += max(0, n_lines - len(gt_set))

    tp, fp, fn, tn = stats["TP"], stats["FP"], stats["FN"], stats["TN"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tool": findings_path.stem,
        "raw_findings": len(raw),
        "scanned_files": scanned_files,
        "skipped_files": skipped,
        "scanned_lines": scanned_lines,
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "FPR": round(fp / (fp + tn) if fp + tn else 0.0, 8),
        "FNR": round(fn / (tp + fn) if tp + fn else 0.0, 4),
        "by_category": dict(sorted(by_category.items(), key=lambda x: -x[1]["TP"])),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="CredData 基线工具评测（同口径）")
    ap.add_argument("--tool", default="gitleaks")
    ap.add_argument("--findings", required=True)
    ap.add_argument("--data-root", default=".bench/CredData")
    ap.add_argument("--json", default="output/creddata_baseline.json")
    args = ap.parse_args()

    result = evaluate(Path(args.data_root), Path(args.findings))
    out = Path(args.json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n=== CredData 基线评测：{args.tool}（子集，同口径）===")
    print(f"原始命中 {result['raw_findings']} | 扫描文件 {result['scanned_files']}"
          f"（跳过 {result['skipped_files']}）| 行数 {result['scanned_lines']:,}")
    print(f"TP {result['TP']} | FP {result['FP']} | FN {result['FN']}")
    print(f"Precision {result['precision']:.4f} | Recall {result['recall']:.4f} | F1 {result['f1']:.4f}")
    print("\n按类别（前 10）：")
    for cat, v in list(result["by_category"].items())[:10]:
        p = v["TP"] / (v["TP"] + v["FP"]) if v["TP"] + v["FP"] else 0
        r = v["TP"] / (v["TP"] + v["FN"]) if v["TP"] + v["FN"] else 0
        print(f"  {cat:24s} TP {v['TP']:5d} FP {v['FP']:5d} FN {v['FN']:5d} | P {p:.2f} R {r:.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
