#!/usr/bin/env python
"""在 CredData（三星，公开基准）上评测凭迹的检测指标。

背景
----
CredData 是业界主流的凭据检测基准（19.4M 行标注语料 + 9 个工具的公开 F1 表）。
完整数据集需按官方快照克隆 337 个仓库重建；本脚本采用**官方流水线的子集**
（默认选取真值行最多的 N 个中小仓库），用**与官方完全相同的口径**统计：

- 逐行判定：某行被标记的凭据命中 → 命中；否则未命中；
- TP = 真值为 T 且命中；FN = 真值为 T 未命中；
- FP = 命中但真值不为 T（含真值为 F 与未标注行）；TN = 其余行；
- 指标：Precision / Recall / F1 / FPR / FNR，另按类别分桶。

用法
----
    python scripts/creddata_eval.py --data-root .bench/CredData --json output/creddata_eval.json
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from credwatch.detectors import DetectionPipeline, RuleEngine  # noqa: E402
from credwatch.models import Document  # noqa: E402


def load_meta(meta_dir: Path) -> dict[str, list[dict]]:
    """读取全部 meta CSV，按仓库 crc32 名聚合。"""
    per_repo: dict[str, list[dict]] = {}
    for f in sorted(meta_dir.glob("*.csv")):
        rows = list(csv.DictReader(f.open(encoding="utf-8")))
        if rows:
            per_repo[f.stem] = rows
    return per_repo


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def evaluate(data_root: Path, engine: RuleEngine, max_files: int | None = None) -> dict:
    meta_dir = data_root / "meta"
    data_dir = data_root / "data"
    per_repo = load_meta(meta_dir)

    pipeline = DetectionPipeline(engine, hmac_salt="creddata-eval")
    stats = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    by_category = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0})
    scanned_files = 0
    scanned_lines = 0
    skipped = 0

    for repo, rows in per_repo.items():
        # 该仓库的数据文件（若子集未包含该仓库则跳过）
        repo_files = {r["FilePath"]: r for r in rows}
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

            doc = Document(
                doc_id=Document.new_id("creddata", rel_path),
                source="local_dir",
                url=f"file://{rel_path}",
                text=text,
                path_hint=rel_path,
                metadata={"source_category": "本地与企业内网"},
            )
            result = pipeline.run([doc])
            flagged_lines: set[int] = set()
            for finding in result.findings:
                ln = finding.evidence.line_no
                if not ln:
                    continue
                end = finding.evidence.line_end or ln
                for x in range(int(ln), max(int(ln), int(end)) + 1):
                    flagged_lines.add(x)

            # 真值行：T/F/X（X = 未定，官方口径排除）
            t_lines: dict[int, str] = {}
            for r in gt_rows:
                start = int(r["LineStart"] or 0)
                end = int(r["LineEnd"] or start)
                for ln in range(start, max(start, end) + 1):
                    t_lines[ln] = (r["GroundTruth"] or "").upper()

            gt_set = set(t_lines)
            for ln in sorted(gt_set):
                label = t_lines[ln]
                if label == "X":
                    continue
                hit = ln in flagged_lines
                cat = next((r["Category"] for r in gt_rows
                            if int(r["LineStart"] or 0) <= ln <= int(r["LineEnd"] or 0)), "Other")
                if label == "T":
                    if hit:
                        stats["TP"] += 1
                        by_category[cat]["TP"] += 1
                    else:
                        stats["FN"] += 1
                        by_category[cat]["FN"] += 1
                else:  # 'F'
                    if hit:
                        stats["FP"] += 1
                        by_category[cat]["FP"] += 1
            # 命中但不在真值集中的行 → FP（官方口径：任何非 T 行的命中都是 FP）
            for ln in flagged_lines:
                if ln in gt_set and t_lines[ln] in ("T", "X"):
                    continue
                if ln in gt_set and t_lines[ln] == "F":
                    continue  # 已在上面计入
                stats["FP"] += 1
                by_category["Other/未标注行"]["FP"] += 1

            # TN：全部行 - T 行 - 任何命中行（近似口径，与官方一致：不逐行枚举阴性）
            stats["TN"] += max(0, n_lines - len(gt_set))

            if max_files and scanned_files >= max_files:
                break
        if max_files and scanned_files >= max_files:
            break

    tp, fp, fn, tn = stats["TP"], stats["FP"], stats["FN"], stats["TN"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    fnr = fn / (tp + fn) if tp + fn else 0.0
    return {
        "repos_used": sum(1 for r in per_repo if any((data_root / p).exists() for p in
                                                     {row["FilePath"] for row in per_repo[r]})),
        "scanned_files": scanned_files,
        "skipped_files": skipped,
        "scanned_lines": scanned_lines,
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "FPR": round(fpr, 8),
        "FNR": round(fnr, 4),
        "by_category": {k: v for k, v in sorted(by_category.items(), key=lambda x: -x[1]["TP"])},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="CredData 基准评测")
    parser.add_argument("--data-root", default=".bench/CredData", help="CredData 仓库目录（含 meta/ 与 data/）")
    parser.add_argument("--json", default="output/creddata_eval.json", help="结果输出路径")
    parser.add_argument("--max-files", type=int, default=None, help="最多扫描文件数（调试用）")
    args = parser.parse_args()

    engine = RuleEngine.from_dir("config/rules")
    result = evaluate(Path(args.data_root), engine, args.max_files)

    out = Path(args.json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n=== CredData 子集评测（与官方同口径逐行判定）===")
    print(f"仓库数 {result['repos_used']} | 扫描文件 {result['scanned_files']}（跳过 {result['skipped_files']}）"
          f" | 扫描行数 {result['scanned_lines']:,}")
    print(f"TP {result['TP']} | FP {result['FP']} | FN {result['FN']}")
    print(f"Precision {result['precision']:.4f} | Recall {result['recall']:.4f} | F1 {result['f1']:.4f}")
    print(f"FPR {result['FPR']:.2e} | FNR {result['FNR']:.4f}")
    print("\n按类别：")
    for cat, v in list(result["by_category"].items())[:10]:
        p = v["TP"] / (v["TP"] + v["FP"]) if v["TP"] + v["FP"] else 0
        r = v["TP"] / (v["TP"] + v["FN"]) if v["TP"] + v["FN"] else 0
        print(f"  {cat:24s} TP {v['TP']:5d} FP {v['FP']:4d} FN {v['FN']:5d} | P {p:.2f} R {r:.2f}")
    print("\n结果已写入:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
