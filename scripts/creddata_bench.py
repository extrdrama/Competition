#!/usr/bin/env python
"""CredData 公开基准子集上的多工具统一口径对比评测。

背景与口径
----------
CredData（三星）是业界主流凭据检测基准：19.4M 行标注语料 + 9 个工具的公开 F1 表
（CredSweeper 0.8586 / gitleaks 0.3336 / detect-secrets 0.2065 / truffleHog3 0.2351）。

官方 harness（`benchmark/`）的 `check_line_from_meta` 要求工具输出的 rule 名与 meta 的
Category 一致才计入，而 gitleaks 适配器未传 rule 名 → 直接套用会得到失真数字。
为保证公平，本脚本对**所有工具使用完全相同的判定口径**（逐条对应官方 result.py）：

- 真值：meta 的 GroundTruth == 'T'（人工确认的真凭据实例，一行一条）；
- **TP** = 命中覆盖到的 T 凭据实例数（凭据范围内任一行被命中即算命中）；
- **FN** = 未被覆盖的 T 凭据实例数；
- **FP** = 命中行中不落在任何 T 范围内的行数（含 F 标注行、X 标注行与未标注行，
  对应官方「非 T 即误报」口径）；
- Precision = TP/(TP+FP)，Recall = TP/(TP+FN)，F1 = 2PR/(P+R)，FPR = FP/(FP+TN)。

子集：真值行最多的 20 个中小仓库，官方流水线重建 + 官方混淆，1665 个标注文件 /
T=3892 / F=7008 / X=1014。所有工具跑的是**同一份数据**，故横向可比；与官方全量数字
仅作背景参照（规模不同，不作绝对数值断言）。

用法
----
    # 凭迹：扫描并把原始命中（含严重度/置信度）落盘，便于多阈值离线复评
    python scripts/creddata_bench.py --tool credwatch --dump-raw output/raw_credwatch.json \
        --json output/creddata_credwatch_all.json
    # 用不同阈值复评（无需重扫）
    python scripts/creddata_bench.py --from-raw output/raw_credwatch.json \
        --min-severity high --json output/creddata_credwatch_high.json
    # 外部工具
    python scripts/creddata_bench.py --tool gitleaks --findings output/gitleaks_creddata.json
    python scripts/creddata_bench.py --tool detect_secrets --findings output/detect_secrets_creddata.json
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

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


# --------------------------------------------------------------------------- #
# 数据加载
# --------------------------------------------------------------------------- #
def available_repos(data_root: Path) -> set[str]:
    return {p.name for p in (data_root / "data").iterdir() if p.is_dir()}


def load_meta(meta_dir: Path, repos: set[str]) -> dict[str, list[dict]]:
    by_file: dict[str, list[dict]] = defaultdict(list)
    for repo in sorted(repos):
        f = meta_dir / f"{repo}.csv"
        if not f.exists():
            continue
        for r in csv.DictReader(f.open(encoding="utf-8")):
            by_file[r["FilePath"]].append(r)
    return by_file


def normalize_path(raw: str) -> str | None:
    p = raw.replace("\\", "/")
    idx = p.find("/data/")
    if idx >= 0:
        return p[idx + 1:]
    if p.startswith("data/"):
        return p
    return None


# --------------------------------------------------------------------------- #
# 命中提取 → 记录列表 [(rel, line, severity, confidence, rule_id)]
# --------------------------------------------------------------------------- #
def records_from_credwatch(data_root: Path, meta_by_file: dict[str, list[dict]]) -> list[dict]:
    from credwatch.detectors import DetectionPipeline, RuleEngine
    from credwatch.models import Document

    engine = RuleEngine.from_dir(str(ROOT / "config" / "rules"))
    pipeline = DetectionPipeline(engine, hmac_salt="creddata-bench")
    records: list[dict] = []

    files = sorted(meta_by_file)
    for i, rel in enumerate(files, 1):
        path = data_root / rel
        if not path.exists():
            continue
        try:
            text = path.read_bytes().decode("utf-8", errors="ignore")
        except OSError:
            continue
        doc = Document(
            doc_id=Document.new_id("creddata", rel),
            source="local_dir",
            url=f"file://{rel}",
            text=text,
            path_hint=rel,
            metadata={"source_category": "本地与企业内网"},
        )
        for finding in pipeline.run([doc]).findings:
            ln = finding.evidence.line_no
            if ln:
                records.append({
                    "file": rel,
                    "line": int(ln),
                    "severity": finding.severity,
                    "confidence": round(float(finding.confidence), 4),
                    "rule_id": finding.rule_id,
                })
        if i % 200 == 0:
            print(f"  凭迹扫描进度 {i}/{len(files)}", flush=True)
    return records


def _records_from_external(items: list[tuple[str, int, int]], tool: str) -> list[dict]:
    out: list[dict] = []
    for rel, start, end in items:
        for ln in range(start, max(start, end) + 1):
            out.append({"file": rel, "line": ln, "severity": "high", "confidence": 1.0, "rule_id": tool})
    return out


def records_from_gitleaks(findings_path: Path) -> list[dict]:
    data = json.loads(findings_path.read_text(encoding="utf-8"))
    items = []
    for it in data:
        rel = normalize_path(it.get("File", ""))
        if rel:
            items.append((rel, int(it.get("StartLine") or 0), int(it.get("EndLine") or 0)))
    return _records_from_external(items, "gitleaks")


def records_from_detect_secrets(findings_path: Path) -> list[dict]:
    payload = json.loads(findings_path.read_text(encoding="utf-8"))
    items = []
    for raw_path, rows in (payload.get("results") or {}).items():
        rel = normalize_path(raw_path)
        if not rel:
            continue
        for it in rows or []:
            if it.get("line_number"):
                items.append((rel, int(it["line_number"]), int(it["line_number"])))
    return _records_from_external(items, "detect-secrets")


def records_from_credsweeper(findings_path: Path) -> list[dict]:
    """CredSweeper 1.18+ JSON 报告 → 统一记录。

    实际结构：顶层 [rule, severity, confidence, ml_probability, line_data_list]，
    line_data_list 每项含 path / line_num（1 基单行）/ value 等。
    """
    data = json.loads(findings_path.read_text(encoding="utf-8"))
    records: list[dict] = []
    for item in data if isinstance(data, list) else data.get("results", []):
        rule = item.get("rule", "credsweeper")
        mp = item.get("ml_probability")
        score = float(mp) if isinstance(mp, (int, float)) else 1.0
        for ld in item.get("line_data_list") or []:
            rel = normalize_path(ld.get("path", ""))
            ln = int(ld.get("line_num") or 0)
            if not rel or ln <= 0:
                continue
            records.append({
                "file": rel, "line": ln, "severity": "high",
                "confidence": round(score, 4), "rule_id": rule,
            })
    return records


# --------------------------------------------------------------------------- #
# 统一评分
# --------------------------------------------------------------------------- #
def score(records: list[dict], meta_by_file: dict[str, list[dict]], data_root: Path,
          min_severity: str | None = None, min_confidence: float | None = None) -> dict:
    floor = SEVERITY_ORDER.get(min_severity or "low", 0)
    flagged: dict[str, set[int]] = defaultdict(set)
    for r in records:
        if SEVERITY_ORDER.get(r.get("severity", "low"), 0) < floor:
            continue
        if min_confidence is not None and float(r.get("confidence", 1.0)) < min_confidence:
            continue
        flagged[r["file"]].add(int(r["line"]))

    tp = fp = fn = tn = 0
    fp_on_f = fp_on_x = fp_unannotated = 0
    scanned_files = scanned_lines = skipped = 0
    by_category: dict[str, dict[str, int]] = defaultdict(lambda: {"TP": 0, "FN": 0})
    fp_by_rule: dict[str, int] = defaultdict(int)

    line_sev: dict[tuple[str, int], dict] = {}
    for r in records:
        line_sev[(r["file"], int(r["line"]))] = r

    for rel, rows in meta_by_file.items():
        path = data_root / rel
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

        hits = flagged.get(rel, set())
        t_rows = [r for r in rows if (r["GroundTruth"] or "").upper() == "T"]
        f_lines: set[int] = set()
        x_lines: set[int] = set()
        for r in rows:
            s = int(r["LineStart"] or 0)
            e = max(s, int(r["LineEnd"] or s))
            gt = (r["GroundTruth"] or "").upper()
            if gt == "F":
                f_lines |= set(range(s, e + 1))
            elif gt == "X":
                x_lines |= set(range(s, e + 1))

        t_lines: set[int] = set()
        for r in t_rows:
            s = int(r["LineStart"] or 0)
            e = max(s, int(r["LineEnd"] or s))
            rng = set(range(s, e + 1))
            t_lines |= rng
            if hits & rng:
                tp += 1
                by_category[r["Category"]]["TP"] += 1
            else:
                fn += 1
                by_category[r["Category"]]["FN"] += 1

        fp_lines = hits - t_lines
        fp += len(fp_lines)
        for ln in fp_lines:
            if ln in f_lines:
                fp_on_f += 1
            elif ln in x_lines:
                fp_on_x += 1
            else:
                fp_unannotated += 1
            rid = line_sev.get((rel, ln), {}).get("rule_id", "?")
            fp_by_rule[rid] += 1
        tn += max(0, n_lines - len(t_lines) - len(fp_lines))

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    fnr = fn / (tp + fn) if tp + fn else 0.0
    acc = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0

    return {
        "min_severity": min_severity or "low",
        "min_confidence": min_confidence,
        "hit_lines": sum(len(v) for v in flagged.values()),
        "files_with_hits": len(flagged),
        "scanned_files": scanned_files, "skipped_files": skipped,
        "scanned_lines": scanned_lines,
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "FP_on_F_lines": fp_on_f, "FP_on_X_lines": fp_on_x, "FP_on_unannotated": fp_unannotated,
        "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
        "accuracy": round(acc, 6), "FPR": round(fpr, 8), "FNR": round(fnr, 4),
        "by_category": {k: v for k, v in sorted(by_category.items(), key=lambda x: -x[1]["TP"])},
        "fp_top_rules": dict(sorted(fp_by_rule.items(), key=lambda x: -x[1])[:12]),
    }


def print_report(tool: str, result: dict) -> None:
    print(f"\n=== {tool} @ CredData 子集（阈值 severity>={result['min_severity']}"
          + (f", conf>={result['min_confidence']}" if result.get("min_confidence") else "") + "）===")
    print(f"命中行 {result['hit_lines']}（涉及 {result['files_with_hits']} 个文件） | 扫描 {result['scanned_files']} 文件")
    print(f"TP {result['TP']} | FP {result['FP']} | FN {result['FN']}")
    print(f"Precision {result['precision']:.4f} | Recall {result['recall']:.4f} | F1 {result['f1']:.4f}")
    print(f"Accuracy {result['accuracy']:.6f} | FPR {result['FPR']:.2e} | FNR {result['FNR']:.4f}")
    print(f"误报来源：F 标注行 {result['FP_on_F_lines']} | X 标注行 {result['FP_on_X_lines']}"
          f" | 未标注行 {result['FP_on_unannotated']}")
    print("误报最多的规则：")
    for rid, n in list(result["fp_top_rules"].items())[:8]:
        print(f"  {rid:32s} {n}")
    print("按类别（TP 前 10）：")
    for cat, v in list(result["by_category"].items())[:10]:
        pr = v["TP"] / (v["TP"] + v["FN"]) if v["TP"] + v["FN"] else 0
        print(f"  {cat:30s} TP {v['TP']:5d} FN {v['FN']:5d} | 召回 {pr:.2f}")


def main() -> int:
    ap = argparse.ArgumentParser(description="CredData 子集多工具统一口径评测")
    ap.add_argument("--tool", choices=["credwatch", "gitleaks", "detect_secrets", "credsweeper"])
    ap.add_argument("--data-root", default=".bench/CredData")
    ap.add_argument("--findings", default=None, help="外部工具 JSON 报告")
    ap.add_argument("--from-raw", default=None, help="从已落盘的原始命中复评")
    ap.add_argument("--dump-raw", default=None, help="把原始命中落盘")
    ap.add_argument("--min-severity", default=None, choices=list(SEVERITY_ORDER))
    ap.add_argument("--min-confidence", type=float, default=None)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    data_root = Path(args.data_root)
    meta_by_file = load_meta(data_root / "meta", available_repos(data_root))
    print(f"子集：{len(available_repos(data_root))} 仓库 | 标注文件 {len(meta_by_file)}", flush=True)

    if args.from_raw:
        records = json.loads(Path(args.from_raw).read_text(encoding="utf-8"))
        tool = Path(args.from_raw).stem
    elif args.tool == "credwatch":
        records = records_from_credwatch(data_root, meta_by_file)
        tool = "credwatch"
        if args.dump_raw:
            Path(args.dump_raw).write_text(json.dumps(records, ensure_ascii=False), encoding="utf-8")
            print(f"原始命中已落盘：{args.dump_raw}（{len(records)} 条）", flush=True)
    elif args.tool == "gitleaks":
        records = records_from_gitleaks(Path(args.findings))
        tool = "gitleaks"
    elif args.tool == "credsweeper":
        records = records_from_credsweeper(Path(args.findings))
        tool = "credsweeper"
    else:
        records = records_from_detect_secrets(Path(args.findings))
        tool = "detect-secrets"

    result = score(records, meta_by_file, data_root, args.min_severity, args.min_confidence)
    result["tool"] = tool
    print_report(tool, result)

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print("\n结果已写入:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
