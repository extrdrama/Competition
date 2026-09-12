#!/usr/bin/env python
"""演示"误报反馈闭环"：标注 → 校准 → 生效 → 复核。

用途有两个：
1. 验证闭环链路可用；
2. 答辩现场演示"系统越用越准"，而不是只展示一次性扫描。

用法：
    python -m credwatch demo                        # 先产生一批发现
    python scripts/demo_feedback_loop.py --dry-run  # 走完整链路，但不写入权重
    python scripts/demo_feedback_loop.py            # 真正写入校准后的权重
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from credwatch.config import Settings  # noqa: E402
from credwatch.detectors.scoring import FEATURE_LABELS, ProbabilityScorer  # noqa: E402
from credwatch.feedback import FeedbackLoop  # noqa: E402
from credwatch.storage import Storage  # noqa: E402

# 模拟人工复核的判定依据：这两类规则在演示语料里分别是"明确格式"与"上下文提示"
TRUE_POSITIVE_RULES = (
    "aws-access-key-id",
    "aws-secret-access-key",
    "gitlab-pat",
    "npm-token",
    "aliyun-access-key-id",
    "aliyun-access-key-secret",
    "tencent-cloud-secret-id",
    "jwt-signing-secret",
    "private-key-rsa-pem",
)
FALSE_POSITIVE_RULES = (
    "generic-private-ip-credential",
    "entropy-high-value",
    "weak-credential-pair",
    "private-config-file-reference",
)


def label_samples(loop: FeedbackLoop, storage: Storage, per_class: int) -> tuple[int, int]:
    print("=== 第一步：模拟人工复核并标注 ===")
    tp = fp = 0
    for cred in storage.credentials():
        rule_id = cred.get("rule_id") or ""
        if rule_id in TRUE_POSITIVE_RULES and tp < per_class:
            outcome = loop.label(cred["fingerprint"][:16], False, "格式明确，确认真实泄露")
            if outcome.found:
                tp += 1
                print(f"  [真实] {outcome.message[:78]}")
        elif rule_id in FALSE_POSITIVE_RULES and fp < per_class:
            outcome = loop.label(cred["fingerprint"][:16], True, "上下文提示，非真实凭据")
            if outcome.found:
                fp += 1
                print(f"  [误报] {outcome.message[:78]}")
    print(f"\n本次标注：真实 {tp} 条 / 误报 {fp} 条")
    return tp, fp


def main() -> int:
    parser = argparse.ArgumentParser(description="演示误报反馈闭环")
    parser.add_argument("--dry-run", action="store_true", help="只计算，不写入权重文件")
    parser.add_argument("--per-class", type=int, default=8, help="每类最多标注多少条")
    args = parser.parse_args()

    settings = Settings.load()
    storage = Storage(settings.db_path)
    loop = FeedbackLoop(settings, storage)

    credentials = storage.credentials()
    if not credentials:
        print("数据库中暂无扫描结果，请先执行：python -m credwatch demo")
        return 1

    print(f"当前数据库：{settings.db_path}")
    print(f"可用发现：{len(credentials)} 条")
    before = ProbabilityScorer.load_or_prior(settings.scoring_weights_file)
    print(
        f"当前评分权重：{'已校准（样本 %d 条）' % before.sample_count if before.calibrated else '专家先验'}\n"
    )

    label_samples(loop, storage, args.per_class)

    # ---------------------------------------------------------------- 校准
    print("\n=== 第二步：用标注样本校准评分权重 ===")
    report = loop.calibrate_weights(save=not args.dry_run)
    if report is None:
        stats = loop.stats()
        print(
            f"样本不足，保持专家先验（当前 {stats['total']} 条，"
            "需要至少 8 条且同时包含正负样本）"
        )
        return 1

    print(f"  {report.summary()}")
    print("\n  权重变化最大的特征：")
    for name, prior, calibrated in report.top_changes[:6]:
        label = FEATURE_LABELS.get(name, name)
        arrow = "↑" if calibrated > prior else "↓"
        print(f"    {arrow} {label:<28s} {prior:+.2f} → {calibrated:+.2f}")

    # ---------------------------------------------------------------- 生效
    print("\n=== 第三步：新权重生效 ===")
    if args.dry_run:
        print("  --dry-run：未写入权重文件，实际运行时会写入")
        print(f"  目标路径：{settings.scoring_weights_file}")
    else:
        print(f"  已写入：{settings.scoring_weights_file}")
        after = ProbabilityScorer.load_or_prior(settings.scoring_weights_file)
        print(f"  下次扫描将加载：{'已校准' if after.calibrated else '专家先验'}")

    # ---------------------------------------------------------------- 抑制
    print("\n=== 第四步：误报抑制 ===")
    print(f"  已抑制指纹：{len(loop.suppressed())} 条（后续扫描不再重复上报）")

    # ---------------------------------------------------------------- 复核
    print("\n=== 第五步：修复复核能力 ===")
    result = loop.verify_remediation()
    print(f"  {result['summary']}")
    print("  说明：修复后重跑扫描，凭据不再出现即计入「已消除」。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
