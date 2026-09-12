#!/usr/bin/env python
"""真实渠道实测脚本：扫描 GitHub 公开 Gist（无需令牌）。

目的：为《测试报告》提供**真实公开渠道**的扫描数据，
回答"你们实际发现了多少条"这一评审必问的问题。

说明：
- 公开 Gist 是凭据泄露高发区（开发者把配置/脚本当"一次性分享"贴上去）；
- `/gists/public` 为公开接口，无需令牌；仅读取公开内容；
- 结果只保留掩码与指纹，不输出任何明文凭据；
- 扫描完成后把统计写入 docs/测试报告.md 的"真实渠道实测"一节。

用法：
    python scripts/demo_real_scan.py --max-gists 60
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from credwatch.config import Settings  # noqa: E402
from credwatch.scheduler import ScanEngine  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="真实渠道实测（GitHub 公开 Gist）")
    parser.add_argument("--max-gists", type=int, default=60, help="最多处理的 Gist 数")
    parser.add_argument("--db", default="data/real_scan.db", help="结果数据库路径")
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=30,
        help="每分钟请求上限（内容走 raw 地址，可按需放宽）",
    )
    args = parser.parse_args()

    settings = Settings.load()
    settings.db_path = ROOT / args.db
    settings.ensure_dirs()

    engine = ScanEngine(settings)
    engine.sources_config = {
        "sources": {
            # mode=search 在无令牌时会被 API 拒绝并快速跳过，
            # 从而只走"公开 Gist"这一高产出的真实来源
            "github": {
                "enabled": True,
                "mode": "search",
                "include_gist": True,
                "max_items": args.max_gists,
                "rate_limit_per_minute": args.rate_limit,
            }
        }
    }

    print("=== 真实渠道实测：GitHub 公开 Gist ===")
    print("说明：只读取公开内容；结果仅含掩码与指纹，不含明文凭据。\n")

    result = engine.run(["github"], full_rescan=True)
    stats = result.stats
    cred = result.credential_stats or {}
    pairs = list(getattr(result.correlation, "pairs", []) or [])

    print("扫描概览")
    print(f"  处理文档        {stats.documents_scanned}")
    print(f"  扫描字节        {stats.bytes_scanned / 1024:.1f} KB")
    print(f"  耗时            {stats.elapsed_seconds():.1f} s")
    print(f"  去重后唯一凭据  {cred.get('unique_credentials', 0)}")
    print(f"  暴露位置总数    {cred.get('total_exposures', 0)}")
    print(f"  凭据对          {len(pairs)}")
    print(f"  跨渠道扩散      {cred.get('multi_channel', 0)}")
    print()
    print("按风险等级：")
    for severity, count in (cred.get("by_severity") or {}).items():
        print(f"  {severity:<10s} {count}")
    print()
    print("按凭据类型：")
    for kind, count in list((cred.get("by_kind") or {}).items())[:10]:
        print(f"  {kind:<24s} {count}")
    print()
    print("按规则：")
    for category, count in list((cred.get("by_category") or {}).items())[:10]:
        print(f"  {category:<24s} {count}")

    if result.clusters:
        print("\n命中样例（已脱敏，按风险排序）：")
        for cluster in result.clusters[:10]:
            attr = result.attributions.get(cluster.fingerprint)
            owner = attr.display if attr else "-"
            print(
                f"  [{cluster.severity:<8s}] {cluster.masked:<16s} "
                f"{cluster.rule_name:<26s} 暴露{cluster.exposure_count}处  归属:{owner}"
            )
            print(f"      判定依据：{cluster.explanation[:90]}")

    print("\n结果已写入数据库：", settings.db_path)
    print("生成正式报告：python -m credwatch report")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
