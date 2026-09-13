#!/usr/bin/env python
"""渠道逐个真实冒烟测试：每个渠道真实抓取，输出"真支持/需配置/失败"矩阵。

判定标准：
- OK     ：真实网络抓取到 >=1 份文档（渠道逻辑真实可用）
- 需配置 ：因缺少令牌/目标实例等外部配置而无法工作（渠道代码本身待配置后验证）
- 失败   ：代码问题导致无法抓取（需要修复）

用法：python scripts/channel_smoke.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from credwatch.config import Settings  # noqa: E402
from credwatch.sources import load_all_sources, registry  # noqa: E402

# 各渠道在无令牌条件下可真实访问的目标（用于实测）
LIVE_TARGETS: dict[str, dict] = {
    "github": {"mode": "recent", "max_items": 3, "include_gist": False},
    "container_registry": {"images": ["library/alpine"], "max_items": 3},
    "npm_registry": {"packages": ["express"], "max_items": 2},
    "pypi_registry": {"packages": ["requests"], "max_items": 2},
    "paste_site": {"sites": ["pastebin"], "max_items": 3},
    "mediawiki": {"api_urls": ["https://zh.wikipedia.org/w/api.php"], "max_items": 2},
    "telegram": {"channels": ["durov"], "max_items": 3},
    "rss_feed": {"feeds": ["https://hnrss.org/frontpage"], "max_items": 2},
    "local_dir": {"paths": [str(ROOT / "credwatch")], "max_files": 5},
}


def main() -> int:
    settings = Settings.load()
    results: list[tuple[str, str, str]] = []  # (渠道, 判定, 说明)

    for name in sorted(registry.names()):
        adapter_cls = registry.get(name)
        meta = adapter_cls.meta
        options = dict(LIVE_TARGETS.get(name, {}))
        options["max_items"] = options.get("max_items", 3)

        # LIVE_TARGETS 中的渠道即使在 requires_token 下也有免令牌模式（如 github recent）
        if meta.requires_token and name not in LIVE_TARGETS:
            results.append((name, "需配置", "需要访问令牌，当前环境未配置"))
            continue

        if name in ("confluence", "doc_share", "search_engine", "weibo") and name not in LIVE_TARGETS:
            results.append((name, "需配置", "需要指定目标实例/接口配置后才能工作"))
            continue
        if name in ("mobile_app", "mini_program"):
            results.append((name, "需配置", "需提供 APK/wxapkg 文件路径后工作（解析逻辑由单元测试覆盖）"))
            continue

        started = time.monotonic()
        try:
            adapter = adapter_cls(settings, **options)
            docs = []
            for doc in adapter.discover({}):
                docs.append(doc)
                if len(docs) >= 3:
                    break
            elapsed = time.monotonic() - started
            if docs:
                sample = (docs[0].url or docs[0].external_id)[:60]
                results.append(
                    (name, "OK", f"实测抓取 {len(docs)} 份文档（{elapsed:.1f}s），样例: {sample}")
                )
            else:
                results.append((name, "失败", f"抓取 0 份文档（{elapsed:.1f}s）——需排查"))
        except Exception as exc:  # noqa: BLE001
            results.append((name, "失败", f"{type(exc).__name__}: {str(exc)[:100]}"))
        finally:
            try:
                adapter.close()  # noqa: F821
            except Exception:  # noqa: BLE001
                pass

    print("\n=== 渠道实测矩阵 ===\n")
    ok = sum(1 for _, v, _ in results if v == "OK")
    need_cfg = sum(1 for _, v, _ in results if v == "需配置")
    failed = sum(1 for _, v, _ in results if v == "失败")
    for name, verdict, note in results:
        mark = {"OK": "✅", "需配置": "⚙️ ", "失败": "❌"}[verdict]
        print(f"{mark} {verdict:４<4} {name:20s} {note}")

    print(f"\n合计 {len(results)}：实测通过 {ok}｜需配置 {need_cfg}｜失败 {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
