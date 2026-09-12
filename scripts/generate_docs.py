#!/usr/bin/env python
"""从代码生成两份交付文档，保证文档与实现永远一致。

生成：
    docs/支持的公开渠道列表.md
    docs/支持的凭据类型列表.md

这两份文档是赛题明确要求的交付件。之所以用脚本生成而不是手工维护，
是因为手工文档一旦与代码脱节就会误导评审；
直接读取渠道注册表与规则库，可以做到"代码改了文档自动跟上"。
"""

from __future__ import annotations

import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from credwatch.config import Settings  # noqa: E402
from credwatch.detectors import RuleEngine  # noqa: E402
from credwatch.sources import CATEGORY_ORDER, registry  # noqa: E402
from credwatch.validators import validators  # noqa: E402

DOCS = PROJECT_ROOT / "docs"

SEVERITY_LABEL = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "提示",
}


def generate_sources_doc() -> Path:
    grouped = registry.by_category()
    order = [c for c in CATEGORY_ORDER if c in grouped]
    order += [c for c in grouped if c not in CATEGORY_ORDER]

    lines: list[str] = []
    add = lines.append
    add("# 凭迹 CredWatch · 支持的公开渠道列表\n")
    add(f"> 本文档由 `scripts/generate_docs.py` 从渠道注册表自动生成，"
        f"生成时间 {datetime.now().strftime('%Y-%m-%d %H:%M')}。\n")
    add(f"当前版本共支持 **{len(registry.names())}** 个公开渠道，"
        f"覆盖 **{len(grouped)}** 个类别。\n")
    add("## 渠道总览\n")
    add("| # | 渠道标识 | 渠道名称 | 类别 | 令牌要求 | 限速(次/分钟) |")
    add("| --- | --- | --- | --- | --- | --- |")
    index = 0
    for category in order:
        for meta in grouped[category]:
            index += 1
            add(
                f"| {index} | `{meta.name}` | {meta.label} | {category} | "
                f"{'需要' if meta.requires_token else '不需要'} | {meta.rate_limit_per_minute} |"
            )
    add("")

    add("## 渠道明细\n")
    for category in order:
        add(f"### {category}\n")
        for meta in grouped[category]:
            add(f"#### `{meta.name}` — {meta.label}\n")
            if meta.description:
                add(f"{meta.description}\n")
            add(f"- 令牌要求：{'需要（未配置时该渠道自动跳过）' if meta.requires_token else '不需要'}")
            add(f"- 调用频率上限：{meta.rate_limit_per_minute} 次/分钟（代码强制限速）")
            if meta.homepage:
                add(f"- 平台主页：{meta.homepage}")
            add("")

    add("## 扩展方式\n")
    add("新增一个渠道只需三步，无需改动任何现有代码：\n")
    add("```python")
    add("@registry.register")
    add("class MySource(SourceAdapter):")
    add("    meta = SourceMeta(")
    add('        name="my_source", label="我的渠道", category="内容共享平台",')
    add("    )")
    add("")
    add("    def discover(self, cursor=None):")
    add("        ...  # 产出 RawDoc")
    add("```")
    add("")
    add("1. 新建模块并在类上标注 `meta`；")
    add("2. 用 `@registry.register` 装饰；")
    add("3. 在 `credwatch/sources/__init__.py` 中增加一行 import。")
    add("")
    add("`normalize()`（内容归一化、归档与镜像层解包）与 `next_cursor()`"
        "（增量游标）已由基类提供默认实现，绝大多数渠道无需覆写。\n")

    path = DOCS / "支持的公开渠道列表.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def generate_rules_doc() -> Path:
    settings = Settings.load()
    engine = RuleEngine.from_dir(settings.rules_dir)
    stats = engine.stats()

    by_category: dict[str, list] = defaultdict(list)
    for rule in engine.rules:
        by_category[rule.label].append(rule)

    kinds = sorted({rule.kind for rule in engine.rules})

    lines: list[str] = []
    add = lines.append
    add("# 凭迹 CredWatch · 支持的凭据类型列表\n")
    add(f"> 本文档由 `scripts/generate_docs.py` 从规则库自动生成，"
        f"生成时间 {datetime.now().strftime('%Y-%m-%d %H:%M')}。\n")
    add("## 覆盖规模\n")
    add("| 项目 | 数量 |")
    add("| --- | --- |")
    add(f"| 检测规则总数 | **{stats['total_rules']}** |")
    add(f"| 凭据大类 | **{len(stats['categories'])}** |")
    add(f"| 凭据类型（细粒度） | **{len(kinds)}** |")
    add(f"| 可做只读活性验证的类型 | **{len(stats['validators'])}** |")
    add("")

    add("## 凭据类型清单（按大类）\n")
    for label, rules in sorted(by_category.items(), key=lambda kv: -len(kv[1])):
        add(f"### {label}（{len(rules)} 条规则）\n")
        add("| 规则 ID | 凭据类型 | 风险等级 | 活性验证 | 说明 |")
        add("| --- | --- | --- | --- | --- |")
        for rule in rules:
            desc = (rule.description or "").replace("|", "／")
            add(
                f"| `{rule.id}` | {rule.name} | {SEVERITY_LABEL.get(rule.severity, rule.severity)} | "
                f"{rule.validator or '—'} | {desc} |"
            )
        add("")

    add("## 活性验证器清单\n")
    add("验证器只调用目标平台的**只读身份查询接口**，默认关闭"
        "（需设置 `CREDWATCH_ENABLE_VALIDATION=true`）：\n")
    add("| 验证器 | 说明 |")
    add("| --- | --- |")
    for name, desc in validators.describe().items():
        add(f"| `{name}` | {desc or '—'} |")
    add("")

    add("## 规则语法说明\n")
    add("规则以 YAML 描述，单条规则字段如下：\n")
    add("| 字段 | 必填 | 说明 |")
    add("| --- | --- | --- |")
    add("| `id` | 是 | 规则唯一标识 |")
    add("| `name` | 是 | 人类可读的凭据名称 |")
    add("| `kind` | 是 | 凭据类型（用于类型统计） |")
    add("| `severity` | 是 | 风险等级：critical/high/medium/low |")
    add("| `pattern` | 是 | Python 正则 |")
    add("| `secret_group` | 否 | 指定哪个捕获组才是密钥本身（连接串类必填，否则会把用户名当凭据） |")
    add("| `require_keywords` | 否 | 关键词必须邻近共现，用于压制泛化规则的误报 |")
    add("| `validator` | 否 | 关联的只读活性验证器 |")
    add("| `multiline` | 否 | 按行匹配（`^`/`$`） |")
    add("| `keywords` | 否 | 检索关键词，供渠道查询构造使用 |")
    add("| `description` | 否 | 风险说明 |")
    add("")

    path = DOCS / "支持的凭据类型列表.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def main() -> None:
    for path in (generate_sources_doc(), generate_rules_doc()):
        print(f"已生成 {path.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
