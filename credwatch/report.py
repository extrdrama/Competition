"""报告层：生成扫描报告（Markdown / JSON / CSV）。

报告是赛题四份交付件里最能体现"应用价值"的一份，因此重点做了三件事：
1. **收敛漏斗可视化**：用数字证明四层过滤各自过滤掉了多少噪声；
2. **时效性指标（MTTD）**：把"发现够快"从形容词变成可量化数字；
3. **可执行的处理建议**：每条发现给出归属主体与负责任披露对象，
   而不是只丢一句"发现泄露"。

所有输出均只含掩码与指纹，不含任何明文凭据。
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .detectors import RuleEngine
from .models import SEVERITY_ORDER
from .report_html import write_html

SEVERITY_LABEL = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "提示",
}

SEVERITY_MARK = {
    "critical": "P0",
    "high": "P1",
    "medium": "P2",
    "low": "P3",
    "info": "P4",
}


def render_markdown(result: Any, rule_engine: RuleEngine) -> str:
    """渲染 Markdown 报告。"""
    stats = result.stats
    cred = result.credential_stats or {}
    lines: list[str] = []
    add = lines.append

    add("# 凭迹 CredWatch 扫描报告\n")
    add(f"- 报告生成时间：{datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S')}")
    add(f"- 扫描开始时间：{_fmt(stats.started_at)}")
    add(f"- 扫描结束时间：{_fmt(stats.finished_at)}")
    add(f"- 扫描耗时：{stats.elapsed_seconds():.1f} 秒")
    add(f"- 扫描记录编号：#{result.scan_id}")
    add("")

    # ---------------------------------------------------------------- 概览
    add("## 一、执行概览\n")
    add("| 指标 | 数值 |")
    add("| --- | --- |")
    add(f"| 扫描文档数 | {stats.documents_scanned} |")
    add(f"| 扫描字节数 | {_human_bytes(stats.bytes_scanned)} |")
    add(f"| 去重后唯一凭据 | **{cred.get('unique_credentials', 0)}** |")
    add(f"| 暴露位置总数 | {cred.get('total_exposures', 0)} |")
    add(f"| 跨渠道扩散凭据 | {cred.get('multi_channel', 0)} |")
    ctx_total = sum(1 for c in result.clusters if getattr(c, "context", None) and c.context.get("fields"))
    add(f"| 已提取结构化上下文 | {ctx_total} |")
    add(f"| **组合风险（凭据对）** | **{len(result.correlation.pairs) if result.correlation else 0}** |")
    add(f"| 活性验证通过 | {cred.get('validated', 0)} |")
    add("")

    # ---------------------------------------------------------------- 漏斗
    add("## 二、四层收敛漏斗\n")
    add("| 阶段 | 数量 |")
    add("| --- | --- |")
    for key in sorted(stats.stage_counts):
        add(f"| {key} | {stats.stage_counts[key]} |")
    add("")
    add(
        "> 第 1 层为格式命中（含占位符与示例值），第 2 层为通过可解释概率评分"
        "确认的高置信度候选，第 3 层为按指纹去重后的真实凭据数量，"
        "第 4 层为通过只读活性验证确认仍然可用的凭据，"
        "第 5 层为识别出的可组合利用凭据对数量。\n"
    )

    # ---------------------------------------------------------------- 分布
    add("## 三、风险与类型分布\n")
    if cred.get("by_severity"):
        add("### 风险等级分布\n")
        add("| 等级 | 数量 |")
        add("| --- | --- |")
        for sev in sorted(cred["by_severity"], key=lambda s: -SEVERITY_ORDER.get(s, 0)):
            add(f"| {SEVERITY_LABEL.get(sev, sev)}（{SEVERITY_MARK.get(sev, '')}） | {cred['by_severity'][sev]} |")
        add("")
    if cred.get("by_kind"):
        add("### 凭据类型分布（Top 20）\n")
        add("| 凭据类型 | 数量 |")
        add("| --- | --- |")
        for kind, count in list(cred["by_kind"].items())[:20]:
            add(f"| {kind} | {count} |")
        add("")
    if cred.get("by_source"):
        add("### 渠道命中分布\n")
        add("| 渠道 | 命中的唯一凭据数 |")
        add("| --- | --- |")
        for source, count in cred["by_source"].items():
            add(f"| {source} | {count} |")
        add("")

    # ---------------------------------------------------------------- 时效性
    add("## 四、时效性指标（MTTD）\n")
    mttd = result.mttd or {}
    if mttd.get("samples"):
        add(
            "MTTD（Mean Time To Detect）＝ 从凭据首次在公开渠道出现，到被本平台发现的延迟。\n"
        )
        add("| 指标 | 数值（小时） |")
        add("| --- | --- |")
        add(f"| 样本量 | {mttd['samples']} |")
        add(f"| 最短延迟 | {mttd['min_hours']} |")
        add(f"| **中位延迟** | **{mttd['median_hours']}** |")
        add(f"| 平均延迟 | {mttd['mean_hours']} |")
        add(f"| 最长延迟 | {mttd['max_hours']} |")
        add("")
    else:
        add("本轮扫描未采集到足够的发布时间数据，无法计算 MTTD。")
        add("")

    # ---------------------------------------------------------------- 发现
    add("## 五、高优先级发现\n")
    top = sorted(
        result.clusters,
        key=lambda c: (-SEVERITY_ORDER.get(c.severity, 0), -c.confidence, -c.exposure_count),
    )[:25]
    if not top:
        add("本轮未发现高置信度凭据泄露。")
        add("")
    for idx, cluster in enumerate(top, 1):
        attr = result.attributions.get(cluster.fingerprint)
        add(f"### {idx}. {cluster.rule_name}（{SEVERITY_LABEL.get(cluster.severity, cluster.severity)}）\n")
        add(f"- **凭据指纹**：`{cluster.fingerprint[:16]}…`")
        add(f"- **掩码值**：`{cluster.masked}`")
        add(f"- **凭据类型**：{cluster.kind or cluster.category}")
        add(f"- **检测方式**：{cluster.detector}（置信度 {cluster.confidence}）")
        explanation = _explanation_of(cluster)
        if explanation:
            add(f"- **判定依据**：{explanation}")
        context = getattr(cluster, "context", None) or {}
        if context.get("fields"):
            add(f"- **关联上下文（敏感信息对）**：`{context['summary']}`")
        pairs = _pairs_of(cluster)
        if pairs:
            for pair in pairs:
                add(
                    f"- **组合风险**：与另一条凭据构成「{pair['label']}」"
                    f"（{pair['scope']} 范围），{pair['impact']}"
                )
        if cluster.validated is True:
            add(f"- **活性验证**：✅ {cluster.validation_note}")
        elif cluster.validated is False:
            add(f"- **活性验证**：❌ {cluster.validation_note}")
        else:
            add(f"- **活性验证**：— {cluster.validation_note or '未做验证'}")
        add(f"- **暴露位置**：{cluster.exposure_count} 处 / {cluster.channel_count} 个渠道"
            + ("（**已跨渠道扩散**）" if cluster.multi_channel else ""))
        if cluster.mttd_hours() is not None:
            add(f"- **发现延迟**：{cluster.mttd_hours()} 小时")
        if attr is not None:
            add(f"- **归属主体**：{attr.display}（{attr.org_type or '未识别'}，可信度 {attr.confidence}）")
            add(f"- **披露建议**：{attr.disclosure_hint}")
        add("- **证据位置**：")
        for exposure in cluster.exposures[:5]:
            loc = f"{exposure.get('path') or ''}"
            if exposure.get("line"):
                loc += f":{exposure['line']}"
            add(f"  - `{exposure.get('source')}` {exposure.get('url')} → {loc}")
        if cluster.exposure_count > 5:
            add(f"  - …共 {cluster.exposure_count} 处，完整清单见 CSV 明细")
        add("")

    # ---------------------------------------------------------------- 组合风险
    pairs = list(getattr(result.correlation, "pairs", []) or [])
    add("## 六、组合风险：凭据对关联\n")
    if pairs:
        add(
            "> 单独一条凭据往往**无法利用**：只有 Access Key ID 没有 Secret，"
            "只有 Client ID 没有 Client Secret，只有加密私钥没有口令——都构不成完整凭据。\n"
            "> 真正需要立刻处置的，是**成对出现、可以拼出完整凭据**的情况。"
            "本节列出系统识别出的凭据对（`document` = 同一文件内，`origin` = 同仓库/同工程目录内）。\n"
        )
        add("| # | 风险 | 凭据对类型 | 关联范围 | 位置 | 涉及凭据（已脱敏） | 可信度 |")
        add("| --- | --- | --- | --- | --- | --- | --- |")
        for idx, pair in enumerate(pairs, 1):
            values = " + ".join(f"`{v}`" for v in pair.masked_values[:4])
            add(
                f"| {idx} | {SEVERITY_LABEL.get(pair.severity, pair.severity)} | {pair.label} | "
                f"{pair.scope} | `{_short(pair.location)}` | {values} | {pair.confidence} |"
            )
        add("")
        add("### 组合风险的处置优先级说明\n")
        for pair in pairs[:10]:
            add(f"**{pair.label}**（{pair.scope} 范围，位置 `{_short(pair.location)}`）\n")
            add(f"- 涉及凭据：{' + '.join(f'`{v}`' for v in pair.masked_values)}")
            add(f"- 危害：{pair.impact}")
            add(
                "- 处置：**按最高优先级处理**——该组合可直接被攻击者利用，"
                "应首先吊销并轮换全部成员凭据\n"
            )
    else:
        add("本轮未识别出可组合利用的凭据对。\n")

    # ---------------------------------------------------------------- 渠道
    add("## 七、渠道执行情况\n")
    add("| 渠道 | 文档数 | 命中数 | 耗时(秒) | 状态 |")
    add("| --- | --- | --- | --- | --- |")
    for prog in result.sources:
        status = "正常" if not prog.error else f"失败：{prog.error[:60]}"
        add(
            f"| {prog.name} | {prog.documents} | {prog.findings} | "
            f"{prog.duration_seconds:.1f} | {status} |"
        )
    add("")

    # ---------------------------------------------------------------- 规则库
    rule_stats = rule_engine.stats()
    add("## 八、检测能力覆盖\n")
    add(f"- 已加载检测规则：**{rule_stats['total_rules']}** 条")
    add(f"- 覆盖凭据大类：**{len(rule_stats['categories'])}** 类")
    add(f"- 覆盖凭据类型：**{len(rule_stats['kinds'])}** 种")
    add(f"- 已注册只读验证器：{', '.join(rule_stats['validators']) or '无'}")
    add("")
    add("| 凭据大类 | 规则数 |")
    add("| --- | --- |")
    for label, count in rule_stats["categories"].items():
        add(f"| {label} | {count} |")
    add("")

    # ---------------------------------------------------------------- 修复建议
    add("## 九、处置建议\n")
    add(
        "> 只报告问题不给出方案，等于把工作留给别人。本节按「应急处置 → 根因修复 → "
        "长期加固」三层给出可直接执行的处置步骤，代码片段可直接复制改造。\n"
    )
    from .remediation import RemediationEngine

    engine = RemediationEngine()
    plans = engine.plans_for_clusters(
        sorted(result.clusters, key=lambda c: -SEVERITY_ORDER.get(c.severity, 0)), limit=5
    )
    if plans:
        for idx, plan in enumerate(plans, 1):
            add(f"### {idx}. {plan.subject}（当前风险等级：{SEVERITY_LABEL.get(plan.severity, plan.severity)}）\n")
            for step in plan.steps:
                add(f"- **[{step.phase}] {step.action}**：{step.detail}")
                if step.snippet:
                    add("")
                    add("  ```bash")
                    for line in step.snippet.splitlines():
                        add(f"  {line}")
                    add("  ```")
                if step.reference:
                    add(f"  - 参考：{step.reference}")
            add("")
    else:
        add("本轮无需处置的发现。\n")

    # ---------------------------------------------------------------- 合规
    add("## 十、合规声明\n")
    add(
        "- 本报告中的凭据值均为**掩码形式**，平台不存储、不输出任何明文凭据；\n"
        "- 全部检测对象均为**公开可访问**内容，未进行任何登录绕过或越权访问；\n"
        "- 活性验证仅在显式开启时执行，且只调用目标平台的**只读身份查询接口**；\n"
        "- 本平台不对泄露凭据进行任何形式的利用、横向移动或数据导出；\n"
        "- 建议按报告给出的披露建议，通过正规渠道通知责任主体并同步平台方删除内容。\n"
    )
    return "\n".join(lines)


def render_json(result: Any) -> str:
    return json.dumps(result.to_record(), ensure_ascii=False, indent=2)


def write_csv(result: Any, path: Path) -> None:
    """输出暴露位置明细，供评审逐条核对。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "凭据指纹(前16位)",
                "掩码值",
                "规则名称",
                "凭据类型",
                "风险等级",
                "置信度",
                "是否验活",
                "暴露渠道",
                "暴露位置",
                "行号",
                "命中片段(已脱敏)",
                "首次公开时间",
                "发现时间",
                "发现延迟(小时)",
                "归属主体",
                "组织类型",
            ]
        )
        for cluster in result.clusters:
            attr = result.attributions.get(cluster.fingerprint)
            for exposure in cluster.exposures:
                writer.writerow(
                    [
                        cluster.fingerprint[:16],
                        cluster.masked,
                        cluster.rule_name,
                        cluster.kind or cluster.category,
                        SEVERITY_LABEL.get(cluster.severity, cluster.severity),
                        cluster.confidence,
                        {True: "有效", False: "无效/已吊销"}.get(cluster.validated, "未验证"),
                        exposure.get("source"),
                        exposure.get("url"),
                        exposure.get("line") or "",
                        exposure.get("snippet") or "",
                        exposure.get("published_at") or "",
                        exposure.get("discovered_at") or "",
                        cluster.mttd_hours() if cluster.mttd_hours() is not None else "",
                        attr.display if attr else "",
                        (attr.org_type if attr else "") or "",
                    ]
                )


def write_reports(result: Any, rule_engine: RuleEngine, out_dir: Path) -> dict[str, Path]:
    """写出全部报告文件，返回路径映射。"""
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    paths = {
        "markdown": out_dir / f"credwatch_report_{stamp}.md",
        "json": out_dir / f"credwatch_result_{stamp}.json",
        "csv": out_dir / f"credwatch_exposures_{stamp}.csv",
    }
    paths["markdown"].write_text(render_markdown(result, rule_engine), encoding="utf-8")
    paths["json"].write_text(render_json(result), encoding="utf-8")
    write_csv(result, paths["csv"])
    # HTML 版：自包含、带图表，浏览器打开即可打印为 PDF（提交用）
    write_html(result, rule_engine, out_dir / "latest_report.html")
    paths["html"] = out_dir / "latest_report.html"

    # 同时维护一份"最新报告"便于演示
    (out_dir / "latest_report.md").write_text(
        paths["markdown"].read_text(encoding="utf-8"), encoding="utf-8"
    )
    return paths


def _fmt(value: Any) -> str:
    if isinstance(value, datetime):
        return value.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    return str(value or "-")


def _short(value: str, limit: int = 58) -> str:
    """截断过长位置串，避免撑破 Markdown 表格。"""
    text = str(value or "")
    return text if len(text) <= limit else "…" + text[-limit:]


def _explanation_of(cluster: Any) -> str:
    return str(getattr(cluster, "explanation", "") or "")


def _pairs_of(cluster: Any) -> list[dict]:
    return list(getattr(cluster, "pairs", []) or [])


def _human_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"
