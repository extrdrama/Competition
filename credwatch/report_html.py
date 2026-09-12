"""自包含 HTML 报告（零依赖，可直接在浏览器打印为 PDF）。

为什么需要它：

1. Markdown 报告适合仓库与 diff，但**不适合给评委看**——没有视觉层次，
   数字不直观；
2. 官方要求提交**单个 PDF**。本模块生成的 HTML 是自包含的
   （内联 CSS，无外部资源、无 JavaScript），在浏览器里打开后
   `Ctrl+P → 另存为 PDF` 即可得到排版良好的提交文档，
   不需要安装 pandoc / LaTeX / 任何工具；
3. 所有图表用纯 CSS 实现，不依赖 Chart.js 等外部库，离线可用。

设计原则：浅色主题、清晰层级、每个数字都能在 Markdown 报告里找到对应来源。
"""

from __future__ import annotations

import html
from datetime import datetime
from typing import Any

from .detectors import RuleEngine
from .models import SEVERITY_ORDER

SEV_LABEL = {"critical": "严重", "high": "高", "medium": "中", "low": "低", "info": "提示"}
SEV_COLOR = {
    "critical": "#c0392b", "high": "#e67e22", "medium": "#f1c40f",
    "low": "#3498db", "info": "#95a5a6",
}

_CSS = """
:root { --ink:#1f2933; --muted:#6b7785; --line:#e3e8ee; --brand:#0b5fff; --bg:#f7f9fb; }
* { box-sizing: border-box; }
body { font-family:"Microsoft YaHei","PingFang SC","Segoe UI",sans-serif;
       color:var(--ink); margin:0; background:var(--bg); font-size:14px; line-height:1.6; }
.page { max-width: 1080px; margin: 0 auto; padding: 28px 32px 60px; background:#fff; }
h1 { font-size: 26px; margin: 0 0 4px; }
h2 { font-size: 19px; margin: 34px 0 12px; padding-bottom:6px; border-bottom:2px solid var(--brand); }
h3 { font-size: 15px; margin: 20px 0 8px; }
.sub { color: var(--muted); font-size: 13px; }
.cards { display:flex; flex-wrap:wrap; gap:12px; margin:18px 0; }
.card { flex:1 1 130px; background:var(--bg); border:1px solid var(--line);
        border-radius:10px; padding:14px 16px; }
.card .num { font-size:26px; font-weight:700; color:var(--brand); }
.card .lbl { font-size:12px; color:var(--muted); margin-top:2px; }
table { width:100%; border-collapse:collapse; margin:10px 0 16px; font-size:13px; }
th, td { border:1px solid var(--line); padding:7px 9px; text-align:left; vertical-align:top; }
th { background:#eef3f9; font-weight:600; }
tr:nth-child(even) td { background:#fbfcfe; }
code { background:#f0f3f7; padding:1px 5px; border-radius:4px; font-size:12px; }
.badge { display:inline-block; padding:1px 8px; border-radius:10px;
         color:#fff; font-size:12px; white-space:nowrap; }
.bar-row { display:flex; align-items:center; gap:10px; margin:5px 0; }
.bar-lbl { width:180px; font-size:13px; text-align:right; color:var(--muted); }
.bar-track { flex:1; background:#eef1f5; border-radius:6px; height:20px; overflow:hidden; }
.bar-fill { height:100%; border-radius:6px; background:var(--brand); }
.bar-val { width:70px; font-size:13px; font-weight:600; }
.funnel { margin:12px 0; }
.note { background:#fff8e6; border-left:4px solid #f1c40f; padding:10px 14px;
        border-radius:0 8px 8px 0; margin:12px 0; font-size:13px; }
.ok { background:#eef9f0; border-left:4px solid #27ae60; }
.warn { background:#fff4f2; border-left:4px solid #c0392b; }
ul { margin:6px 0 6px 18px; padding:0; }
li { margin:3px 0; }
.footer { margin-top:40px; padding-top:14px; border-top:1px solid var(--line);
          color:var(--muted); font-size:12px; }
@media print { body { background:#fff; } .page { padding:0; } h2 { page-break-after:avoid; } }
"""


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _bar(label: str, value: float, max_value: float, color: str = "#0b5fff") -> str:
    pct = (value / max_value * 100) if max_value else 0
    return (
        f'<div class="bar-row"><div class="bar-lbl">{_esc(label)}</div>'
        f'<div class="bar-track"><div class="bar-fill" style="width:{pct:.1f}%;'
        f'background:{color}"></div></div>'
        f'<div class="bar-val">{value:g}</div></div>'
    )


def _bars(items: list[tuple[str, float]], color: str = "#0b5fff") -> str:
    if not items:
        return '<p class="sub">无数据</p>'
    top = max(v for _, v in items) or 1
    return "".join(_bar(k, v, top, color) for k, v in items)


def _badge(severity: str) -> str:
    return (
        f'<span class="badge" style="background:{SEV_COLOR.get(severity, "#95a5a6")}">'
        f'{_esc(SEV_LABEL.get(severity, severity))}</span>'
    )


def render_html(result: Any, rule_engine: RuleEngine) -> str:
    """渲染自包含 HTML 报告。"""
    stats = result.stats
    cred = result.credential_stats or {}
    pairs = list(getattr(getattr(result, "correlation", None), "pairs", []) or [])
    clusters = result.clusters or []
    mttd = result.mttd or {}
    rule_stats = rule_engine.stats()

    funnel = sorted((stats.stage_counts or {}).items())
    severity_items = sorted(
        ((SEV_LABEL.get(k, k), v) for k, v in (cred.get("by_severity") or {}).items()),
        key=lambda kv: -kv[1],
    )
    source_items = list((cred.get("by_source") or {}).items())[:12]
    kind_items = list((cred.get("by_kind") or {}).items())[:10]

    # ---------------- 头部 KPI ----------------
    kpis = [
        ("扫描文档", stats.documents_scanned),
        ("唯一凭据", cred.get("unique_credentials", 0)),
        ("暴露位置", cred.get("total_exposures", 0)),
        ("凭据对", len(pairs)),
        ("跨渠道扩散", cred.get("multi_channel", 0)),
        ("活性验证通过", cred.get("validated", 0)),
        ("扫描耗时", f"{stats.elapsed_seconds():.1f}s"),
    ]
    kpi_html = "".join(
        f'<div class="card"><div class="num">{_esc(v)}</div><div class="lbl">{_esc(k)}</div></div>'
        for k, v in kpis
    )

    # ---------------- 组合风险 ----------------
    pair_rows = ""
    for idx, pair in enumerate(pairs[:15], 1):
        values = " + ".join(_esc(v) for v in pair.masked_values[:4])
        pair_rows += (
            f"<tr><td>{idx}</td><td>{_badge(pair.severity)}</td>"
            f"<td>{_esc(pair.label)}</td><td>{_esc(pair.scope)}</td>"
            f"<td><code>{_esc(pair.location[-52:])}</code></td>"
            f"<td>{values}</td><td>{pair.confidence}</td></tr>"
        )

    # ---------------- Top 发现 ----------------
    top_rows = ""
    for cluster in clusters[:20]:
        attr = result.attributions.get(cluster.fingerprint)
        context = getattr(cluster, "context", None) or {}
        ctx_html = (
            f'<div class="sub">{_esc(context.get("summary", ""))}</div>'
            if context.get("fields") else ""
        )
        pairs_flag = "是" if getattr(cluster, "pairs", None) else "—"
        validated = {True: "✅", False: "❌"}.get(cluster.validated, "—")
        top_rows += (
            f"<tr><td><code>{_esc(cluster.masked)}</code>{ctx_html}</td>"
            f"<td>{_esc(cluster.rule_name)}</td>"
            f"<td>{_badge(cluster.severity)}</td>"
            f"<td>{cluster.confidence:.2f}</td>"
            f"<td>{validated}</td><td>{pairs_flag}</td>"
            f"<td>{cluster.exposure_count}</td>"
            f"<td>{_esc(attr.display if attr else '-')}</td></tr>"
        )

    # ---------------- MTTD ----------------
    if mttd.get("samples"):
        mttd_html = (
            f"<p>MTTD（Mean Time To Detect）＝ 从凭据首次公开到被本平台发现的延迟。</p>"
            f"<table><tr><th>指标</th><th>小时</th></tr>"
            f"<tr><td>样本量</td><td>{mttd['samples']}</td></tr>"
            f"<tr><td><b>中位延迟</b></td><td><b>{mttd['median_hours']}</b></td></tr>"
            f"<tr><td>平均延迟</td><td>{mttd['mean_hours']}</td></tr>"
            f"<tr><td>最短 / 最长</td><td>{mttd['min_hours']} / {mttd['max_hours']}</td></tr></table>"
        )
    else:
        mttd_html = '<p class="sub">本轮未采集到足够的发布时间数据。</p>'

    # ---------------- 渠道 ----------------
    source_rows = "".join(
        f"<tr><td><code>{_esc(p.name)}</code></td><td>{p.documents}</td>"
        f"<td>{p.findings}</td><td>{p.duration_seconds:.1f}s</td>"
        f"<td>{_esc('正常' if not p.error else p.error[:60])}</td></tr>"
        for p in result.sources
    ) or '<tr><td colspan="5" class="sub">无</td></tr>'

    # ---------------- 凭据大类 ----------------
    category_rows = "".join(
        f"<tr><td>{_esc(label)}</td><td>{count}</td></tr>"
        for label, count in rule_stats["categories"].items()
    )

    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>凭迹 CredWatch 扫描报告</title><style>{_CSS}</style></head>
<body><div class="page">

<h1>凭迹 CredWatch 扫描报告</h1>
<div class="sub">云上凭据泄露自动化检测平台 · 报告生成 {now} · 扫描记录 #{_esc(result.scan_id)}</div>

<h2>一、执行概览</h2>
<div class="cards">{kpi_html}</div>

<h2>二、四层收敛漏斗</h2>
<div class="funnel">{_bars([(k, v) for k, v in funnel])}</div>
<div class="note ok">收敛漏斗展示每一层过滤掉的噪声量：第 1 层为格式命中（含占位符与示例值），
第 2 层为通过可解释概率评分的高置信度候选，第 3 层为指纹去重后的真实凭据，
第 4 层为活性验证通过数，第 5 层为凭据对，第 6 层为已提取结构化上下文的数量。</div>

<h2>三、风险与类型分布</h2>
<h3>按风险等级</h3>{_bars(severity_items, "#e67e22")}
<h3>按命中渠道</h3>{_bars(source_items)}
<h3>按凭据类型（Top 10）</h3>{_bars(kind_items, "#27ae60")}

<h2>四、时效性指标（MTTD）</h2>
{mttd_html}

<h2>五、组合风险：凭据对关联</h2>
<p class="sub">单独一条凭据往往无法利用；成对出现、可拼出完整凭据的组合需要最高优先级处置。</p>
<table><tr><th>#</th><th>风险</th><th>凭据对类型</th><th>范围</th><th>位置</th><th>涉及凭据</th><th>可信度</th></tr>
{pair_rows or '<tr><td colspan="7" class="sub">本轮未识别出凭据对</td></tr>'}</table>

<h2>六、高优先级发现（凭据已脱敏）</h2>
<table><tr><th>掩码值</th><th>类型</th><th>风险</th><th>概率</th><th>验活</th><th>成对</th><th>暴露</th><th>归属主体</th></tr>
{top_rows or '<tr><td colspan="8" class="sub">本轮未发现高置信度凭据泄露</td></tr>'}</table>

<h2>七、渠道执行情况</h2>
<table><tr><th>渠道</th><th>文档数</th><th>命中数</th><th>耗时</th><th>状态</th></tr>{source_rows}</table>

<h2>八、检测能力覆盖</h2>
<p>已加载检测规则 <b>{rule_stats['total_rules']}</b> 条 ·
凭据大类 <b>{len(rule_stats['categories'])}</b> 类 ·
凭据类型 <b>{len(rule_stats['kinds'])}</b> 种 ·
只读验证器 <b>{len(rule_stats['validators'])}</b> 个</p>
<table><tr><th>凭据大类</th><th>规则数</th></tr>{category_rows}</table>

<h2>九、合规声明</h2>
<div class="note">
<ul>
<li>报告中的凭据值均为<b>掩码形式</b>，平台不存储、不输出任何明文凭据；</li>
<li>全部检测对象均为<b>公开可访问</b>内容，未进行任何登录绕过或越权访问；</li>
<li>活性验证仅在显式开启时执行，且只调用目标平台的<b>只读身份查询接口</b>；</li>
<li>本平台不对泄露凭据进行任何形式的利用、横向移动或数据导出；</li>
<li>建议按披露建议通过正规渠道通知责任主体，并同步平台方删除内容。</li>
</ul>
</div>

<div class="footer">凭迹 CredWatch · 防御性安全研究工具 · 本报告由系统自动生成，可直接在浏览器中打印为 PDF（Ctrl+P）</div>
</div></body></html>"""


def write_html(result: Any, rule_engine: RuleEngine, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(result, rule_engine), encoding="utf-8")
    return path


__all__ = ["render_html", "write_html"]
