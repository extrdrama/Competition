"""可视化看板（Streamlit）。

启动： python -m credwatch serve
或：   streamlit run credwatch/dashboard.py

看板重点展示三块内容，对应赛题关注的核心能力：
1. 时效性（MTTD）：凭据从公开到被发现的延迟分布；
2. 收敛质量：四层过滤各自的通过量，证明误报控制能力；
3. 风险全景：跨渠道扩散凭据、待处置清单与归属主体。
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = PROJECT_ROOT / "data" / "credwatch.db"

SEVERITY_LABEL = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "提示",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@st.cache_data(ttl=15)
def load_data(db_path: str) -> dict:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        credentials = [dict(r) for r in conn.execute("SELECT * FROM credentials").fetchall()]
        exposures = [dict(r) for r in conn.execute("SELECT * FROM exposures").fetchall()]
        attributions = {
            r["fingerprint"]: dict(r) for r in conn.execute("SELECT * FROM attributions")
        }
        scans = [dict(r) for r in conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 50")]
    finally:
        conn.close()
    return {
        "credentials": credentials,
        "exposures": exposures,
        "attributions": attributions,
        "scans": scans,
    }


def compute(data: dict) -> dict:
    creds = data["credentials"]
    exposures = data["exposures"]
    by_severity: dict[str, int] = {}
    by_source: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    mttd_values: list[float] = []

    for cred in creds:
        sev = cred.get("severity") or "medium"
        by_severity[sev] = by_severity.get(sev, 0) + 1
        kind = cred.get("kind") or "未分类"
        by_kind[kind] = by_kind.get(kind, 0) + 1
        try:
            sources = json.loads(cred.get("sources_json") or "[]")
        except (ValueError, TypeError):
            sources = []
        for source in sources:
            by_source[source] = by_source.get(source, 0) + 1

        published, seen = cred.get("first_published"), cred.get("first_seen")
        if published and seen:
            from datetime import datetime

            try:
                delta = datetime.fromisoformat(seen) - datetime.fromisoformat(published)
                mttd_values.append(max(delta.total_seconds() / 3600.0, 0.0))
            except ValueError:
                pass

    mttd_values.sort()
    return {
        "unique": len(creds),
        "exposures": len(exposures),
        "validated": sum(1 for c in creds if c.get("validated") == 1),
        "multi_channel": sum(1 for c in creds if c.get("multi_channel")),
        "by_severity": by_severity,
        "by_source": by_source,
        "by_kind": by_kind,
        "mttd": mttd_values,
    }


def main() -> None:
    st.set_page_config(page_title="凭迹 CredWatch 控制台", layout="wide")
    st.title("凭迹 CredWatch · 云上凭据泄露监测控制台")
    st.caption("防御性安全研究工具 · 所有凭据仅以掩码与指纹展示")

    db_path = st.sidebar.text_input("数据库路径", str(DEFAULT_DB))
    if not Path(db_path).exists():
        st.warning(f"数据库不存在：{db_path}\n\n请先执行 `python -m credwatch demo` 或 `scan`。")
        return

    data = load_data(db_path)
    stats = compute(data)

    if not stats["unique"]:
        st.info("数据库中暂无数据，先跑一次扫描吧。")
        return

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("唯一凭据", stats["unique"])
    col2.metric("暴露位置", stats["exposures"])
    col3.metric("跨渠道扩散", stats["multi_channel"])
    col4.metric("活性验证通过", stats["validated"])
    col5.metric(
        "MTTD 中位数",
        f"{stats['mttd'][len(stats['mttd']) // 2]:.2f} h" if stats["mttd"] else "—",
    )

    left, right = st.columns(2)
    with left:
        st.subheader("风险等级分布")
        ordered = sorted(stats["by_severity"].items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))
        st.bar_chart(
            {"数量": {SEVERITY_LABEL.get(k, k): v for k, v in ordered}},
            horizontal=True,
            height=260,
        )
    with right:
        st.subheader("渠道命中分布")
        st.bar_chart({"数量": stats["by_source"]}, horizontal=True, height=260)

    st.subheader("凭据类型分布（Top 15）")
    top_kinds = dict(list(sorted(stats["by_kind"].items(), key=lambda kv: -kv[1]))[:15])
    st.bar_chart({"数量": top_kinds}, height=300)

    if stats["mttd"]:
        st.subheader("发现延迟（MTTD）分布")
        st.caption("横轴为延迟区间（小时），纵轴为凭据数量。MTTD 越小说明时效性越好。")
        buckets = [(0, 1), (1, 6), (6, 24), (24, 72), (72, 168), (168, 10**9)]
        labels = ["<1h", "1-6h", "6-24h", "1-3d", "3-7d", ">7d"]
        counts = {label: 0 for label in labels}
        for value in stats["mttd"]:
            for (low, high), label in zip(buckets, labels):
                if low <= value < high:
                    counts[label] += 1
                    break
        st.bar_chart({"凭据数量": counts}, height=260)

    st.subheader("待处置凭据清单")
    severities = st.multiselect(
        "按风险等级筛选",
        list(SEVERITY_LABEL),
        default=[s for s in SEVERITY_LABEL if s in {"critical", "high"}],
        format_func=lambda s: SEVERITY_LABEL.get(s, s),
    )
    show_validated_only = st.checkbox("只看已确认有效的凭据", value=False)

    rows = []
    for cred in sorted(
        data["credentials"],
        key=lambda c: (SEVERITY_ORDER.get(c.get("severity"), 9), -(c.get("confidence") or 0)),
    ):
        if severities and cred.get("severity") not in severities:
            continue
        if show_validated_only and cred.get("validated") != 1:
            continue
        attr = data["attributions"].get(cred["fingerprint"]) or {}
        owner = attr.get("org_name") or attr.get("owner") or "-"
        rows.append(
            {
                "掩码值": cred["masked"],
                "凭据类型": cred.get("kind") or cred.get("rule_name"),
                "风险": SEVERITY_LABEL.get(cred.get("severity"), cred.get("severity")),
                "置信度": cred.get("confidence"),
                "跨渠道": "是" if cred.get("multi_channel") else "否",
                "验活": {1: "有效", 0: "无效"}.get(cred.get("validated"), "未验证"),
                "暴露点": cred.get("exposure_count"),
                "归属主体": owner,
                "披露建议": (attr.get("disclosure_hint") or "")[:60],
            }
        )
    st.dataframe(rows, use_container_width=True, height=420)

    st.subheader("暴露位置明细")
    fp_options = {c["fingerprint"]: f"{c['masked']} · {c.get('rule_name')}" for c in data["credentials"]}
    if fp_options:
        chosen = st.selectbox(
            "选择一条凭据查看全部暴露位置",
            options=list(fp_options),
            format_func=lambda fp: fp_options[fp],
        )
        detail = [e for e in data["exposures"] if e["fingerprint"] == chosen]
        st.dataframe(
            [
                {
                    "渠道": e.get("source"),
                    "位置": e.get("url"),
                    "文件": e.get("path"),
                    "行号": e.get("line"),
                    "命中片段": e.get("snippet"),
                    "首次公开": e.get("published_at"),
                    "发现时间": e.get("discovered_at"),
                }
                for e in detail
            ],
            use_container_width=True,
            height=300,
        )


if __name__ == "__main__":
    main()
