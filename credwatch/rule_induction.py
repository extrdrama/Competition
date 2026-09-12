"""规则自动归纳。

规则的敌人是**格式变化**。新平台上线、老平台改 token 格式，手写规则永远
追不上。本模块解决"从样本到规则"这一步：

    一批确认的泄露样本 ──▶ 归纳出候选 YAML 规则 ──▶ 冲突检测 ──▶ 人工审核入库

为什么"候选"而非"直接生效"：归纳是启发式的，可能过拟合少数样本。
它负责把"写规则"从完全手工变成"机器起草 + 人工审核"，而不是替人做决定。
这种克制本身也是防御性工具的伦理要求——误报会影响应急响应信任。

归纳依据（均可解释、可复核）：
- 公共前缀（如 `sk-`、`ghp_`、`LTAI`）
- 长度区间（min–max，样本足够时收紧到固定长度）
- 字符集（全大写+数字 / 字母数字 / 含符号）
- 熵区间（信息量下限，剔除纯数字串）
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .detectors.entropy import shannon_entropy

# 字符集 → 正则字符类
CHARSET_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"^[A-Z0-9]+$"), "[A-Z0-9]", "大写字母与数字"),
    (re.compile(r"^[a-z0-9]+$"), "[a-z0-9]", "小写字母与数字"),
    (re.compile(r"^[A-Za-z0-9]+$"), "[A-Za-z0-9]", "字母与数字"),
    (re.compile(r"^[a-f0-9]+$"), "[a-f0-9]", "十六进制小写"),
    (re.compile(r"^[A-F0-9]+$"), "[A-F0-9]", "十六进制大写"),
    (re.compile(r"^[A-Za-z0-9_\-]+$"), "[A-Za-z0-9_\\-]", "字母数字与连字符"),
    (re.compile(r"^[A-Za-z0-9_\-./+=]+$"), "[A-Za-z0-9_\\-./+=]", "Base64 类字符"),
    (re.compile(r"^[A-Za-z0-9_\-]+$"), "[A-Za-z0-9_\\-]", "字母数字与下划线"),
)


@dataclass
class RuleDraft:
    """归纳出的候选规则。"""

    rule_id: str
    name: str
    kind: str
    severity: str
    pattern: str
    sample_count: int
    prefix: str
    min_length: int
    max_length: int
    charset_label: str
    entropy_min: float
    entropy_max: float
    # 归纳质量信号，帮助人工判断是否值得采用
    quality_note: str = ""
    # 与已有规则的冲突检测结果
    conflicts: list[str] = field(default_factory=list)

    def to_yaml(self) -> str:
        lines = [
            f"  - id: {self.rule_id}",
            f"    name: {self.name}",
            f"    kind: {self.kind}",
            f"    severity: {self.severity}",
            f"    pattern: '{self.pattern}'",
            f"    keywords: [{self.prefix}]",
            f"    description: （由规则归纳自动生成，样本 {self.sample_count} 条；"
            f"前缀 {self.prefix or '无'}，长度 {self.min_length}-{self.max_length}，"
            f"字符集 {self.charset_label}，熵 {self.entropy_min:.1f}-{self.entropy_max:.1f}）",
        ]
        return "\n".join(lines)

    def to_record(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "kind": self.kind,
            "severity": self.severity,
            "pattern": self.pattern,
            "sample_count": self.sample_count,
            "prefix": self.prefix,
            "min_length": self.min_length,
            "max_length": self.max_length,
            "charset_label": self.charset_label,
            "entropy_min": round(self.entropy_min, 3),
            "entropy_max": round(self.entropy_max, 3),
            "quality_note": self.quality_note,
            "conflicts": self.conflicts,
        }


def _common_prefix(values: list[str]) -> str:
    if not values:
        return ""
    prefix = values[0]
    for value in values[1:]:
        i = 0
        while i < len(prefix) and i < len(value) and prefix[i] == value[i]:
            i += 1
        prefix = prefix[:i]
        if not prefix:
            break
    return prefix


def _charset_class(values: list[str]) -> tuple[str, str]:
    """判断样本共有的字符集，返回 (正则字符类, 中文描述)。"""
    for pattern, cls, label in CHARSET_PATTERNS:
        if all(pattern.match(v) for v in values):
            return cls, label
    # 兜底：任意可打印字符（但归纳质量会降级）
    return r"[\x20-\x7e]", "任意可打印字符"


def _build_pattern(prefix: str, charset: str, min_len: int, max_len: int) -> str:
    """由前缀 + 字符集 + 长度区间拼出正则。"""
    prefix_escaped = re.escape(prefix)
    body = (
        f"{charset}{{{min_len},{max_len}}}"
        if min_len != max_len
        else f"{charset}{{{min_len}}}"
    )
    if prefix:
        # 前缀后紧跟"主体"；主体长度 = 总长度 - 前缀长度
        body_len = max_len - len(prefix)
        body_min = max(min_len - len(prefix), 0)
        body_max = max(max_len - len(prefix), body_min)
        if body_min == body_max and body_min > 0:
            body = f"{charset}{{{body_min}}}"
        elif body_max > 0:
            body = f"{charset}{{{body_min},{body_max}}}"
        return f"(?<![A-Za-z0-9])({prefix_escaped}{body})(?![A-Za-z0-9])"
    return f"(?<![A-Za-z0-9])({body})(?![A-Za-z0-9])"


def induce_rule(
    rule_id: str,
    name: str,
    samples: list[str],
    *,
    kind: str = "自动归纳",
    severity: str = "high",
    min_prefix_len: int = 3,
) -> RuleDraft:
    """从一批样本归纳一条候选规则。"""
    values = [s.strip() for s in samples if s and s.strip()]
    if not values:
        raise ValueError("样本为空")

    lengths = [len(v) for v in values]
    prefix = _common_prefix(values)
    # 前缀太短没有锚定价值，视为无前缀
    effective_prefix = prefix if len(prefix) >= min_prefix_len else ""
    charset, charset_label = _charset_class(values)
    entropies = [shannon_entropy(v) for v in values]
    min_len, max_len = min(lengths), max(lengths)

    pattern = _build_pattern(effective_prefix, charset, min_len, max_len)

    quality = _quality_note(
        len(values), effective_prefix, min_len, max_len, entropies, charset_label
    )

    return RuleDraft(
        rule_id=rule_id,
        name=name,
        kind=kind,
        severity=severity,
        pattern=pattern,
        sample_count=len(values),
        prefix=effective_prefix,
        min_length=min_len,
        max_length=max_len,
        charset_label=charset_label,
        entropy_min=min(entropies),
        entropy_max=max(entropies),
        quality_note=quality,
    )


def _quality_note(
    sample_count: int,
    prefix: str,
    min_len: int,
    max_len: int,
    entropies: list[float],
    charset_label: str,
) -> str:
    notes: list[str] = []
    if sample_count < 5:
        notes.append("样本偏少，长度区间可能偏宽，建议补充样本")
    if not prefix:
        notes.append("无公共前缀，仅靠长度与字符集匹配，误报风险较高")
    if min_len == max_len:
        notes.append("长度完全一致，格式稳定")
    elif max_len - min_len > 16:
        notes.append("长度跨度较大，建议补充样本收紧区间")
    if min(entropies) < 3.0:
        notes.append("熵值偏低，需警惕匹配到普通单词")
    if charset_label == "任意可打印字符":
        notes.append("字符集过于宽泛，建议人工补充前缀约束")
    return "；".join(notes) if notes else "归纳质量良好"


def detect_conflicts(draft: RuleDraft, existing_patterns: dict[str, str]) -> list[str]:
    """检测候选规则与已有规则是否命中同一批样本。"""
    try:
        compiled = re.compile(draft.pattern, re.IGNORECASE if "(?i" not in draft.pattern[:6] else 0)
    except re.error:
        return ["候选正则无法编译，请检查归纳结果"]

    conflicts: list[str] = []
    # 与已有规则的 pattern 做字面相似度判断（近似冲突检测，不追求精确等价）
    for rid, pattern in existing_patterns.items():
        if pattern == draft.pattern:
            conflicts.append(f"与规则 `{rid}` 的正则完全相同")
        elif _pattern_overlap(draft.pattern, pattern):
            conflicts.append(f"与规则 `{rid}` 的正则高度相似，可能重复识别")
    return conflicts


def _pattern_overlap(a: str, b: str) -> bool:
    """粗略判断两个正则是否覆盖同类样本（比较字面量锚点）。"""
    import difflib

    ratio = difflib.SequenceMatcher(None, a, b).ratio()
    # 去掉字符类差异后仍高度相似
    norm_a = re.sub(r"\[[^\]]*\]", "X", a)
    norm_b = re.sub(r"\[[^\]]*\]", "X", b)
    ratio2 = difflib.SequenceMatcher(None, norm_a, norm_b).ratio()
    return ratio > 0.92 or ratio2 > 0.88


def induce_from_file(path: Path | str) -> list[RuleDraft]:
    """从样本文件归纳规则。文件每行一个样本，`#` 开头为注释。"""
    samples: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        samples.append(line)
    stem = Path(path).stem
    draft = induce_rule(
        f"induced-{stem}",
        f"自动归纳（{stem}）",
        samples,
        kind="自动归纳凭据",
        severity="high",
    )
    return [draft]


def render_draft_yaml(drafts: Iterable[RuleDraft]) -> str:
    lines = ["# ============================================================",
             "# 规则自动归纳候选（需人工审核后合并到正式规则文件）",
             "# 生成方式：python -m credwatch induce-rule --from <样本文件>",
             "# ============================================================",
             "category: induced",
             "label: 自动归纳候选",
             "rules:"]
    for draft in drafts:
        lines.append(draft.to_yaml())
    return "\n".join(lines) + "\n"


__all__ = [
    "RuleDraft",
    "detect_conflicts",
    "induce_from_file",
    "induce_rule",
    "render_draft_yaml",
]
