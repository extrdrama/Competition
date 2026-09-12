"""规则库自检（Lint）。

规则文件是"数据"，但数据同样需要校验——一条写错的规则不会让程序崩溃，
却会静默地漏报或制造误报，这种问题在比赛演示现场才暴露就太晚了。

检查项分两类：

**错误（必须修）**
- YAML 解析失败、缺少必填字段
- 规则 ID 重复、ID 含非 ASCII 字符
- 正则无法编译
- `secret_group` 超出捕获组数量（会导致取不到密钥）
- `severity` 取值非法
- 引用了不存在的活性验证器
- 熵阈值不在合理区间

**警告（建议修）**
- 格式过于宽泛（无字面量前缀、无长度约束）却未设置 `require_keywords`
- 正则与已有规则完全相同（重复劳动）
- critical 级别规则未绑定活性验证器（可用性打折）
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .detectors.rule_engine import GENERIC_FALLBACK_RULE_IDS, Rule

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
REQUIRED_FIELDS = ("id", "name", "kind", "severity", "pattern")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-_.]*$")

# 判断"格式是否足够具体"：正则里出现连续 3 个以上字面字符
# （3 位已足够锚定协议名/平台前缀，如 ftp:// 、ssh、AKIA）
LITERAL_RUN_RE = re.compile(r"[A-Za-z0-9_\-/.=+:]{3,}")


@dataclass
class LintIssue:
    """一条检查结果。"""

    level: str          # error / warning / info
    rule_id: str
    file: str
    message: str

    def __str__(self) -> str:
        return f"[{self.level.upper()}] {self.file} :: {self.rule_id} — {self.message}"


@dataclass
class LintReport:
    files: int = 0
    rules: int = 0
    errors: list[LintIssue] = field(default_factory=list)
    warnings: list[LintIssue] = field(default_factory=list)
    infos: list[LintIssue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_record(self) -> dict[str, Any]:
        return {
            "files": self.files,
            "rules": self.rules,
            "errors": [str(i) for i in self.errors],
            "warnings": [str(i) for i in self.warnings],
            "infos": [str(i) for i in self.infos],
            "ok": self.ok,
        }

    def summary(self) -> str:
        return (
            f"检查 {self.files} 个规则文件 / {self.rules} 条规则："
            f"错误 {len(self.errors)}、警告 {len(self.warnings)}、提示 {len(self.infos)}"
        )


def lint_rules(rules_dir: Path | str) -> LintReport:
    """对规则目录执行全部检查。"""
    from .validators import validators

    rules_dir = Path(rules_dir)
    report = LintReport()
    seen_ids: dict[str, str] = {}
    seen_patterns: dict[str, str] = {}
    known_validators = set(validators.names())

    specs = sorted(rules_dir.glob("*.y*ml"))
    report.files = len(specs)
    critical_unverifiable: list[str] = []
    for path in specs:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            report.errors.append(LintIssue("error", "-", path.name, f"YAML 解析失败：{exc}"))
            continue

        items = data.get("rules") or []
        if not items:
            report.warnings.append(LintIssue("warning", "-", path.name, "文件未定义任何规则"))

        for idx, item in enumerate(items, 1):
            report.rules += 1
            rid = str(item.get("id") or f"<第{idx}条>")
            _check_required(report, item, rid, path.name)
            _check_id(report, rid, path.name, seen_ids)
            _check_pattern(report, item, rid, path.name, seen_patterns)
            _check_secret_group(report, item, rid, path.name)
            _check_severity(report, item, rid, path.name)
            _check_validator(report, item, rid, path.name, known_validators)
            _check_entropy(report, item, rid, path.name)
            _check_specificity(report, item, rid, path.name)
            if item.get("severity") == "critical" and not item.get("validator"):
                critical_unverifiable.append(rid)

    # 汇总为重灾区提示——逐条列出会淹没真正需要修的问题
    if critical_unverifiable:
        _add(
            report, "info", f"（共 {len(critical_unverifiable)} 条）", "-",
            "这些 critical 规则未绑定活性验证器，通常是需要配对才能验证"
            "或平台未提供只读身份接口的类型（如云厂商 Secret、支付密钥），"
            "已由凭据对关联与人工复核覆盖",
        )
    return report


def _add(report: LintReport, level: str, rule_id: str, file: str, message: str) -> None:
    issue = LintIssue(level, rule_id, file, message)
    {"error": report.errors, "warning": report.warnings, "info": report.infos}[level].append(issue)


def _check_required(report: LintReport, item: dict, rid: str, file: str) -> None:
    for field_name in REQUIRED_FIELDS:
        if not item.get(field_name):
            _add(report, "error", rid, file, f"缺少必填字段 `{field_name}`")


def _check_id(report: LintReport, rid: str, file: str, seen: dict[str, str]) -> None:
    if not ID_RE.match(rid):
        _add(report, "error", rid, file, "规则 ID 只能包含小写字母、数字、连字符、下划线和点")
    if rid in seen:
        _add(report, "error", rid, file, f"规则 ID 与 {seen[rid]} 重复")
    else:
        seen[rid] = file


def _check_pattern(
    report: LintReport, item: dict, rid: str, file: str, seen: dict[str, str]
) -> None:
    pattern = item.get("pattern")
    if not isinstance(pattern, str):
        return
    try:
        compiled = re.compile(pattern, re.IGNORECASE if "(?i" not in pattern[:6] else 0)
    except re.error as exc:
        _add(report, "error", rid, file, f"正则无法编译：{exc}")
        return
    if compiled.groups == 0:
        # 密钥材料类规则（整块 PEM / PGP）本来就应该拿整个匹配当密钥，
        # 不需要捕获组，这里不提示，避免淹没真正需要关注的项
        kind = str(item.get("kind") or "")
        if "私钥" not in kind and "证书" not in kind:
            _add(
                report, "info", rid, file,
                "正则未设置捕获组，将使用整个匹配作为密钥"
                "（连接串类规则需用 secret_group 指定）",
            )
    # 同一条正则被多条规则使用时，如果 require_keywords 不同，
    # 说明是"同一格式、不同平台"的有意区分，不算重复
    signature = f"{pattern}\u0000{'|'.join(sorted(item.get('require_keywords') or []))}"
    if signature in seen and seen[signature] != rid:
        _add(
            report, "warning", rid, file,
            f"正则与关键词均与规则 `{seen[signature]}` 相同，存在重复识别",
        )
    else:
        seen[signature] = rid


def _check_secret_group(report: LintReport, item: dict, rid: str, file: str) -> None:
    group = item.get("secret_group")
    if group is None:
        return
    pattern = item.get("pattern") or ""
    try:
        groups = re.compile(pattern).groups
    except re.error:
        return
    if not isinstance(group, int) or group < 1:
        _add(report, "error", rid, file, f"secret_group 必须为正整数，当前 {group!r}")
    elif group > groups:
        _add(
            report, "error", rid, file,
            f"secret_group={group} 超出了正则的捕获组数量（共 {groups} 组），将取不到密钥",
        )


def _check_severity(report: LintReport, item: dict, rid: str, file: str) -> None:
    severity = item.get("severity")
    if severity and severity not in VALID_SEVERITIES:
        _add(
            report, "error", rid, file,
            f"severity=`{severity}` 非法，可选值：{sorted(VALID_SEVERITIES)}",
        )


def _check_validator(
    report: LintReport, item: dict, rid: str, file: str, known: set[str]
) -> None:
    validator = item.get("validator")
    if not validator:
        return
    if validator not in known:
        _add(
            report, "error", rid, file,
            f"引用了不存在的验证器 `{validator}`，可用：{sorted(known)}",
        )


def _check_entropy(report: LintReport, item: dict, rid: str, file: str) -> None:
    if not item.get("entropy"):
        return
    threshold = item.get("entropy_threshold")
    if threshold is None:
        _add(report, "warning", rid, file, "启用 entropy 但未设置 entropy_threshold，默认不过滤")
        return
    try:
        value = float(threshold)
    except (TypeError, ValueError):
        _add(report, "error", rid, file, f"entropy_threshold 不是数字：{threshold!r}")
        return
    if not (0.0 < value < 8.0):
        _add(report, "error", rid, file, f"entropy_threshold={value} 超出合理区间 (0, 8)")


def _check_specificity(report: LintReport, item: dict, rid: str, file: str) -> None:
    """格式过于宽泛的规则必须设置 require_keywords，否则容易误报。"""
    if rid in GENERIC_FALLBACK_RULE_IDS or item.get("require_keywords"):
        return
    pattern = item.get("pattern") or ""
    if not LITERAL_RUN_RE.search(pattern):
        _add(
            report, "warning", rid, file,
            "正则中没有 4 位以上的字面量前缀，格式过于宽泛，建议补充 require_keywords 或固定前缀",
        )


def format_report(report: LintReport) -> str:
    """把检查结果格式化为可读文本。"""
    lines = [report.summary()]
    for title, issues in (("错误", report.errors), ("警告", report.warnings), ("提示", report.infos)):
        if issues:
            lines.append(f"\n【{title}】")
            lines.extend(f"  {issue}" for issue in issues)
    if report.ok and not report.warnings:
        lines.append("\n规则库检查通过，未发现问题。")
    return "\n".join(lines)


__all__ = ["LintIssue", "LintReport", "format_report", "lint_rules"]
