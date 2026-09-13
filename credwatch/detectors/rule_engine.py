"""检测层第 1 环：YAML 规则引擎。

设计取舍：
- 规则以 YAML 描述，运行为 `re` 原生正则，避免引入重型规则引擎依赖。
- 支持 `require_keywords`（关键词必须在命中位置邻近窗口内共现），
  这是把"格式匹配"升级为"语义确认"的关键，可显著压低误报。
- 统一过滤占位符与示例值（`your_key_here` / `<TOKEN>` / `xxxx` / `changeme` 等），
  这是凭据扫描类工具误报的最大来源。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

# 占位符/示例值特征：命中即丢弃，不进入后续评分
PLACEHOLDER_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"^[\*x\-#\.]+$",                      # ***, xxx, ####
        r"^(?:your|my|the|some|test|demo|sample|example|dummy|fake|foo|bar)[_\-]?",
        r"(?:placeholder|redacted|removed|changeme|change_me|todo|fixme|none|null|nil|undefined)",
        r"^(?:abc|abcd|123|1234|123456|password|passwd|secret|token|key|apikey|value|string|input)$",
        r"^[<{\(\[]|[{<\)\]]$",                # <TOKEN> / ${VAR} / [KEY]
        r"^\$\{?[A-Z_][A-Z0-9_]*\}?$",          # ${ENV_VAR} 变量引用
        r"^(?:env|os\.environ|process\.env|System\.getenv)",
        r"(?:%s|%d|\{\{|\}\})",                 # 格式化占位
    )
)

# require_keywords 的邻近窗口（字符数）
KEYWORD_WINDOW = 240

# --------------------------------------------------------------------- 规则特异性
#
# 有的规则描述的是"具体格式"（AKIA 开头 + 16 位、glpat- 开头 + 20 位），
# 有的规则只是"通用兜底"（变量名里有 PASSWORD、值是高熵串）。
# 两者可能命中同一段文本——此时必须让**具体格式规则胜出**，因为：
#   1. 它给出的是准确凭据类型，兜底规则只能给出"某个配置项"；
#   2. 它绑定了只读活性验证器，兜底规则没有；
#   3. 如果不区分优先级，谁胜出取决于候选的排列顺序——结果就不可复现。
#
# 下面这份清单列出"通用兜底"性质的规则，它们的特异性为负值。
GENERIC_FALLBACK_RULE_IDS: frozenset[str] = frozenset(
    {
        # generic.yaml
        "env-assignment-password",
        "yaml-password-field",
        "json-password-field",
        "os-account-credential",
        "ssh-command-password",
        "mysql-command-password",
        "high-entropy-quoted-string",
        "hardcoded-password-any",
        "weak-credential-pair",
        "generic-private-ip-credential",
        "private-config-file-reference",
        "docker-history-secret",
        # api_service.yaml
        "generic-api-key-variable",
        # crypto_keys.yaml
        "pgp-passphrase-var",
        "ssh-private-key-file-path",
        "aws-credentials-file-path",
        "kubeconfig-file-path",
        "pem-certificate",
    }
)

# 说明：像 `generic-db-password-var`（要求 MYSQL_/PG_ 等前缀）、
# `oauth-client-secret-generic`、`generic-dsn-assignment` 这类规则，
# 虽然 ID 带 generic，但命中的是**明确的技术字段名**，属于"具体格式"，
# 不应被降级——否则会被"变量名含 SECRET"的兜底规则盖掉，
# 进而丢失凭据类型，并破坏 OAuth / 数据库凭据的配对关联。

SPECIFICITY_GENERIC = -10
SPECIFICITY_KEYWORD_DEPENDENT = -5
SPECIFICITY_NORMAL = 0


def rule_specificity(rule_id: str, require_keywords: list[str] | None = None) -> int:
    """计算规则特异性。

    - 通用兜底规则：-10
    - 依赖关键词共现才敢报的规则：-5（说明其格式本身不够特异）
    - 其余（有固定前缀 / 长度 / 校验位等具体格式）：0
    """
    if rule_id in GENERIC_FALLBACK_RULE_IDS:
        return SPECIFICITY_GENERIC
    if require_keywords:
        return SPECIFICITY_KEYWORD_DEPENDENT
    return SPECIFICITY_NORMAL


def _iter_tokens(sequence):
    """递归展开 sre_parse 的子模式/分支/重复，产出 (op, av) 序列。"""
    from re import _parser as sre_parser

    for op, av in sequence:
        yield op, av
        try:
            if op is sre_parser.SUBPATTERN:
                yield from _iter_tokens(av[-1])
            elif op is sre_parser.BRANCH:
                for branch in av[1]:
                    yield from _iter_tokens(branch)
            elif op in (sre_parser.MAX_REPEAT, sre_parser.MIN_REPEAT):
                yield from _iter_tokens([av[2]])
        except Exception:  # noqa: BLE001 - 结构变体直接跳过
            continue


def longest_literal_run(pattern: str) -> int:
    """模式**头部**的最长字面前缀（特异性平局决胜）。

    例如 anthropic 的 `sk-ant-`（7）> openai 的 `sk-`（3）：
    同一跨度同时命中多条规则时，平台专有前缀更长的规则胜出，
    避免"Anthropic 密钥被标成 OpenAI 密钥"的标签降级。

    只统计从模式开头起的连续字面量（遇到字符类/量词/断言即停），
    分组透传、分支取第一个选项——这正是"平台专有前缀"的语义。
    """
    from re import _parser as sre_parser

    def head(seq) -> int:
        run = 0
        for op, av in seq:
            if op is sre_parser.LITERAL:
                run += 1
            elif op is sre_parser.SUBPATTERN:
                sub = head(av[-1])
                if sub == 0:
                    break  # 组头部不是字面量 → 前缀到此为止
                run += sub
            elif op is sre_parser.BRANCH:
                # 取第一个分支的头部（典型平台前缀写法）
                run += head(av[1][0])
                break
            elif op in (sre_parser.MAX_REPEAT, sre_parser.MIN_REPEAT):
                sub = head(av[2])
                if sub == 0:
                    break
                run += sub
                if not av[0]:
                    continue  # 可选组（如 jdbc: 前缀）：计入并继续
                break
            elif op in (sre_parser.AT, sre_parser.ASSERT, sre_parser.ASSERT_NOT):
                continue  # 断言/锚点零宽，不打断字面前缀
            else:
                break  # 字符类/量词等：前缀结束
        return run

    try:
        return head(sre_parser.parse(pattern, 0))
    except Exception:  # noqa: BLE001 - 解析失败时退回 0，不影响排序
        return 0


# 整个命中串本身即为"文档示例"的特征。
# 与 PLACEHOLDER_PATTERNS 的区别：后者只检查捕获组，
# 这里检查整段匹配——因为 DSN 类规则的"示例特征"往往出现在
# 用户名位置（如 mysql://user:password@host/db），不在捕获组里。
PLACEHOLDER_MATCH_RE = re.compile(
    r"(?i)(?:"
    r"\buser(?:name)?\b\s*[:/]\s*\bpass(?:word|wd)?\b"      # user:password@
    r"|\b(?:root|admin|test|demo|foo|bar)\b\s*[:/]\s*\bpass(?:word|wd)?\b"
    r"|\bpass(?:word|wd)?\b\s*[:@]"                          # password@host
    r"|<[A-Z_]{2,}>"                                         # <YOUR_KEY>
    r"|\$\{[A-Z_]+\}"                                        # ${ENV_VAR}
    r"|\byour[_-]"
    r"|\bxxxx+"
    r"|example\.(?:com|org|net)"
    r"|\bplaceholder\b|\breplace[_-]?me\b|\bchangeme\b"
    r"|\bfoo[:.]bar\b"
    r")"
)


def is_placeholder_match(full_match: str) -> bool:
    """判断整段匹配是否带有明显的"文档示例"特征。"""
    return bool(PLACEHOLDER_MATCH_RE.search(full_match))


@dataclass
class Candidate:
    """规则引擎产出的候选命中，尚未经过熵与上下文评分。"""

    rule_id: str
    rule_name: str
    category: str
    kind: str
    severity: str
    detector: str = "rule"
    secret: str = ""
    span: tuple[int, int] = (0, 0)
    line_no: int | None = None
    snippet: str = ""
    validator: str | None = None
    description: str = ""
    rule_index: int = 0
    # 规则特异性：越大越"具体"。位置重叠时用它决定谁胜出，
    # 保证"具体格式规则"永远压过"通用兜底规则"。
    rule_specificity: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Rule:
    id: str
    name: str
    kind: str
    severity: str
    pattern: str
    category: str
    label: str
    description: str = ""
    keywords: list[str] = field(default_factory=list)
    require_keywords: list[str] = field(default_factory=list)
    validator: str | None = None
    entropy: bool = False
    entropy_threshold: float = 0.0
    multiline: bool = False
    # 显式指定"哪一个捕获组才是密钥本身"。
    # 连接串类规则里 group(1) 常是用户名，必须用 secret_group 指到口令上，
    # 否则会把用户名当成凭据上报（既错又无法验活）。
    secret_group: int | None = None
    # 最长字面前缀长度：同跨度多规则竞争时的平局决胜（见 longest_literal_run）
    prefix_score: int = 0
    _compiled: re.Pattern[str] | None = field(default=None, repr=False, compare=False)

    @property
    def compiled(self) -> re.Pattern[str]:
        if self._compiled is None:
            flags = re.IGNORECASE if "(?i" not in self.pattern[:6] else 0
            if self.multiline:
                flags |= re.MULTILINE
            self._compiled = re.compile(self.pattern, flags)
        return self._compiled


def is_placeholder(value: str) -> bool:
    """判断一个候选值是否为占位符/示例值。"""
    v = value.strip()
    if len(v) < 4:
        return True
    if v.lower() in {"true", "false", "none", "null"}:
        return True
    # 单一字符重复（aaaa..., 1111...）
    if len(set(v)) <= 2:
        return True
    for pat in PLACEHOLDER_PATTERNS:
        if pat.search(v):
            return True
    return False


def line_of(text: str, offset: int) -> int:
    """由字符偏移量反推行号（1 起）。"""
    return text.count("\n", 0, offset) + 1


def snippet_of(text: str, start: int, end: int, secret: str, width: int = 60) -> str:
    """截取命中行片段，并把明文替换为掩码，保证报告本身不含明文。"""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end].strip()
    if len(line) > width * 2:
        line = line[: width * 2] + "…"
    if secret:
        line = line.replace(secret, "*" * min(len(secret), 12))
    return line


class RuleEngine:
    """加载规则目录下全部 YAML 规则，并对文档执行扫描。"""

    def __init__(self, rules: Iterable[Rule]) -> None:
        self.rules: list[Rule] = list(rules)

    # ------------------------------------------------------------------ 加载

    @classmethod
    def from_dir(cls, rules_dir: Path | str) -> "RuleEngine":
        rules_dir = Path(rules_dir)
        rules: list[Rule] = []
        for path in sorted(rules_dir.glob("*.y*ml")):
            rules.extend(cls._load_file(path))
        return cls(rules)

    @staticmethod
    def _load_file(path: Path) -> list[Rule]:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        category = data.get("category") or path.stem
        label = data.get("label") or category
        loaded: list[Rule] = []
        for idx, item in enumerate(data.get("rules") or []):
            try:
                loaded.append(
                    Rule(
                        id=str(item["id"]),
                        name=str(item.get("name", item["id"])),
                        kind=str(item.get("kind", "未分类")),
                        severity=str(item.get("severity", "medium")),
                        pattern=str(item["pattern"]),
                        category=category,
                        label=label,
                        description=str(item.get("description", "")),
                        keywords=[str(k) for k in (item.get("keywords") or [])],
                        require_keywords=[str(k) for k in (item.get("require_keywords") or [])],
                        validator=item.get("validator"),
                        entropy=bool(item.get("entropy", False)),
                        entropy_threshold=float(item.get("entropy_threshold", 0.0) or 0.0),
                        multiline=bool(item.get("multiline", False)),
                        secret_group=item.get("secret_group"),
                        prefix_score=longest_literal_run(str(item["pattern"])),
                    )
                )
            except KeyError as exc:  # 规则文件写错时给出明确位置
                raise ValueError(f"规则文件 {path.name} 第 {idx + 1} 条缺少字段 {exc}") from exc
        return loaded

    # ------------------------------------------------------------------ 统计

    def stats(self) -> dict[str, Any]:
        by_category: dict[str, int] = {}
        by_kind: dict[str, int] = {}
        for r in self.rules:
            by_category[r.label] = by_category.get(r.label, 0) + 1
            by_kind[r.kind] = by_kind.get(r.kind, 0) + 1
        return {
            "total_rules": len(self.rules),
            "categories": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
            "kinds": dict(sorted(by_kind.items(), key=lambda kv: -kv[1])),
            "validators": sorted({r.validator for r in self.rules if r.validator}),
        }

    # ------------------------------------------------------------------ 扫描

    def scan(self, text: str) -> list[Candidate]:
        """对一段文本执行全部规则，返回通过占位符与关键词校验的候选。"""
        if not text:
            return []
        lowered = text.lower()
        out: list[Candidate] = []
        for rule in self.rules:
            try:
                matches = list(rule.compiled.finditer(text))
            except re.error:
                continue
            if not matches:
                continue
            for m in matches:
                secret = self._extract_secret(m, rule)
                if not secret or is_placeholder(secret):
                    continue
                if is_placeholder_match(m.group(0)):
                    continue
                start, end = m.span()
                if rule.require_keywords and not self._window_has_keyword(
                    lowered, start, end, rule.require_keywords
                ):
                    continue
                out.append(
                    Candidate(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        category=rule.category,
                        kind=rule.kind,
                        severity=rule.severity,
                        secret=secret,
                        span=(start, end),
                        line_no=line_of(text, start),
                        snippet=snippet_of(text, start, end, secret),
                        validator=rule.validator,
                        description=rule.description,
                        rule_index=len(out),
                        rule_specificity=rule_specificity(rule.id, rule.require_keywords)
                        + min(rule.prefix_score, 24),
                        metadata={
                            "rule_entropy": rule.entropy,
                            "rule_entropy_threshold": rule.entropy_threshold,
                            "label": rule.label,
                            "keywords": rule.keywords,
                        },
                    )
                )
        return out

    @staticmethod
    def _extract_secret(match: re.Match[str], rule: Rule) -> str:
        """取出"密钥本身"。

        优先级：规则显式指定的 secret_group > 捕获组 1 > 整个匹配。
        """
        if rule.secret_group is not None and match.re.groups >= rule.secret_group:
            value = match.group(rule.secret_group)
            if value is not None:
                return value.strip()
        if match.re.groups and match.group(1) is not None:
            return match.group(1).strip()
        return match.group(0).strip()

    @staticmethod
    def _window_has_keyword(
        lowered_text: str, start: int, end: int, keywords: list[str]
    ) -> bool:
        left = max(0, start - KEYWORD_WINDOW)
        right = min(len(lowered_text), end + KEYWORD_WINDOW)
        window = lowered_text[left:right]
        return any(k.lower() in window for k in keywords)
