"""检测层补充环：结构化文件解析。

正则匹配对 `KEY=value` 这类结构是"盲猜"，而配置文件本身是有语法的。
能结构化解析的地方就结构化解析——准确率显著高于正则，且几乎不产生误报。

覆盖对象：
- dotenv 风格（.env / .env.production / 环境导出脚本）
- INI 风格（~/.aws/credentials、MobaXterm、部分 SDK 配置）
- Kubernetes Secret 清单（data 字段 Base64，等价明文）
- Docker 镜像构建历史中的 ENV / ARG 残留
- PEM 私钥整块提取
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

from .rule_engine import Candidate, is_placeholder, line_of, snippet_of

# 变量名中出现即视为凭据类
SECRET_NAME_RE = re.compile(
    r"(?i)(?:^|_)(?:PASS(?:WORD|WD)?|PWD|SECRET|TOKEN|KEY|CREDENTIAL|AUTH|"
    r"SALT|CIPHER|PRIVATE|CERT|DSN|CONN(?:ECTION)?)(?:$|_)"
)

# 常见环境/配置取值——形如 SECRET_KEY=development 不应算作凭据泄露
_COMMON_ENV_WORDS = frozenset({
    "development", "production", "staging", "testing", "test", "local",
    "localhost", "debug", "default", "enabled", "disabled", "true", "false",
    "none", "null", "undefined", "utf8", "ascii", "json", "yaml", "text",
    "application", "server", "client", "public", "readonly", "readwrite",
    "info", "warn", "warning", "error", "trace", "silent",
})

DOTENV_RE = re.compile(r"^(?P<indent>\s*)(?:export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(?P<raw>.*)$")
INI_SECTION_RE = re.compile(r"^\s*\[(?P<name>[^\]]+)\]\s*$")
INI_KV_RE = re.compile(r"^\s*(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)\s*[=:]\s*(?P<raw>.+?)\s*$")
PEM_BLOCK_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
    r"[\s\S]{40,8000}?"
    r"-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
)
DOCKER_ENV_RE = re.compile(
    r"(?im)^\s*(?:ENV|ARG)\s+(?P<key>[A-Za-z_][A-Za-z0-9_]*)(?:[=\s]+)(?P<value>.+?)\s*$"
)
B64_RE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")

# 值为这些形态时视为非明文凭据
NON_SECRET_VALUE_RE = re.compile(
    r"(?i)^(?:true|false|none|null|nil|0|1|\d+|localhost|127\.0\.0\.1|"
    r"utf-?8|debug|info|warn|error|production|development|testing|"
    r"redis|mysql|postgres|mongo|http|https|GET|POST)$"
)


@dataclass
class ParseReport:
    """结构化解析的统计信息（保留给上层做覆盖率统计用）。"""

    strategies: list[str] = field(default_factory=list)
    hits: int = 0


class StructuredParser:
    """按文件类型选择解析策略，全部返回统一的 Candidate。"""

    def parse(self, text: str, path_hint: str = "") -> list[Candidate]:
        if not text:
            return []
        out: list[Candidate] = []
        out.extend(self._parse_pem(text))
        out.extend(self._parse_dotenv(text))
        out.extend(self._parse_ini(text))
        out.extend(self._parse_k8s_secret(text))
        out.extend(self._parse_docker_history(text))
        return out

    # ---------------------------------------------------------------- PEM 私钥

    def _parse_pem(self, text: str) -> list[Candidate]:
        out: list[Candidate] = []
        for m in PEM_BLOCK_RE.finditer(text):
            block = m.group(0)
            head = block.splitlines()[0].strip()
            label = (
                "OpenSSH 私钥"
                if "OPENSSH" in head
                else "RSA 私钥"
                if "RSA" in head
                else "EC 私钥"
                if "EC " in head or "EC PRIVATE" in head
                else "加密私钥"
                if "ENCRYPTED" in head
                else "PGP 私钥"
                if "PGP" in head
                else "通用私钥"
            )
            start, end = m.span()
            out.append(
                Candidate(
                    rule_id="structured-pem-private-key",
                    rule_name=f"{label}（结构化提取）",
                    category="crypto_keys",
                    kind="非对称私钥",
                    severity="critical",
                    detector="structured",
                    secret=block,
                    span=(start, end),
                    line_no=line_of(text, start),
                    snippet=f"{head} … 共 {len(block.splitlines())} 行（内容已省略）",
                    metadata={"pem_header": head, "label": "私钥与密钥文件"},
                )
            )
        return out

    # ---------------------------------------------------------------- dotenv

    def _parse_dotenv(self, text: str) -> list[Candidate]:
        out: list[Candidate] = []
        offset = 0
        for raw_line in text.splitlines(keepends=True):
            m = DOTENV_RE.match(raw_line.rstrip("\n"))
            if m:
                key = m.group("key")
                value = self._clean_value(m.group("raw"))
                if self._is_secret_pair(key, value):
                    out.append(
                        self._make(
                            key=key,
                            value=value,
                            rule_id="structured-dotenv-secret",
                            rule_name="dotenv 凭据变量",
                            severity="high",
                            text=text,
                            offset=offset + m.start("raw"),
                            note="dotenv 结构解析",
                        )
                    )
            offset += len(raw_line)
        return out

    # ---------------------------------------------------------------- INI

    def _parse_ini(self, text: str) -> list[Candidate]:
        out: list[Candidate] = []
        offset = 0
        section = ""
        for raw_line in text.splitlines(keepends=True):
            line = raw_line.rstrip("\n")
            sec = INI_SECTION_RE.match(line)
            if sec:
                section = sec.group("name")
            else:
                kv = INI_KV_RE.match(line)
                if kv and section:
                    key = kv.group("key")
                    value = self._clean_value(kv.group("raw"))
                    # INI 中只有处于凭据类 section 或键名敏感时才采纳
                    sensitive_section = bool(
                        re.search(r"(?i)default|credentials|profile|auth|token|secret", section)
                    )
                    if self._is_secret_pair(key, value) and (
                        sensitive_section or SECRET_NAME_RE.search(key)
                    ):
                        out.append(
                            self._make(
                                key=f"{section}.{key}",
                                value=value,
                                rule_id="structured-ini-credential",
                                rule_name="INI 凭据配置",
                                severity="critical"
                                if re.search(r"(?i)secret|key$", key)
                                else "high",
                                text=text,
                                offset=offset + kv.start("raw"),
                                note=f"INI 段 [{section}] 解析",
                            )
                        )
            offset += len(raw_line)
        return out

    # ---------------------------------------------------------------- k8s Secret

    def _parse_k8s_secret(self, text: str) -> list[Candidate]:
        if not re.search(r"(?im)^\s*kind:\s*Secret\s*$", text):
            return []
        out: list[Candidate] = []
        offset = 0
        in_data = False
        for raw_line in text.splitlines(keepends=True):
            line = raw_line.rstrip("\n")
            if re.match(r"^\s*(?:data|stringData):\s*$", line):
                in_data = True
                offset += len(raw_line)
                continue
            if in_data:
                if re.match(r"^\S", line):
                    in_data = False
                else:
                    m = re.match(r"^\s+(?P<key>[A-Za-z0-9_.\-]+)\s*:\s*(?P<raw>\S+)\s*$", line)
                    if m:
                        raw_value = self._clean_value(m.group("raw"))
                        decoded = ""
                        if B64_RE.match(raw_value):
                            try:
                                decoded = base64.b64decode(
                                    raw_value + "=" * (-len(raw_value) % 4)
                                ).decode("utf-8", errors="ignore")
                            except (binascii.Error, ValueError):
                                decoded = ""
                        value = decoded or raw_value
                        if value and not is_placeholder(value):
                            out.append(
                                self._make(
                                    key=m.group("key"),
                                    value=value,
                                    rule_id="structured-k8s-secret",
                                    rule_name="Kubernetes Secret 数据",
                                    severity="critical",
                                    text=text,
                                    offset=offset + m.start("raw"),
                                    note="k8s Secret 清单 Base64 解码",
                                )
                            )
            offset += len(raw_line)
        return out

    # ---------------------------------------------------------------- 镜像构建历史

    def _parse_docker_history(self, text: str) -> list[Candidate]:
        out: list[Candidate] = []
        for m in DOCKER_ENV_RE.finditer(text):
            key, value = m.group("key"), self._clean_value(m.group("value"))
            if self._is_secret_pair(key, value):
                out.append(
                    self._make(
                        key=key,
                        value=value,
                        rule_id="structured-docker-env",
                        rule_name="镜像构建 ENV/ARG 残留",
                        severity="high",
                        text=text,
                        offset=m.start("value"),
                        note="Dockerfile / 镜像构建历史解析",
                    )
                )
        return out

    # ---------------------------------------------------------------- 工具方法

    def _make(
        self,
        *,
        key: str,
        value: str,
        rule_id: str,
        rule_name: str,
        severity: str,
        text: str,
        offset: int,
        note: str,
    ) -> Candidate:
        return Candidate(
            rule_id=rule_id,
            rule_name=rule_name,
            category="generic" if "dotenv" in rule_id or "ini" in rule_id else "vcs_ci",
            kind="配置文件凭据",
            severity=severity,
            detector="structured",
            secret=value,
            span=(offset, offset + len(value)),
            line_no=line_of(text, offset),
            snippet=snippet_of(text, offset, offset + len(value), value),
            metadata={"config_key": key, "label": note},
        )

    @staticmethod
    def _clean_value(raw: str) -> str:
        """去掉引号、行尾注释与常见转义。"""
        value = raw.strip()
        # 去行尾注释（未包裹在引号内时）
        if not value.startswith(("'", '"')):
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        value = value.strip().strip("'\"")
        return value

    def _is_secret_pair(self, key: str, value: str) -> bool:
        """判断 (键, 值) 是否构成一条真实的凭据泄露。"""
        if not value or len(value) < 6:
            return False
        if is_placeholder(value) or NON_SECRET_VALUE_RE.match(value):
            return False
        # 值是纯数字、单字符重复、或明显是路径/URL 参数时排除
        if len(set(value)) <= 2:
            return False
        if value.startswith(("/", "./", "../")):
            return False
        # 真实凭据不含空格；含空格的取值几乎都是 "Secret access key" 这类
        # 文档说明文字（CredData 探针中的主要误报形态之一）。
        if " " in value or "\t" in value:
            return False
        # URL、模板表达式与 shell 命令替换不是凭据
        if "://" in value or "`" in value or "$(" in value or "${" in value:
            return False
        # 纯数字取值（枚举常量、端口、时间戳）
        if value.isdigit():
            return False
        # 真实凭据通常含数字或符号；纯字母单词（development / production /
        # localhost 等环境名）不是凭据。经验证据：CredData 探针中该规则
        # 误报远多于真值，主因即 dotenv 里大量纯字母配置值。
        if len(value) < 12 and value.isalpha():
            return False
        if value.isalpha() and value.lower() in _COMMON_ENV_WORDS:
            return False
        if not SECRET_NAME_RE.search(key):
            return False
        return True
