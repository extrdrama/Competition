"""上下文结构化提取：把"发现了一条凭据"升级为"这凭据能访问什么"。

为什么这是必要的：

同类赛题明确要求"能关联上下文，输出关联的敏感信息对"，
例如 `{"ip":"127.0.0.1","port":3306,"username":"root","password":"root"}`。
这个要求的本质是：**一条孤立的口令对应急响应几乎没有用**，
有用的是知道它连的是哪台主机、哪个端口、哪个库、以什么身份。

    「数据库口令 = Pr0d_xxxx」      → 只知道"有泄露"
    「MySQL，10.20.30.41:3306，账号 app_rw，库 production」
                                    → 知道暴露面有多大、该封哪台、该改哪个账号

本模块从命中位置的上下文中提取结构化字段，产出可直接用于
应急响应与资产定位的"信息对"。所有敏感字段（口令/私钥）一律掩码。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, urlparse

from .models import Finding

# --------------------------------------------------------------------- DSN 解析

# scheme://user:pass@host[:port][/db]
DSN_RE = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.]*)://"
    r"(?:(?P<user>[^\s:/@'\"]*)?(?::(?P<password>[^\s:/@'\"]+))?@)?"
    r"(?P<host>[^\s/'\"@:]+)"
    r"(?::(?P<port>\d{1,5}))?"
    r"(?:/(?P<database>[^\s'\"?]*))?"
)

# scheme → 服务类型（用于识别与展示）
SCHEME_SERVICE: dict[str, str] = {
    "mysql": "MySQL", "mysql+pymysql": "MySQL", "mysql+mysqldb": "MySQL",
    "mariadb": "MariaDB",
    "postgres": "PostgreSQL", "postgresql": "PostgreSQL", "postgres+psycopg2": "PostgreSQL",
    "mongodb": "MongoDB", "mongodb+srv": "MongoDB", "mongo": "MongoDB",
    "redis": "Redis", "rediss": "Redis",
    "amqp": "RabbitMQ", "kafka": "Kafka", "zookeeper": "ZooKeeper",
    "clickhouse": "ClickHouse", "gaussdb": "GaussDB", "oceanbase": "OceanBase",
    "ftp": "FTP", "ftps": "FTP",
    "socks5": "SOCKS5 代理", "socks4": "SOCKS4 代理",
    "oracle": "Oracle", "mssql": "SQL Server", "sqlserver": "SQL Server",
    "elasticsearch": "Elasticsearch", "opensearch": "OpenSearch",
}

# 常见服务的默认端口（DSN 未写端口时补全，方便定位）
DEFAULT_PORTS: dict[str, str] = {
    "MySQL": "3306", "MariaDB": "3306", "PostgreSQL": "5432", "MongoDB": "27017",
    "Redis": "6379", "RabbitMQ": "5672", "Kafka": "9092", "ZooKeeper": "2181",
    "ClickHouse": "8123", "Elasticsearch": "9200", "OpenSearch": "9200",
    "Oracle": "1521", "SQL Server": "1433", "FTP": "21",
    "HTTP 服务": "80", "SOCKS5 代理": "1080",
}

# IP 地址（含内网段识别）
IP_RE = re.compile(
    r"\b((?:\d{1,3}\.){3}\d{1,3})\b"
)
PRIVATE_IP_RE = re.compile(
    r"^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)"
)

# 通用 KEY=VALUE 扫描（覆盖 MYSQL_USER / DB_HOST / POSTGRES_PORT 等）
KV_RE = re.compile(
    r"(?im)(?:^|\s)([A-Za-z_][A-Za-z0-9_.]{1,40})\s*[=:]\s*['\"]?([^\s'\";,]{1,120})"
)

# 键名关键词 → 结构化字段（按优先级，先命中先用）
FIELD_KEY_HINTS: tuple[tuple[str, str], ...] = (
    ("username", "username"), ("user_name", "username"),
    ("db_user", "username"), ("db_username", "username"),
    ("user", "username"),
    ("host", "host"), ("hostname", "host"), ("endpoint", "host"),
    ("server", "host"),
    ("port", "port"),
    ("database", "database"), ("dbname", "database"), ("db_name", "database"),
    ("schema", "database"),
    ("bucket", "bucket"), ("container", "bucket"),
)


def _classify_key(key: str) -> str | None:
    """把变量名归类为结构化字段（MYSQL_USER -> username）。"""
    k = key.lower()
    # 优先长关键词，避免 "username" 被 "user" 抢先
    for hint, field_name in FIELD_KEY_HINTS:
        if hint in k:
            return field_name
    return None

CONTEXT_WINDOW = 300


@dataclass
class SecretContext:
    """一条凭据的结构化上下文（敏感信息对）。"""

    kind: str                       # mysql / generic / cloud 等
    service: str                    # MySQL / PostgreSQL / ...
    fields: dict[str, str] = field(default_factory=dict)
    is_internal: bool = False       # 是否指向内网资产
    extraction: str = "none"        # dsn / nearby / none
    confidence: float = 0.0

    def to_record(self) -> dict[str, Any]:
        if not self.fields:
            return {}
        return {
            "kind": self.kind,
            "service": self.service,
            "fields": self.fields,
            "is_internal": self.is_internal,
            "extraction": self.extraction,
            "confidence": self.confidence,
            "summary": self.summary(),
        }

    def summary(self) -> str:
        """生成一句话描述，用于报告与告警。"""
        if not self.fields:
            return ""
        parts = [f"{k}={v}" for k, v in self.fields.items() if v]
        scope = "内网" if self.is_internal else "公网/未判定"
        return f"{self.service}（{scope}）：" + "，".join(parts)

    def as_pair(self) -> dict[str, str]:
        """输出赛题风格的"敏感信息对"（口令已掩码）。"""
        return dict(self.fields)


def _mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * max(len(value), 4)
    return f"{value[:2]}****{value[-2:]}"


def _classify_host(host: str) -> tuple[bool, str]:
    """返回 (是否内网, 主机类型)。"""
    if PRIVATE_IP_RE.match(host):
        return True, "IP"
    if IP_RE.match(host):
        return False, "IP"
    if host in ("localhost",) or host.endswith(".local"):
        return True, "主机名"
    if re.match(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$", host):
        return False, "域名"
    return False, "标识符"


# --------------------------------------------------------------------- 提取器


class ContextExtractor:
    """从发现及其上下文中提取结构化"敏感信息对"。"""

    def extract(self, finding: Finding, text: str) -> SecretContext | None:
        start = finding.evidence.line_no or 0
        # 用命中位置附近的一段文本做上下文抽取
        window = self._window_around(text, finding)
        if not window:
            return None

        dsn = self._from_dsn(finding, window)
        if dsn:
            return dsn
        return self._from_nearby(finding, window)

    # ------------------------------------------------------------------ 内部

    @staticmethod
    def _window_around(text: str, finding: Finding) -> str:
        """取命中行附近 ±CONTEXT_WINDOW 的文本。"""
        if not text:
            return ""
        # 以行号为锚点定位（evidence 保存的是行号）
        line_no = finding.evidence.line_no
        if line_no:
            lines = text.splitlines()
            idx = min(max(line_no - 1, 0), len(lines) - 1)
            lo = max(0, idx - 6)
            hi = min(len(lines), idx + 7)
            return "\n".join(lines[lo:hi])
        # 退化：无行号时用整个文本（较弱）
        return text[: CONTEXT_WINDOW * 2]

    def _from_dsn(self, finding: Finding, window: str) -> SecretContext | None:
        """从 DSN/URL 形式的命中中解析结构化字段。"""
        m = DSN_RE.search(window)
        if not m:
            return None
        scheme = (m.group("scheme") or "").lower()
        if scheme not in SCHEME_SERVICE:
            return None  # 只解析已知数据库/服务协议，普通 URL 不算 DSN
        host = m.group("host") or ""
        if not host:
            return None

        service = SCHEME_SERVICE.get(scheme, scheme.upper() or "未知服务")
        fields: dict[str, str] = {"service": service, "host": host}

        user = m.group("user")
        if user:
            fields["username"] = unquote(user)
        password = m.group("password")
        if password:
            # 口令绝不落明文
            fields["password"] = _mask(unquote(password))
        port = m.group("port") or DEFAULT_PORTS.get(service, "")
        if port:
            fields["port"] = port
        database = m.group("database")
        if database:
            database = database.split("?")[0].rstrip("/")
            # 只接受"像库名"的值：字母数字下划线连字符
            if database and re.fullmatch(r"[A-Za-z0-9_.\-]+", database):
                fields["database"] = database

        internal, host_type = _classify_host(host)
        fields["host_type"] = host_type

        confidence = 0.85 if (user and password) else 0.65
        return SecretContext(
            kind="database" if service in DEFAULT_PORTS else "service",
            service=service,
            fields=fields,
            is_internal=internal,
            extraction="dsn",
            confidence=confidence,
        )

    def _from_nearby(self, finding: Finding, window: str) -> SecretContext | None:
        """通用兜底：扫描邻近的 KEY=VALUE，把变量名归类为结构化字段。"""
        fields: dict[str, str] = {}
        for m in KV_RE.finditer(window):
            field_name = _classify_key(m.group(1))
            if not field_name or field_name in fields:
                continue
            value = m.group(2).strip()
            if not value or value.startswith(("${", "<", "%", "*", "os.", "process.")):
                continue
            if value.lower() in ("localhost",):
                continue
            fields[field_name] = value

        # 口令字段：来自 finding 本身（已掩码），不重复抽取
        if finding.masked:
            fields.setdefault("credential", finding.masked)

        if not fields:
            return None

        host = fields.get("host", "")
        internal = False
        if host:
            internal, host_type = _classify_host(host)
            fields["host_type"] = host_type
        else:
            # 退化：从窗口中找第一个 IP
            ip = IP_RE.search(window)
            if ip:
                fields["host"] = ip.group(1)
                internal, host_type = _classify_host(ip.group(1))
                fields["host_type"] = host_type

        if len(fields) < 2:
            return None

        return SecretContext(
            kind="generic",
            service="未识别服务",
            fields=fields,
            is_internal=internal,
            extraction="nearby",
            confidence=0.5,
        )


def enrich_with_context(
    findings: Iterable[Finding], documents: dict[str, str]
) -> int:
    """为一批发现补充结构化上下文，返回成功提取的数量。

    Args:
        findings: 发现列表（就地修改 metadata["context"]）
        documents: url -> 文档正文 的映射（用于提取上下文窗口）
    """
    extractor = ContextExtractor()
    count = 0
    for finding in findings:
        text = documents.get(finding.evidence.url, "")
        if not text:
            continue
        context = extractor.extract(finding, text)
        if context and context.fields:
            finding.metadata["context"] = context.to_record()
            count += 1
    return count


def context_statistics(findings: Iterable[Finding]) -> dict[str, Any]:
    """统计上下文提取的覆盖与构成。"""
    total = extracted = internal = 0
    by_service: dict[str, int] = {}
    hosts: set[str] = set()
    for finding in findings:
        total += 1
        context = (finding.metadata or {}).get("context") or {}
        if not context:
            continue
        extracted += 1
        if context.get("is_internal"):
            internal += 1
        service = context.get("service") or "未知"
        by_service[service] = by_service.get(service, 0) + 1
        host = (context.get("fields") or {}).get("host")
        if host:
            hosts.add(host)
    return {
        "findings": total,
        "with_context": extracted,
        "coverage": round(extracted / total, 3) if total else 0.0,
        "internal_targets": internal,
        "unique_hosts": len(hosts),
        "by_service": dict(sorted(by_service.items(), key=lambda kv: -kv[1])),
    }


__all__ = [
    "ContextExtractor",
    "SecretContext",
    "context_statistics",
    "enrich_with_context",
]
