"""数据模型层。

设计要点（对应赛题"防御性"与"合规"要求）：
1. 凭据**永不落盘明文**。对外序列化时只保留 `masked`（掩码）与 `fingerprint`
   （HMAC-SHA256 指纹）。明文仅以 `raw` 字段短暂存在于内存，用于可选的只读活性验证，
   且 `to_record()` 会主动丢弃。
2. 指纹使用带盐 HMAC，保证同一凭据在不同渠道、不同批次能被识别为同一条，
   同时不可逆推出原文。
"""

from __future__ import annotations

import hashlib
import hmac
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

MASK_HEAD = 4
MASK_TAIL = 4
# 掩码中间的星号数量固定，避免凭据长度被反推出来
MASK_STARS = 4

DEFAULT_SALT = "credwatch-default-salt"


def utcnow() -> datetime:
    """统一使用带时区的 UTC 时间，避免跨时区比较出错。"""
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).isoformat() if dt else None


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER: dict[str, int] = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


def max_severity(a: str, b: str) -> str:
    """取两个风险等级中更高的一个，用于跨渠道关联时升级风险。"""
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


def mask_secret(secret: str) -> str:
    """把凭据掩码成 ``AKIA****f9Xz`` 形式。

    中间固定 4 个星号（而非按长度生成），避免凭据的真实长度被反推出来。
    私钥类内容过长且整体敏感，只保留头部标识与长度。
    """
    s = secret.strip()
    if s.startswith("-----BEGIN"):
        header = s.splitlines()[0].strip()
        return f"{header}（{len(s)} 字节，内容已省略）"
    if len(s) <= MASK_HEAD + MASK_TAIL + 2:
        return "*" * min(len(s), 8)
    return f"{s[:MASK_HEAD]}{'*' * MASK_STARS}{s[-MASK_TAIL:]}"


def fingerprint(secret: str, salt: str | None = None) -> str:
    """对凭据做带盐 HMAC-SHA256，得到可去重、可关联、不可逆的指纹。"""
    key = (salt or os.getenv("CREDWATCH_HMAC_SALT") or DEFAULT_SALT).encode("utf-8")
    return hmac.new(key, secret.strip().encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass
class RawDoc:
    """渠道采集到的**原始**内容，尚未做任何解析。"""

    source: str
    external_id: str
    url: str
    content: bytes
    content_type: str = "text/plain"
    author: str | None = None
    published_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.content, str):
            self.content = self.content.encode("utf-8", errors="replace")


@dataclass
class Document:
    """归一化后的待检测文本载体。"""

    doc_id: str
    source: str
    url: str
    text: str
    content_type: str = "text/plain"
    author: str | None = None
    published_at: datetime | None = None
    discovered_at: datetime = field(default_factory=utcnow)
    path_hint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def new_id(source: str, external_id: str) -> str:
        return f"{source}:{external_id}"


@dataclass
class Evidence:
    """命中位置证据，保证结果可解释、可审计、可复核。"""

    url: str
    path_hint: str = ""
    line_no: int | None = None
    line_end: int | None = None
    snippet: str = ""
    published_at: datetime | None = None
    discovered_at: datetime | None = None


@dataclass
class Finding:
    """一条凭据泄露发现。"""

    rule_id: str
    rule_name: str
    category: str
    severity: str
    confidence: float
    detector: str
    masked: str
    fingerprint: str
    evidence: Evidence
    source: str = ""
    validated: bool | None = None
    validation_note: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    # 仅内存中存在，绝不序列化。用于可选的只读活性验证。
    raw: str | None = field(default=None, repr=False, compare=False)

    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])

    def to_record(self) -> dict[str, Any]:
        """产出可落盘/可上报的字典，**主动丢弃明文**。"""
        data = asdict(self)
        data.pop("raw", None)
        ev = data.get("evidence") or {}
        ev["published_at"] = iso(self.evidence.published_at)
        ev["discovered_at"] = iso(self.evidence.discovered_at)
        data["evidence"] = ev
        return data


@dataclass
class ScanStats:
    """单次扫描的统计信息，用于报告与 MTTD 计算。"""

    documents_scanned: int = 0
    bytes_scanned: int = 0
    candidates: int = 0
    findings: int = 0
    validated: int = 0
    stage_counts: dict[str, int] = field(default_factory=dict)
    started_at: datetime = field(default_factory=utcnow)
    finished_at: datetime | None = None

    def elapsed_seconds(self) -> float:
        end = self.finished_at or utcnow()
        return (end - self.started_at).total_seconds()

    def to_record(self) -> dict[str, Any]:
        data = asdict(self)
        data["started_at"] = iso(self.started_at)
        data["finished_at"] = iso(self.finished_at)
        data["elapsed_seconds"] = round(self.elapsed_seconds(), 3)
        return data
