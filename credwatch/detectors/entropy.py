"""检测层第 2 环：香农熵检测。

作用：规则库只能覆盖"已知格式"的凭据。对于自研系统的密钥、
内部平台的 token 这类没有公开格式的凭据，靠熵值兜底发现。
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from .rule_engine import Candidate, is_placeholder, line_of, snippet_of

# 候选 token 的形态：base64 / base64url / hex 混合的长串
TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,128}")

# 纯数字、纯小写字母等低信息密度串直接排除
NUMERIC_RE = re.compile(r"^\d+$")
ALPHA_LOWER_RE = re.compile(r"^[a-z]+$")

# 常见的高频无害长串（哈希文件名、依赖版本哈希等）
NOISE_RE = re.compile(
    r"(?i)(?:^[a-f0-9]{40}$|^[a-f0-9]{64}$|sha256[-:]|integrity|sha512|"
    r"^\d+\.\d+\.\d+|cdn|\.min\.js|sourceMappingURL)"
)


def shannon_entropy(value: str) -> float:
    """计算字符串的香农熵（比特/字符）。"""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


@dataclass
class EntropyConfig:
    threshold: float = 4.5
    min_length: int = 20
    max_length: int = 128
    # 要求串中至少包含两类字符，避免"aaaa1111"这类伪高熵
    min_charset: int = 2

    def charset_count(self, value: str) -> int:
        n = 0
        if re.search(r"[a-z]", value):
            n += 1
        if re.search(r"[A-Z]", value):
            n += 1
        if re.search(r"\d", value):
            n += 1
        if re.search(r"[+/=_\-]", value):
            n += 1
        return n


class EntropyDetector:
    """对文档做高熵串扫描，产出 `detector="entropy"` 的候选。"""

    def __init__(self, config: EntropyConfig | None = None) -> None:
        self.config = config or EntropyConfig()

    def scan(self, text: str) -> list[Candidate]:
        if not text:
            return []
        cfg = self.config
        lowered = text.lower()
        out: list[Candidate] = []
        for m in TOKEN_RE.finditer(text):
            value = m.group(0)
            if not (cfg.min_length <= len(value) <= cfg.max_length):
                continue
            if NUMERIC_RE.match(value) or ALPHA_LOWER_RE.match(value):
                continue
            if cfg.charset_count(value) < cfg.min_charset:
                continue
            if is_placeholder(value) or NOISE_RE.search(value):
                continue
            score = shannon_entropy(value)
            if score < cfg.threshold:
                continue
            start, end = m.span()
            out.append(
                Candidate(
                    rule_id="entropy-high-value",
                    rule_name="高熵候选串",
                    category="generic",
                    kind="通用密钥",
                    severity="medium",
                    detector="entropy",
                    secret=value,
                    span=(start, end),
                    line_no=line_of(text, start),
                    snippet=snippet_of(text, start, end, value),
                    metadata={
                        "entropy": round(score, 3),
                        "length": len(value),
                        "charset": cfg.charset_count(value),
                        "window": lowered[max(0, start - 80) : start],
                    },
                )
            )
        return out
