"""性能基准测试。

赛题评分项里明确包含"作品的性能"。性能不能只靠嘴说，必须有可复现的数字。

本模块做三件事：

1. **吞吐量**：生成可控规模的合成语料，测出文档/秒、MB/秒；
2. **阶段耗时**：把检测流水线拆成几个阶段分别计时，指出瓶颈在哪；
3. **规则热点**：逐条规则的累计耗时排行，为规则库优化提供依据。

合成语料采用固定随机种子，任何人都能复现出同样的数字；
语料中的凭据全部为程序生成的伪造值。
"""

from __future__ import annotations

import random
import string
import time
import tracemalloc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .detectors import DetectionPipeline, RuleEngine
from .models import Document

RNG_SEED = 20260912

TEMPLATE = """# 服务配置
APP_ENV=production
LOG_LEVEL=info

# 对象存储
AWS_ACCESS_KEY_ID=AKIA{ak}
AWS_SECRET_ACCESS_KEY={sk}

# 数据库
MYSQL_HOST=10.20.30.{host}
MYSQL_USER=app_rw
MYSQL_PASSWORD=Pr0d_{dbpass}
DATABASE_URL=mysql://app_rw:Pr0d_{dbpass}@10.20.30.{host}:3306/production

# 缓存
REDIS_PASSWORD={redispass}

# 第三方
JWT_SECRET={jwt}
{extra}
"""

# 一部分文档不含任何凭据，模拟真实语料中的噪声比例
NOISE_TEMPLATE = """# 说明文档
本项目使用标准的分层架构。

## 配置方式
复制 .env.example 为 .env 后填写：
AWS_ACCESS_KEY_ID=your_access_key_here
SECRET_KEY=<YOUR_SECRET_KEY>
API_KEY=xxxxxxxxxxxxxxxx

## 运行
python -m app --port 8080
"""


@dataclass
class BenchmarkResult:
    documents: int
    bytes_total: int
    credentials_expected: int
    findings: int
    elapsed_seconds: float
    docs_per_second: float
    mb_per_second: float
    stage_seconds: dict[str, float] = field(default_factory=dict)
    rule_hotspots: list[tuple[str, float, int]] = field(default_factory=list)
    peak_memory_mb: float = 0.0
    matched_expectation: bool = False
    # 按风险等级分解命中数：注入的凭据大多是严重/高级，
    # 多出来的部分是低级别的上下文提示（如"内网 IP + 口令关键词共现"），
    # 这里如实列出，避免"命中数高于注入数"看起来像在凑数
    by_severity: dict[str, int] = field(default_factory=dict)

    def to_record(self) -> dict[str, Any]:
        return {
            "documents": self.documents,
            "bytes_total": self.bytes_total,
            "credentials_expected": self.credentials_expected,
            "findings": self.findings,
            "elapsed_seconds": round(self.elapsed_seconds, 4),
            "docs_per_second": round(self.docs_per_second, 1),
            "mb_per_second": round(self.mb_per_second, 3),
            "stage_seconds": {k: round(v, 4) for k, v in self.stage_seconds.items()},
            "rule_hotspots": [
                {"rule": r, "seconds": round(s, 5), "matches": n}
                for r, s, n in self.rule_hotspots
            ],
            "peak_memory_mb": round(self.peak_memory_mb, 2),
            "matched_expectation": self.matched_expectation,
            "by_severity": self.by_severity,
        }

    def render(self) -> str:
        lines = [
            "性能基准测试结果",
            "=" * 46,
            f"语料规模        {self.documents} 份文档 / {self.bytes_total / 1024:.1f} KB",
            f"注入凭据        {self.credentials_expected} 条（伪造值）",
            f"实际命中        {self.findings} 条",
            f"总耗时          {self.elapsed_seconds:.3f} 秒",
            f"吞吐量          {self.docs_per_second:.1f} 文档/秒  |  {self.mb_per_second:.2f} MB/秒",
            f"峰值内存        {self.peak_memory_mb:.2f} MB",
        ]
        if self.by_severity:
            lines.append("命中按风险等级：" + "  ".join(
                f"{k} {v}" for k, v in self.by_severity.items()
            ))
        lines += [
            "",
            "各阶段耗时：",
        ]
        for stage, seconds in self.stage_seconds.items():
            share = seconds / max(self.elapsed_seconds, 1e-9) * 100
            lines.append(f"  {stage:<16s} {seconds * 1000:8.2f} ms  ({share:5.1f}%)")

        if self.rule_hotspots:
            lines.append("")
            lines.append("耗时最高的规则（Top 10）：")
            for rule, seconds, matches in self.rule_hotspots[:10]:
                lines.append(f"  {rule:<34s} {seconds * 1000:7.2f} ms  命中 {matches} 次")
        return "\n".join(lines)


def generate_corpus(
    count: int = 500, noise_ratio: float = 0.25
) -> tuple[list[Document], int]:
    """生成合成语料，返回 (文档列表, 预期凭据条数)。

    固定随机种子 → 结果可复现；凭据全部为伪造值。
    """
    rng = random.Random(RNG_SEED)
    alnum = string.ascii_letters + string.digits
    hexs = "0123456789abcdef"

    def rand(n: int, pool: str = alnum) -> str:
        return "".join(rng.choice(pool) for _ in range(n))

    docs: list[Document] = []
    expected = 0
    for i in range(count):
        if rng.random() < noise_ratio:
            text = NOISE_TEMPLATE
            docs.append(_doc(i, text, f"docs/notes_{i}.md"))
            continue

        extra_lines = [f"API_KEY_{j}={rand(32)}" for j in range(rng.randint(0, 3))]
        text = TEMPLATE.format(
            ak=rand(16, string.ascii_uppercase + string.digits),
            sk=rand(40),
            host=rng.randint(1, 250),
            dbpass=rand(12),
            redispass=rand(20),
            jwt=rand(48),
            extra="\n".join(extra_lines),
        )
        docs.append(_doc(i, text, f"service_{i}/.env"))
        expected += 5 + len(extra_lines)
    return docs, expected


def _doc(index: int, text: str, path: str) -> Document:
    return Document(
        doc_id=f"bench:{index}",
        source="benchmark",
        url=f"https://example.invalid/{path}",
        text=text,
        path_hint=path,
        metadata={"source_category": "本地与企业内网"},
    )


def run_benchmark(
    rule_engine: RuleEngine,
    *,
    documents: int = 500,
    noise_ratio: float = 0.25,
    profile_rules: bool = True,
    pipeline: DetectionPipeline | None = None,
) -> BenchmarkResult:
    """执行基准测试。"""
    corpus, expected = generate_corpus(documents, noise_ratio)
    total_bytes = sum(len(doc.text.encode("utf-8")) for doc in corpus)

    engine = pipeline or DetectionPipeline(rule_engine, hmac_salt="benchmark-salt")

    tracemalloc.start()
    started = time.perf_counter()
    result = engine.run(corpus)
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    stage_seconds = _stage_breakdown(engine, corpus, elapsed)
    hotspots = _rule_hotspots(rule_engine, corpus) if profile_rules else []

    return BenchmarkResult(
        documents=len(corpus),
        bytes_total=total_bytes,
        credentials_expected=expected,
        findings=len(result.findings),
        elapsed_seconds=elapsed,
        docs_per_second=len(corpus) / max(elapsed, 1e-9),
        mb_per_second=(total_bytes / 1024 / 1024) / max(elapsed, 1e-9),
        stage_seconds=stage_seconds,
        rule_hotspots=hotspots,
        peak_memory_mb=peak / 1024 / 1024,
        matched_expectation=len(result.findings) >= expected * 0.8,
        by_severity=_severity_breakdown(result.findings),
    )


def _severity_breakdown(findings: Iterable[Any]) -> dict[str, int]:
    """统计命中按风险等级的分布（严重 → 提示）。"""
    order = ("critical", "high", "medium", "low", "info")
    counts: dict[str, int] = {sev: 0 for sev in order}
    for finding in findings:
        severity = getattr(finding, "severity", "medium")
        counts[severity] = counts.get(severity, 0) + 1
    return {k: v for k, v in counts.items() if v}


def _stage_breakdown(
    engine: DetectionPipeline, corpus: list[Document], total: float
) -> dict[str, float]:
    """分别测量各阶段的累计耗时。"""
    import re

    structured = rule = entropy = scoring = 0.0
    for doc in corpus:
        t0 = time.perf_counter()
        structured_cands = engine.structured.parse(doc.text, doc.path_hint)
        t1 = time.perf_counter()
        rule_cands = engine.rule_engine.scan(doc.text)
        t2 = time.perf_counter()
        entropy_cands = engine.entropy.scan(doc.text)
        t3 = time.perf_counter()
        merged = engine._merge_same_span(structured_cands + rule_cands + entropy_cands)
        for cand in merged:
            engine.scorer.score(cand, doc.text, doc.path_hint)
        t4 = time.perf_counter()

        structured += t1 - t0
        rule += t2 - t1
        entropy += t3 - t2
        scoring += t4 - t3

    accounted = structured + rule + entropy + scoring
    return {
        "结构化解析": structured,
        "规则匹配": rule,
        "熵检测": entropy,
        "概率评分": scoring,
        "其他（去重/存储）": max(total - accounted, 0.0),
    }


def _rule_hotspots(
    rule_engine: RuleEngine, corpus: list[Document], top: int = 15
) -> list[tuple[str, float, int]]:
    """逐条规则计时，找出最耗时的规则。"""
    import re

    timings: dict[str, list[float]] = {}
    counts: dict[str, int] = {}
    text = "\n".join(doc.text for doc in corpus)
    for rule in rule_engine.rules:
        pattern = rule.compiled
        start = time.perf_counter()
        matches = sum(1 for _ in pattern.finditer(text))
        cost = time.perf_counter() - start
        timings.setdefault(rule.id, []).append(cost)
        counts[rule.id] = counts.get(rule.id, 0) + matches

    ranked = sorted(
        ((rid, sum(v), counts.get(rid, 0)) for rid, v in timings.items()),
        key=lambda item: -item[1],
    )
    return ranked[:top]


__all__ = ["BenchmarkResult", "generate_corpus", "run_benchmark"]
