"""检测层总装：四层收敛流水线。

    全量内容 ──①规则/结构化/熵命中──▶ 候选
             ──②占位符与关键词过滤──▶ 有效候选
             ──③可解释概率评分截断──▶ 高置信度发现
             ──④只读活性验证──▶ 已确认泄露

每一层都会记录通过数量，既用于报告，也用于答辩时展示收敛效果。
置信度由 `scoring.ProbabilityScorer` 输出，语义是
"该命中为真实凭据的概率"，而不是一个无单位的分数。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable

from ..models import Document, Evidence, Finding, ScanStats, fingerprint, mask_secret, max_severity, utcnow
from .entropy import EntropyConfig, EntropyDetector
from .rule_engine import Candidate, RuleEngine
from .scoring import ProbabilityScorer
from .structured import StructuredParser

# 概率阈值：结构化与规则精确度高，阈值可放宽；
# 熵检测天然噪声大，必须依赖强上下文才采纳。
DETECTOR_THRESHOLDS: dict[str, float] = {
    "structured": 0.50,
    "rule": 0.50,
    "entropy": 0.70,
}

# 熵检测的"佐证门控"。
# 这是**在真实 GitHub 公开数据上实测后新增的**：仅凭"熵高 + 长度合理"会在
# 真实内容中命中大量包名（com/xxx_x86）、构建标识（PATCH_xxx）、随机哈希等
# 非凭据串，概率都能到 0.83。熵检测本质只是"这里可能有个密钥"的**假设**，
# 必须有下述任一佐证才允许成为发现，否则一律拦截。
ENTROPY_CORROBORATION_FEATURES: tuple[str, ...] = (
    "sensitive_identifier",   # 左侧是敏感变量名/配置键
    "known_prefix",           # 值本身带已知凭据前缀
    "sensitive_path",         # 位于 .env / credentials 等敏感文件
)

# 检测器优先级：同一位置多条命中时保留"信息量最大"的那一条。
# 规则命中带有具体的凭据类型（如"阿里云 AccessKey ID"）与配套验证器，
# 比结构化解折出的通用"dotenv 凭据变量"更有价值，因此规则优先。
# 结构化解析的价值在于覆盖规则无法表达的结构（k8s Secret 的 Base64 解码等），
# 而不是抢规则的活。
DETECTOR_PRIORITY: dict[str, int] = {"rule": 3, "structured": 2, "entropy": 1}

ValidatorFn = Callable[[Finding], tuple[bool | None, str]]


# 单个文档内、同一条规则允许上报的最大发现数。
# 超出通常意味着该文件是数据导出/字典/批量 dump，而不是一处配置泄露。
MAX_FINDINGS_PER_RULE_PER_DOC = 50


def _apply_flood_control(
    doc_findings: list[Finding], stage_counts: dict[str, int]
) -> list[Finding]:
    """按 (文档, 规则) 抑制命中风暴，返回保留的发现。"""
    by_rule: dict[str, list[Finding]] = {}
    for finding in doc_findings:
        by_rule.setdefault(finding.rule_id, []).append(finding)

    kept: list[Finding] = []
    suppressed_total = 0
    for rule_id, group in by_rule.items():
        if len(group) <= MAX_FINDINGS_PER_RULE_PER_DOC:
            kept.extend(group)
            continue
        # 保留置信度最高的前 N 条，其余合并计数
        group.sort(key=lambda f: f.confidence, reverse=True)
        keep = group[:MAX_FINDINGS_PER_RULE_PER_DOC]
        overflow = len(group) - len(keep)
        suppressed_total += overflow
        keep[0].metadata["flood_suppressed"] = overflow
        keep[0].metadata["flood_note"] = (
            f"该文档内规则 {rule_id} 命中 {len(group)} 条，"
            f"疑似数据导出/字典文件，已按置信度保留 {len(keep)} 条并合并计数"
        )
        kept.extend(keep)

    if suppressed_total:
        stage_counts["命中风暴抑制"] = (
            stage_counts.get("命中风暴抑制", 0) + suppressed_total
        )
    return kept


def _rank(candidate: Candidate) -> tuple[int, int]:
    """候选的"具体性"排序键：(检测器优先级, 规则特异性)。"""
    return (
        DETECTOR_PRIORITY.get(candidate.detector, 0),
        candidate.rule_specificity,
    )


@dataclass
class PipelineResult:
    findings: list[Finding]
    stats: ScanStats
    rejected: list[dict] = field(default_factory=list)


class DetectionPipeline:
    """把规则、熵、结构化解析、可解释评分串成一条收敛流水线。"""

    def __init__(
        self,
        rule_engine: RuleEngine,
        *,
        entropy_config: EntropyConfig | None = None,
        scorer: ProbabilityScorer | None = None,
        structured_parser: StructuredParser | None = None,
        validator: ValidatorFn | None = None,
        hmac_salt: str | None = None,
        threshold_overrides: dict[str, float] | None = None,
    ) -> None:
        self.rule_engine = rule_engine
        self.entropy = EntropyDetector(entropy_config)
        self.scorer = scorer or ProbabilityScorer()
        self.structured = structured_parser or StructuredParser()
        self.validator = validator
        self.hmac_salt = hmac_salt
        self.thresholds = dict(DETECTOR_THRESHOLDS)
        if threshold_overrides:
            self.thresholds.update(threshold_overrides)

    # ------------------------------------------------------------------ 主流程

    def run(self, documents: Iterable[Document]) -> PipelineResult:
        stats = ScanStats()
        findings: list[Finding] = []
        rejected: list[dict] = []
        seen: set[tuple[str, str]] = set()

        for doc in documents:
            stats.documents_scanned += 1
            stats.bytes_scanned += len(doc.text.encode("utf-8", errors="ignore"))

            candidates = self._collect(doc)
            stats.stage_counts["1_格式命中候选"] = (
                stats.stage_counts.get("1_格式命中候选", 0) + len(candidates)
            )

            doc_findings: list[Finding] = []
            rejected_doc: list[dict] = []

            for cand in self._merge_same_span(candidates):
                probability, explanation = self.scorer.score(cand, doc.text, doc.path_hint)
                threshold = self.thresholds.get(cand.detector, 0.6)

                if probability < threshold:
                    rejected_doc.append(
                        {
                            "doc": doc.url,
                            "rule": cand.rule_id,
                            "detector": cand.detector,
                            "probability": probability,
                            "threshold": threshold,
                            "reason": "判定为真实凭据的概率低于阈值",
                            "explanation": explanation.summary(),
                        }
                    )
                    continue

                # 熵检测必须有情证佐证（真实数据实测教训，见 ENTROPY_CORROBORATION_FEATURES）
                if cand.detector == "entropy":
                    values = explanation.values
                    if not any(values.get(f) for f in ENTROPY_CORROBORATION_FEATURES):
                        rejected.append(
                            {
                                "doc": doc.url,
                                "rule": cand.rule_id,
                                "detector": cand.detector,
                                "probability": probability,
                                "threshold": threshold,
                                "reason": "熵命中缺乏佐证（无敏感标识符/已知前缀/敏感文件）",
                                "explanation": explanation.summary(),
                            }
                        )
                        continue

                stats.stage_counts["2_上下文确认"] = (
                    stats.stage_counts.get("2_上下文确认", 0) + 1
                )

                fp = fingerprint(cand.secret, self.hmac_salt)
                # 同一凭据的同一处暴露位置只上报一次；
                # 但同一凭据出现在不同文件/渠道时**必须分别保留**，
                # 这样才能聚合成"1 个凭据、N 个暴露点"，而不是虚报成 N 个凭据。
                exposure_key = (fp, doc.url)
                if exposure_key in seen:
                    continue
                seen.add(exposure_key)

                finding = Finding(
                    rule_id=cand.rule_id,
                    rule_name=cand.rule_name,
                    category=cand.category,
                    severity=cand.severity,
                    confidence=probability,
                    detector=cand.detector,
                    masked=mask_secret(cand.secret),
                    fingerprint=fp,
                    evidence=Evidence(
                        url=doc.url,
                        path_hint=doc.path_hint or doc.url,
                        line_no=cand.line_no,
                        snippet=cand.snippet,
                        published_at=doc.published_at,
                        discovered_at=doc.discovered_at,
                    ),
                    source=doc.source,
                    metadata={
                        "kind": cand.kind,
                        "rule_validator": cand.validator,
                        # 可解释性：保留逐特征贡献，答辩时可逐项讲解判定依据
                        "score_explanation": explanation.to_record(),
                        "feature_vector": dict(explanation.values),
                        # 渠道类别必须从 Document 透传下来，否则跨渠道关联
                        # 会退化成"不同规则名也算跨渠道"，导致误判
                        "source_category": doc.metadata.get("source_category", ""),
                        "source_label": doc.metadata.get("source_label", ""),
                        **{k: v for k, v in cand.metadata.items() if k != "window"},
                    },
                    raw=cand.secret,
                )

                if self.validator is not None:
                    ok, note = self.validator(finding)
                    finding.validated = ok
                    finding.validation_note = note
                    if ok:
                        finding.severity = max_severity(finding.severity, "high")

                doc_findings.append(finding)

            # ---- 命中风暴抑制 ----
            # 真实数据实测教训：一个 Gist 里可能塞着几百条 `"key": "<base64>"`，
            # 若逐条上报会把报告淹没成噪声，也让人无法判断"到底该看哪一条"。
            # 因此按 (文档, 规则) 设上限：超出部分合并计数，
            # 并在保留的首条上标注被抑制的数量。
            kept = _apply_flood_control(doc_findings, stats.stage_counts)
            findings.extend(kept)

            rejected.extend(rejected_doc)

        stats.candidates = stats.stage_counts.get("1_格式命中候选", 0)
        stats.findings = len(findings)
        stats.validated = sum(1 for f in findings if f.validated)
        stats.stage_counts["3_去重后发现"] = len(findings)
        if self.validator is not None:
            stats.stage_counts["4_活性验证通过"] = stats.validated
        stats.finished_at = utcnow()
        return PipelineResult(findings=findings, stats=stats, rejected=rejected)

    # ------------------------------------------------------------------ 内部

    def _collect(self, doc: Document) -> list[Candidate]:
        """汇聚三个检测器的候选。"""
        candidates: list[Candidate] = []
        candidates.extend(self.structured.parse(doc.text, doc.path_hint))
        candidates.extend(self.rule_engine.scan(doc.text))
        candidates.extend(self.entropy.scan(doc.text))
        # 附上路径信息，供上下文评分与报告使用
        for c in candidates:
            c.metadata.setdefault("path_hint", doc.path_hint)
        return candidates

    @staticmethod
    def _merge_same_span(candidates: list[Candidate]) -> list[Candidate]:
        """合并**位置重叠**的候选，只保留"最具体"的那一条。

        例如同一段 PEM 私钥，既会被"私钥头"格式规则命中，也会被结构化解析
        命中；同一行 `AWS_SECRET_ACCESS_KEY=xxx`，既会被"AWS Secret"具体规则
        命中，也会被"变量名含 SECRET"的通用兜底规则命中。

        判定顺序（前一项相同才看后一项）：
          1. 检测器优先级：规则 > 结构化 > 熵
          2. 规则特异性：具体格式（AKIA/glpat-/AKID 等）> 通用兜底（变量名匹配）

        这样保证胜出的是**信息量最大**的那条：给出准确凭据类型，并绑定只读
        活性验证器。同时因为不再依赖候选的输入顺序，结果是可复现的。
        """
        if not candidates:
            return []
        ordered = sorted(candidates, key=lambda c: (c.span[0], -(c.span[1] - c.span[0])))
        merged: list[Candidate] = []
        for cand in ordered:
            if not merged:
                merged.append(cand)
                continue
            last = merged[-1]
            # 位置有重叠 → 视为同一处命中，只留更具体的那条
            if cand.span[0] < last.span[1]:
                if _rank(cand) > _rank(last):
                    merged[-1] = cand
                continue
            merged.append(cand)
        return merged

