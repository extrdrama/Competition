"""调度层：把采集 → 检测 → 验证 → 去重 → 归属 → 落盘串成一次完整扫描。

增量策略：
- 每个渠道维护独立游标（cursor），记录已处理的 ID、内容哈希、查询完成情况；
- 支持"只扫新增"（增量）与"全量重扫"两种模式；
- 游标持久化在 SQLite，进程重启后继续，不会重复上报同一条凭据。
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

from .attribution import AttributionEngine
from .config import Settings, load_sources_config
from .context_extract import enrich_with_context
from .correlation import PairCorrelator
from .dedup import Deduplicator
from .detectors import DetectionPipeline, ProbabilityScorer, RuleEngine
from .models import Document, Finding, ScanStats, utcnow
from .sources import load_all_sources, registry
from .storage import Storage
from .validators import make_validator

logger = logging.getLogger("credwatch.scheduler")

TOP_FINDINGS_LIMIT = 20

# 排序用的风险等级权重
_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class SourceProgress:
    """单个渠道的执行情况。"""

    name: str
    documents: int = 0
    findings: int = 0
    error: str = ""
    duration_seconds: float = 0.0

    def to_record(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "documents": self.documents,
            "findings": self.findings,
            "error": self.error,
            "duration_seconds": round(self.duration_seconds, 3),
        }


@dataclass
class _SourceOutcome:
    """单个渠道的执行结果（内部结构，用于并发汇总）。"""

    name: str
    progress: SourceProgress
    findings: list[Finding]
    stats: ScanStats
    cursor: dict[str, Any]
    documents: dict[str, str] = field(default_factory=dict)


@dataclass
class ScanResult:
    """一次扫描的完整结果。"""

    stats: ScanStats
    sources: list[SourceProgress] = field(default_factory=list)
    clusters: list[Any] = field(default_factory=list)
    attributions: dict[str, Any] = field(default_factory=dict)
    credential_stats: dict[str, Any] = field(default_factory=dict)
    mttd: dict[str, Any] = field(default_factory=dict)
    storage_summary: dict[str, Any] = field(default_factory=dict)
    scan_id: int | None = None
    top_findings: list[Finding] = field(default_factory=list)
    correlation: Any = None

    def to_record(self) -> dict[str, Any]:
        return {
            "stats": self.stats.to_record(),
            "sources": [s.to_record() for s in self.sources],
            "credential_stats": self.credential_stats,
            "mttd": self.mttd,
            "storage_summary": self.storage_summary,
            "scan_id": self.scan_id,
            "correlation": self.correlation.to_record() if self.correlation else None,
            "clusters": [c.to_record() for c in self.clusters],
            "attributions": {
                fp: (attr.to_record() if hasattr(attr, "to_record") else attr)
                for fp, attr in self.attributions.items()
            },
        }


class ScanEngine:
    """扫描引擎。CLI 与看板都通过它驱动，保证行为一致、结果可复现。"""

    def __init__(
        self,
        settings: Settings,
        sources_config: dict[str, Any] | None = None,
        storage: Storage | None = None,
    ) -> None:
        self.settings = settings
        self.settings.ensure_dirs()
        self.sources_config = sources_config or load_sources_config(settings.sources_file)
        self.storage = storage or Storage(settings.db_path)
        self.rule_engine = RuleEngine.from_dir(settings.rules_dir)
        self.attribution = AttributionEngine()

    # ------------------------------------------------------------------ 渠道

    def available_sources(self) -> dict[str, Any]:
        return {name: registry.get(name).meta for name in registry.names()}

    def _build_pipeline(self, validator: Any = None) -> DetectionPipeline:
        # 评分权重优先使用"经标注样本校准"的版本，缺失时回退到专家先验
        scorer = ProbabilityScorer.load_or_prior(self.settings.scoring_weights_file)
        if scorer.calibrated:
            logger.info("已加载校准后的评分权重（样本 %s 条）", scorer.sample_count)
        return DetectionPipeline(
            self.rule_engine,
            scorer=scorer,
            validator=validator,
            hmac_salt=self.settings.hmac_salt or None,
        )

    @staticmethod
    def _iter_documents(
        adapter: Any, cursor: dict[str, Any]
    ) -> Iterator[Document]:
        """产出文档，并就地更新 cursor（由调用方负责持久化）。"""
        for raw in adapter.discover(cursor):
            for doc in adapter.normalize(raw):
                doc.metadata.setdefault("source_category", adapter.meta.category)
                doc.metadata.setdefault("source_label", adapter.meta.label)
                yield doc
            new_cursor = adapter.next_cursor(raw)
            if new_cursor:
                cursor.update(new_cursor)

    # ------------------------------------------------------------------ 主流程

    def run(
        self,
        source_names: Iterable[str] | None = None,
        *,
        full_rescan: bool = False,
        max_documents: int | None = None,
        workers: int = 1,
    ) -> ScanResult:
        """执行一轮扫描。

        Args:
            source_names: 只扫描指定渠道；None 表示扫描配置中已启用的全部渠道。
            full_rescan: 忽略游标做全量重扫。
            max_documents: 单渠道最多处理的文档数（用于快速验证）。
            workers: 渠道并发数。默认 1（顺序执行），保证结果完全可复现；
                设为 >1 可显著缩短多渠道路径的总耗时，各渠道内部仍严格限速。
        """
        adapters = load_all_sources(self.settings, self.sources_config.get("sources", {}))
        if source_names:
            wanted = {s for s in source_names}
            adapters = {k: v for k, v in adapters.items() if k in wanted}

        if not adapters:
            logger.warning("没有可用的渠道，请检查 config/sources.yaml 与 .env 配置")

        # 验证器只建一次：限速护栏必须是全局的，不能每个渠道一份
        validator = make_validator(self.settings)

        tasks = [
            (name, adapter, {} if full_rescan else self.storage.get_cursor(name))
            for name, adapter in adapters.items()
        ]

        outcomes: list[_SourceOutcome] = []
        if workers > 1 and len(tasks) > 1:
            logger.info("启用 %s 个并发渠道", workers)
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [
                    pool.submit(self._scan_source, name, adapter, cursor, validator, max_documents)
                    for name, adapter, cursor in tasks
                ]
                for future in as_completed(futures):
                    outcomes.append(future.result())
            # 并发结果按渠道名排序，保证输出顺序稳定（可复现）
            outcomes.sort(key=lambda o: o.name)
        else:
            for name, adapter, cursor in tasks:
                outcomes.append(
                    self._scan_source(name, adapter, cursor, validator, max_documents)
                )

        # ---- 汇总（顺序执行，避免并发写库） ----
        all_stats = ScanStats(started_at=utcnow())
        all_findings: list[Finding] = []
        progress: list[SourceProgress] = []
        doc_text_by_url: dict[str, str] = {}
        for outcome in outcomes:
            all_findings.extend(outcome.findings)
            _merge_stats(all_stats, outcome.stats)
            progress.append(outcome.progress)
            doc_text_by_url.update(outcome.documents)
            self.storage.set_cursor(
                outcome.name,
                {
                    **outcome.cursor,
                    "last_run": utcnow().isoformat(),
                    "documents": outcome.progress.documents,
                    "findings": outcome.progress.findings,
                },
            )

        # ---- 组合风险分析：必须在去重之前跑，因为配对依赖"每一处暴露位置" ----
        # 单条凭据无法利用，成对出现才构成完整凭据，这一步会相应提升风险等级
        correlation = PairCorrelator().correlate(all_findings)
        all_stats.stage_counts["5_凭据对关联"] = len(correlation.pairs)

        # ---- 上下文结构化提取：把"发现口令"升级为"知道它能访问什么" ----
        # 产出形如 {"service":"MySQL","host":"10.20.30.41","port":"3306",
        #           "username":"app_rw","database":"production"} 的敏感信息对
        context_extracted = enrich_with_context(all_findings, doc_text_by_url)
        all_stats.stage_counts["6_上下文提取"] = context_extracted

        aggregator = Deduplicator()
        aggregator.add_many(all_findings)
        clusters = aggregator.correlate()
        attributions = {
            c.fingerprint: self.attribution.attribute_from_cluster(c) for c in clusters
        }
        all_stats.finished_at = utcnow()

        scan_id = self.storage.save_scan(all_stats.to_record())
        self.storage.upsert_clusters(clusters, attributions, scan_id)
        if correlation.pairs:
            self.storage.upsert_pairs(correlation.pairs)

        top = sorted(
            all_findings,
            key=lambda f: (f.validated is True, _SEV_ORDER.get(f.severity, 0), f.confidence),
            reverse=True,
        )[:TOP_FINDINGS_LIMIT]

        return ScanResult(
            stats=all_stats,
            sources=progress,
            clusters=clusters,
            attributions=attributions,
            credential_stats=aggregator.statistics(),
            mttd=self.storage.mttd_stats(),
            storage_summary=self.storage.summary(),
            scan_id=scan_id,
            top_findings=top,
            correlation=correlation,
        )

    # ------------------------------------------------------------------ 单渠道

    def _scan_source(
        self,
        name: str,
        adapter: Any,
        cursor: dict[str, Any],
        validator: Any,
        max_documents: int | None,
    ) -> "_SourceOutcome":
        """扫描单个渠道。可在独立线程中执行。

        每个渠道使用独立的流水线实例（互不共享状态），因此天然线程安全；
        渠道内部依然通过各自的限速器控制频率。
        """
        prog = SourceProgress(name=name)
        stats = ScanStats()
        findings: list[Finding] = []
        started = time.monotonic()
        try:
            batch: list[Document] = []
            for doc in self._iter_documents(adapter, cursor):
                batch.append(doc)
                if max_documents and len(batch) >= max_documents:
                    break
            prog.documents = len(batch)

            if batch:
                pipeline = self._build_pipeline(validator)
                result = pipeline.run(batch)
                findings = result.findings
                stats = result.stats
                prog.findings = len(findings)
        except Exception as exc:  # noqa: BLE001 - 单渠道失败不应中断整体扫描
            prog.error = f"{type(exc).__name__}: {exc}"
            logger.warning("渠道 %s 扫描失败：%s", name, prog.error)
        finally:
            prog.duration_seconds = time.monotonic() - started
            try:
                adapter.close()
            except Exception:  # noqa: BLE001
                pass
        return _SourceOutcome(
            name=name,
            progress=prog,
            findings=findings,
            stats=stats,
            cursor=cursor,
            documents={d.url: d.text for d in batch},
        )

    # ------------------------------------------------------------------ 常驻

    def run_forever(self, interval_seconds: int = 600) -> None:
        """常驻模式：按固定间隔循环扫描，维持分钟级发现延迟。"""
        logger.info("进入常驻扫描模式，间隔 %s 秒", interval_seconds)
        while True:
            started = time.monotonic()
            try:
                result = self.run()
                logger.info(
                    "本轮完成：文档 %s 份，去重后凭据 %s 条",
                    result.stats.documents_scanned,
                    len(result.clusters),
                )
            except KeyboardInterrupt:
                logger.info("收到中断信号，退出常驻模式")
                return
            except Exception as exc:  # noqa: BLE001
                logger.error("本轮扫描异常：%s", exc)
            elapsed = time.monotonic() - started
            time.sleep(max(5.0, interval_seconds - elapsed))


def _merge_stats(target: ScanStats, source: ScanStats) -> None:
    target.documents_scanned += source.documents_scanned
    target.bytes_scanned += source.bytes_scanned
    target.candidates += source.candidates
    target.findings += source.findings
    target.validated += source.validated
    for key, value in source.stage_counts.items():
        target.stage_counts[key] = target.stage_counts.get(key, 0) + value
