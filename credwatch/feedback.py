"""误报反馈闭环与权重自适应。

这是让系统"越用越准"的机制，也是与"写死一份规则库"的工具最本质的区别。

完整闭环：

    标注（确认 / 误报）
        ↓  特征向量随标注一起入库
    校准（逻辑回归 + 专家先验锚定）
        ↓  产出新的评分权重 config/scoring_weights.json
    生效（下次扫描自动加载）
        ↓
    抑制（已确认的误报指纹不再重复上报）
        ↓
    复核（重扫确认修复结果）

关键点：**误报不再只是"加一条白名单"**。白名单只能压掉那一条，
而权重校准改变的是判定边界本身——下次遇到同类写法就会自动判得更准。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import Settings
from .detectors.scoring import (
    CalibrationReport,
    FeatureVector,
    ProbabilityScorer,
    calibrate,
)
from .storage import Storage


@dataclass
class FeedbackOutcome:
    """一次标注的结果。"""

    fingerprint: str
    label: int
    found: bool
    message: str

    def to_record(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "label": self.label,
            "found": self.found,
            "message": self.message,
        }


class FeedbackLoop:
    """把标注、校准、抑制、复核四件事串起来。"""

    def __init__(self, settings: Settings, storage: Storage | None = None) -> None:
        self.settings = settings
        self.storage = storage or Storage(settings.db_path)

    # ------------------------------------------------------------------ 标注

    def label(
        self, fingerprint: str, is_false_positive: bool, note: str = ""
    ) -> FeedbackOutcome:
        """标注一条发现。

        指纹支持前缀匹配（报告中展示的是前 16 位），方便直接复制粘贴。
        """
        matches = self._resolve(fingerprint)
        if not matches:
            return FeedbackOutcome(
                fingerprint, 0 if is_false_positive else 1, False,
                f"未在数据库中匹配到指纹 `{fingerprint}`",
            )
        if len(matches) > 1:
            return FeedbackOutcome(
                fingerprint, 0 if is_false_positive else 1, False,
                f"指纹前缀匹配到 {len(matches)} 条记录，请提供更长的前缀",
            )

        cred = matches[0]
        samples = dict(
            (row["fingerprint"], row) for row in self.storage.feedback()
        )
        existing = samples.get(cred["fingerprint"])

        # 从最近一次扫描的暴露记录里取回特征向量，供权重校准使用
        vector = self._feature_vector_of(cred["fingerprint"], existing)
        self.storage.record_feedback(
            cred["fingerprint"],
            label=0 if is_false_positive else 1,
            note=note,
            rule_id=cred.get("rule_id") or "",
            kind=cred.get("kind") or "",
            feature_vector=vector,
        )
        verb = "误报" if is_false_positive else "真实泄露"
        detail = f"，特征向量{'已' if vector else '未'}记录" if vector is not None else ""
        return FeedbackOutcome(
            cred["fingerprint"],
            0 if is_false_positive else 1,
            True,
            f"已标注为{verb}：{cred.get('masked')}（{cred.get('rule_name')}）{detail}",
        )

    def _resolve(self, fingerprint: str) -> list[dict]:
        fp = fingerprint.strip().lower()
        if len(fp) >= 64:
            return [c for c in self.storage.credentials() if c["fingerprint"] == fp]
        return [c for c in self.storage.credentials() if c["fingerprint"].startswith(fp)]

    def _feature_vector_of(
        self, fingerprint: str, existing: dict | None
    ) -> dict[str, float]:
        """取回该凭据在扫描时记录的特征向量。

        特征向量随扫描结果一起入库，因此标注时可以直接取用——
        不需要重新解析原始文本（原始内容早已被丢弃，这也是"不保留
        第三方内容副本"设计的一个副产品）。
        """
        import json

        for source in (existing, self._credential_row(fingerprint)):
            if not source:
                continue
            raw = source.get("feature_vector_json")
            if not raw:
                continue
            try:
                vector = json.loads(raw)
            except (ValueError, TypeError):
                continue
            if vector:
                return {str(k): float(v) for k, v in vector.items()}
        return {}

    def _credential_row(self, fingerprint: str) -> dict | None:
        for cred in self.storage.credentials():
            if cred["fingerprint"] == fingerprint:
                return cred
        return None

    # ------------------------------------------------------------------ 校准

    def calibrate_weights(self, save: bool = True) -> CalibrationReport | None:
        """用已标注样本校准评分权重。样本不足时返回 None（保持专家先验）。"""
        raw = self.storage.feedback_samples()
        samples = [(FeatureVector(values=v), label) for v, label in raw]
        report = calibrate(samples)
        if report is None:
            return None
        if save:
            report.scorer.save(self.settings.scoring_weights_file)
        return report

    # ------------------------------------------------------------------ 抑制

    def suppressed(self) -> set[str]:
        return self.storage.false_positive_fingerprints()

    def confirmed(self) -> set[str]:
        return self.storage.confirmed_fingerprints()

    def apply_suppression(self, findings: list[Any]) -> tuple[list[Any], int]:
        """过滤掉已标注为误报的发现，返回 (保留项, 过滤数量)。"""
        suppressed = self.suppressed()
        if not suppressed:
            return findings, 0
        kept = [f for f in findings if f.fingerprint not in suppressed]
        return kept, len(findings) - len(kept)

    # ------------------------------------------------------------------ 复核

    def verify_remediation(self, fingerprint_prefix: str = "") -> dict[str, Any]:
        """复核修复结果：确认被标注的凭据是否还出现在最近一次扫描中。

        这是"处置闭环"的最后一环——很多工具报完就结束，
        无法回答运维最关心的问题："我改完了，还在吗？"
        """
        targets = (
            self._resolve(fingerprint_prefix) if fingerprint_prefix
            else self.storage.credentials()
        )
        confirmed = self.confirmed()
        still_present: list[dict] = []
        resolved: list[dict] = []
        for cred in targets:
            if confirmed and cred["fingerprint"] not in confirmed:
                continue
            exposures = self.storage.exposures_for(cred["fingerprint"])
            record = {
                "fingerprint": cred["fingerprint"][:16],
                "masked": cred["masked"],
                "rule_name": cred["rule_name"],
                "exposures": len(exposures),
            }
            (still_present if exposures else resolved).append(record)
        return {
            "checked": len(targets),
            "still_present": still_present,
            "resolved": resolved,
            "summary": (
                f"复核 {len(targets)} 条：仍在暴露 {len(still_present)} 条，"
                f"已消除 {len(resolved)} 条"
            ),
        }

    # ------------------------------------------------------------------ 概览

    def stats(self) -> dict[str, Any]:
        summary = self.storage.feedback_summary()
        summary["suppressed_fingerprints"] = len(self.suppressed())
        scorer = ProbabilityScorer.load_or_prior(self.settings.scoring_weights_file)
        summary["weights_calibrated"] = scorer.calibrated
        summary["weights_samples"] = scorer.sample_count
        return summary


__all__ = ["FeedbackLoop", "FeedbackOutcome"]
