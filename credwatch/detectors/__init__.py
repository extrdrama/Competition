"""检测层：规则引擎、熵检测、结构化解析、可解释评分与收敛流水线。

模块分工：
- `signals.py`    上下文信号正则库（什么线索说明它可能是真凭据）
- `rule_engine.py` 声明式规则引擎 + 两级占位符过滤
- `entropy.py`     香农熵兜底检测
- `structured.py`  配置文件语法级解析
- `scoring.py`     特征向量 + 可解释概率评分 + 权重自动校准
- `pipeline.py`    把上述组件串成四层收敛流水线
"""

from .entropy import EntropyConfig, EntropyDetector, shannon_entropy
from .pipeline import DetectionPipeline, PipelineResult
from .rule_engine import Candidate, Rule, RuleEngine, is_placeholder
from .scoring import (
    FEATURE_LABELS,
    PRIOR_BIAS,
    PRIOR_WEIGHTS,
    CalibrationReport,
    FeatureVector,
    ProbabilityScorer,
    ScoreExplanation,
    calibrate,
    extract_features,
)
from .signals import context_slice, left_slice
from .structured import StructuredParser

__all__ = [
    "CalibrationReport",
    "Candidate",
    "DetectionPipeline",
    "EntropyConfig",
    "EntropyDetector",
    "FEATURE_LABELS",
    "FeatureVector",
    "PRIOR_BIAS",
    "PRIOR_WEIGHTS",
    "PipelineResult",
    "ProbabilityScorer",
    "Rule",
    "RuleEngine",
    "ScoreExplanation",
    "StructuredParser",
    "calibrate",
    "context_slice",
    "extract_features",
    "is_placeholder",
    "left_slice",
    "shannon_entropy",
]
