"""检测层第 3 环：可解释概率评分。

与"硬编码加权求和"的区别，也是本模块存在的理由：

1. **输出的是概率而不是分数**。用 sigmoid(w·x + b) 把特征线性组合映射为
   0~1 的概率，可以直接读作"该命中是真实泄露的概率"，阈值有明确语义。

2. **每条判定都能解释**。返回每个特征对最终结果的贡献量
   （`feature × weight`），排序输出。评审问"为什么这条判为真"，可以逐项列出来，
   而不是只能说"因为分数够了"。

3. **权重可以从标注样本自动校准**。初始权重是安全工程师的经验先验；
   有了人工标注（确认/误报）后，用带 L2 正则的逻辑回归重新拟合，
   并用专家先验做初始化与锚定，避免小样本过拟合。

正是这第三点让系统具备了"越用越准"的能力：误报反馈不再是简单加个白名单，
而是真的调整了判定边界。
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .rule_engine import Candidate

# --------------------------------------------------------------------- 特征定义

# 特征名 → 中文解释（用于报告与答辩讲解）
FEATURE_LABELS: dict[str, str] = {
    # 正向证据
    "sensitive_identifier": "左侧存在敏感变量名或配置键",
    "assignment_adjacent": "紧邻赋值运算符",
    "sensitive_path": "位于敏感文件（.env / credentials / docker-compose 等）",
    "in_config_file": "位于配置文件类型",
    "rule_evidence": "命中结构化格式规则",
    "structured_evidence": "由结构化解析器提取（语法级证据）",
    "nearby_keyword": "邻近出现凭据类关键词",
    "cloud_keyword": "邻近出现云厂商或平台名称",
    "quoted_value": "值被引号包裹（典型的硬编码写法）",
    "known_prefix": "值具有已知凭据前缀（AKIA / LTAI / glpat- 等）",
    "high_entropy": "值的信息熵偏高",
    "length_plausible": "长度落在凭据的常见区间",
    "multi_char_class": "值包含多类字符",
    "repeat_in_doc": "同一文档中重复出现（配置传播特征）",
    # 负向证据
    "doc_path": "位于文档或示例路径",
    "hash_context": "邻近出现摘要/校验值关键词",
    "benign_hint": "邻近出现示例或占位提示词",
    "env_reference": "疑似环境变量引用而非明文",
    "low_information": "值的信息量过低",
}

# 专家先验权重。正值支持"是真实泄露"，负值支持"是噪声"。
PRIOR_WEIGHTS: dict[str, float] = {
    "sensitive_identifier": 2.2,
    "assignment_adjacent": 0.4,
    "sensitive_path": 2.0,
    "in_config_file": 0.6,
    "rule_evidence": 1.6,
    "structured_evidence": 2.4,
    "nearby_keyword": 1.1,
    "cloud_keyword": 1.3,
    "quoted_value": 0.3,
    "known_prefix": 2.6,
    "high_entropy": 0.8,
    "length_plausible": 0.5,
    "multi_char_class": 0.4,
    "repeat_in_doc": 0.5,
    "doc_path": -2.6,
    "hash_context": -2.6,
    "benign_hint": -2.2,
    "env_reference": -1.5,
    "low_information": -3.0,
}

PRIOR_BIAS = -2.0

# 已知凭据前缀：命中即为强证据
KNOWN_PREFIXES: tuple[str, ...] = (
    "AKIA", "ASIA", "ABIA", "ACCA", "AIDA", "AROA", "AIPA",
    "LTAI", "AKID", "AKLT",
    "ghp_", "gho_", "ghs_", "ghr_", "github_pat_",
    "glpat-", "glrt-",
    "npm_", "pypi-", "dckr_pat_",
    "xoxb-", "xoxp-", "xapp-",
    "sk-", "sk_live_", "sk_test_", "rk_live_",
    "eyJ", "hf_", "NRAK-", "glsa_", "sntrys_",
    "AIza", "GOCSPX-", "dop_v1_", "doo_v1_", "oy2",
    "-----BEGIN",
)

# 云厂商与平台名称
CLOUD_NAMES = (
    "aws", "amazon", "aliyun", "阿里云", "tencent", "腾讯云", "qcloud",
    "huawei", "huaweicloud", "华为云", "gcp", "google", "azure", "oracle",
    "digitalocean", "cloudflare", "baidu", "bce", "jdcloud", "qiniu",
    "upyun", "ucloud", "ksyun", "linode", "vultr",
)

CONFIG_SUFFIXES = (
    ".env", ".ini", ".cfg", ".conf", ".config", ".yaml", ".yml", ".json",
    ".toml", ".properties", ".xml", ".tfvars", ".credentials",
)


def _sigmoid(x: float) -> float:
    """数值稳定的 sigmoid。"""
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    exp_x = math.exp(x)
    return exp_x / (1.0 + exp_x)


# --------------------------------------------------------------------- 特征向量


@dataclass
class FeatureVector:
    """一条候选命中的特征向量。"""

    values: dict[str, float]

    def dot(self, weights: dict[str, float]) -> float:
        return sum(self.values.get(k, 0.0) * w for k, w in weights.items())

    def active(self) -> list[str]:
        return [k for k, v in self.values.items() if v]

    def to_dict(self) -> dict[str, float]:
        return {k: round(v, 4) for k, v in self.values.items() if v}


@dataclass
class ScoreExplanation:
    """评分结果与逐项贡献分解。"""

    probability: float
    logit: float
    contributions: list[tuple[str, float, float]] = field(default_factory=list)
    # (特征名, 特征值, 贡献量)，按 |贡献量| 降序

    # 完整特征向量（含未触发的 0 值）。保留它是为了让"误报反馈"能把
    # 这条样本原样喂给权重校准器，而不必重新解析原始文本。
    values: dict[str, float] = field(default_factory=dict)

    def top(self, n: int = 5) -> list[tuple[str, float]]:
        return [(name, contrib) for name, _, contrib in self.contributions[:n]]

    def summary(self, n: int = 3) -> str:
        """生成一句话解释，用于报告与终端输出。"""
        if not self.contributions:
            return "无显著上下文特征"
        parts = []
        for name, _, contrib in self.contributions[:n]:
            label = FEATURE_LABELS.get(name, name)
            sign = "+" if contrib > 0 else "−"
            parts.append(f"{sign}{abs(contrib):.2f} {label}")
        return "；".join(parts)

    def to_record(self) -> dict[str, Any]:
        return {
            "probability": self.probability,
            "logit": round(self.logit, 4),
            "contributions": [
                {"feature": name, "label": FEATURE_LABELS.get(name, name),
                 "value": round(value, 3), "contribution": round(contrib, 4)}
                for name, value, contrib in self.contributions
            ],
            "feature_vector": self.values,
            "summary": self.summary(),
        }


# --------------------------------------------------------------------- 特征抽取


def extract_features(
    candidate: Candidate,
    text: str,
    path_hint: str = "",
) -> FeatureVector:
    """从候选命中与其上下文中抽取特征。"""
    from .entropy import shannon_entropy
    from .signals import (
        ASSIGN_RE,
        BENIGN_NEARBY_RE,
        DOC_PATH_RE,
        HASH_CONTEXT_RE,
        NEARBY_KEYWORD_RE,
        SECRET_IDENT_RE,
        SENSITIVE_PATH_RE,
        context_slice,
        left_slice,
    )

    start, end = candidate.span
    left = left_slice(text, start)
    window = context_slice(text, start, end).lower()
    secret = candidate.secret or ""
    lowered_path = (path_hint or "").lower()
    lowered_secret = secret.lower()

    values: dict[str, float] = {}

    # ---- 正向证据 ----
    values["sensitive_identifier"] = 1.0 if SECRET_IDENT_RE.search(left) else 0.0
    values["assignment_adjacent"] = 1.0 if ASSIGN_RE.search(left) else 0.0
    values["sensitive_path"] = 1.0 if path_hint and SENSITIVE_PATH_RE.search(path_hint) else 0.0
    values["in_config_file"] = 1.0 if lowered_path.endswith(CONFIG_SUFFIXES) else 0.0
    values["rule_evidence"] = 1.0 if candidate.detector == "rule" else 0.0
    values["structured_evidence"] = 1.0 if candidate.detector == "structured" else 0.0
    values["nearby_keyword"] = 1.0 if NEARBY_KEYWORD_RE.search(window) else 0.0
    values["cloud_keyword"] = 1.0 if any(n in window for n in CLOUD_NAMES) else 0.0
    values["quoted_value"] = 1.0 if _is_quoted(text, start, end) else 0.0
    values["known_prefix"] = 1.0 if any(
        secret.startswith(p) or p.lower() in lowered_secret[:24] for p in KNOWN_PREFIXES
    ) else 0.0
    entropy = shannon_entropy(secret) if secret else 0.0
    values["high_entropy"] = 1.0 if entropy >= 4.0 else 0.0
    values["length_plausible"] = 1.0 if 16 <= len(secret) <= 128 else 0.0
    values["multi_char_class"] = 1.0 if _char_class_count(secret) >= 3 else 0.0
    values["repeat_in_doc"] = 1.0 if secret and text.count(secret) > 1 else 0.0

    # ---- 负向证据 ----
    values["doc_path"] = 1.0 if path_hint and DOC_PATH_RE.search(path_hint) else 0.0
    # hash_context 只看**命中所在行**：多行凭据（PEM 块）的窗口会覆盖整段
    # base64，随机字符极易偶然拼出 md5/sha 等词，造成系统性误判。
    _line_start = text.rfind("\n", 0, start) + 1
    _line_end = text.find("\n", end)
    _same_line = text[_line_start : _line_end if _line_end != -1 else len(text)].lower()
    values["hash_context"] = 1.0 if HASH_CONTEXT_RE.search(_same_line) else 0.0
    values["benign_hint"] = 1.0 if BENIGN_NEARBY_RE.search(window) else 0.0
    values["env_reference"] = 1.0 if ("${" in window or "environ" in window or "process.env" in window) else 0.0
    values["low_information"] = 1.0 if len(set(secret)) <= 3 or len(secret) < 8 else 0.0

    # 未出现在先验权重里的特征补 0，保证向量维度稳定
    for name in PRIOR_WEIGHTS:
        values.setdefault(name, 0.0)

    return FeatureVector(values={k: round(v, 4) for k, v in values.items()})


def _is_quoted(text: str, start: int, end: int) -> bool:
    left = text[max(0, start - 1) : start]
    right = text[end : end + 1]
    return left in ("'", '"') and right in ("'", '"')


def _char_class_count(value: str) -> int:
    import re

    n = 0
    for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"):
        if re.search(pattern, value):
            n += 1
    return n


# --------------------------------------------------------------------- 评分器


class ProbabilityScorer:
    """基于特征向量与权重计算"是真实泄露"的概率。"""

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        bias: float | None = None,
        *,
        calibrated: bool = False,
        sample_count: int = 0,
    ) -> None:
        self.weights = dict(PRIOR_WEIGHTS if weights is None else weights)
        self.bias = PRIOR_BIAS if bias is None else bias
        self.calibrated = calibrated
        self.sample_count = sample_count

    # ------------------------------------------------------------------ 评分

    def score(
        self, candidate: Candidate, text: str, path_hint: str = ""
    ) -> tuple[float, ScoreExplanation]:
        vector = extract_features(candidate, text, path_hint)
        return self.score_vector(vector)

    def score_vector(self, vector: FeatureVector) -> tuple[float, ScoreExplanation]:
        logit = vector.dot(self.weights) + self.bias
        probability = round(_sigmoid(logit), 4)
        contributions = sorted(
            (
                (name, vector.values.get(name, 0.0), vector.values.get(name, 0.0) * self.weights.get(name, 0.0))
                for name in self.weights
                if vector.values.get(name, 0.0)
            ),
            key=lambda item: -abs(item[2]),
        )
        return probability, ScoreExplanation(
            probability=probability,
            logit=logit,
            contributions=contributions,
            values={k: round(v, 4) for k, v in vector.values.items()},
        )

    # ------------------------------------------------------------------ 权重管理

    def feature_importance(self, top: int | None = None) -> list[tuple[str, float]]:
        """按权重绝对值排序的特征重要性。"""
        items = sorted(self.weights.items(), key=lambda kv: -abs(kv[1]))
        return items[:top] if top else items

    def to_dict(self) -> dict[str, Any]:
        return {
            "weights": {k: round(v, 6) for k, v in self.weights.items()},
            "bias": round(self.bias, 6),
            "calibrated": self.calibrated,
            "sample_count": self.sample_count,
        }

    def save(self, path: Path | str) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return target

    @classmethod
    def load_or_prior(cls, path: Path | str) -> "ProbabilityScorer":
        """加载已校准权重；不存在时回退到专家先验。"""
        target = Path(path)
        if not target.exists():
            return cls()
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return cls()
        weights = {k: float(v) for k, v in (data.get("weights") or {}).items()}
        if not weights:
            return cls()
        # 保证新增特征也有权重，避免版本升级后失效
        for name, value in PRIOR_WEIGHTS.items():
            weights.setdefault(name, value)
        return cls(
            weights=weights,
            bias=float(data.get("bias", PRIOR_BIAS)),
            calibrated=bool(data.get("calibrated", False)),
            sample_count=int(data.get("sample_count", 0)),
        )


# --------------------------------------------------------------------- 权重校准


@dataclass
class CalibrationReport:
    """一次权重校准的结果。"""

    samples: int
    positives: int
    negatives: int
    prior_accuracy: float
    calibrated_accuracy: float
    prior_precision: float
    calibrated_precision: float
    prior_recall: float
    calibrated_recall: float
    epochs: int
    scorer: ProbabilityScorer
    top_changes: list[tuple[str, float, float]] = field(default_factory=list)

    def to_record(self) -> dict[str, Any]:
        return {
            "samples": self.samples,
            "positives": self.positives,
            "negatives": self.negatives,
            "epochs": self.epochs,
            "prior": {
                "accuracy": round(self.prior_accuracy, 4),
                "precision": round(self.prior_precision, 4),
                "recall": round(self.prior_recall, 4),
            },
            "calibrated": {
                "accuracy": round(self.calibrated_accuracy, 4),
                "precision": round(self.calibrated_precision, 4),
                "recall": round(self.calibrated_recall, 4),
            },
            "top_weight_changes": [
                {"feature": name, "prior": round(a, 4), "calibrated": round(b, 4)}
                for name, a, b in self.top_changes
            ],
        }

    def summary(self) -> str:
        return (
            f"样本 {self.samples} 条（正例 {self.positives} / 负例 {self.negatives}），"
            f"准确率 {self.prior_accuracy:.3f} → {self.calibrated_accuracy:.3f}，"
            f"精确率 {self.prior_precision:.3f} → {self.calibrated_precision:.3f}，"
            f"召回率 {self.prior_recall:.3f} → {self.calibrated_recall:.3f}"
        )


def calibrate(
    samples: Iterable[tuple[FeatureVector, int]],
    *,
    epochs: int = 600,
    learning_rate: float = 0.35,
    l2: float = 0.02,
    anchor_strength: float = 0.12,
    min_samples: int = 8,
) -> CalibrationReport | None:
    """用逻辑回归从标注样本校准权重。

    三个关键设计（都是为了防止小样本跑偏）：

    1. **专家先验做初始化**：不是从零开始，而是从经验权重出发做微调。
    2. **锚定项（anchor）**：在损失里加一项，把权重往先验拉，强度由
       `anchor_strength` 控制。样本越少，先验的话语权越大。
    3. **L2 正则**：抑制单个特征被少量样本带跑。

    样本不足 `min_samples` 时直接返回 None——宁可用先验，也不要用
    几条样本拟合出一个不靠谱的模型。
    """
    data = [(v, int(label)) for v, label in samples]
    if len(data) < min_samples:
        return None
    if len({label for _, label in data}) < 2:
        return None  # 只有单一类别，无法训练

    weights = dict(PRIOR_WEIGHTS)
    bias = PRIOR_BIAS
    names = list(PRIOR_WEIGHTS)
    positives = sum(1 for _, label in data if label == 1)
    negatives = len(data) - positives

    prior = ProbabilityScorer()
    prior_metrics = _evaluate(
        (prior.score_vector(v)[0] for v, _ in data),
        [label for _, label in data],
    )

    n = len(data)
    for _ in range(epochs):
        grad = {name: 0.0 for name in names}
        grad_bias = 0.0
        for vector, label in data:
            logit = vector.dot(weights) + bias
            error = _sigmoid(logit) - label
            for name in names:
                grad[name] += error * vector.values.get(name, 0.0)
            grad_bias += error
        for name in names:
            # 数据梯度 + L2 + 先验锚定
            g = grad[name] / n + l2 * weights[name] + anchor_strength * (weights[name] - PRIOR_WEIGHTS[name])
            weights[name] -= learning_rate * g
        bias -= learning_rate * (grad_bias / n)

    scorer = ProbabilityScorer(weights=weights, bias=bias, calibrated=True, sample_count=n)
    cal_metrics = _evaluate(
        (scorer.score_vector(v)[0] for v, _ in data),
        [label for _, label in data],
    )

    changes = sorted(
        ((name, PRIOR_WEIGHTS[name], weights[name]) for name in names),
        key=lambda item: -abs(item[2] - item[1]),
    )[:8]

    return CalibrationReport(
        samples=n,
        positives=positives,
        negatives=negatives,
        prior_accuracy=prior_metrics["accuracy"],
        calibrated_accuracy=cal_metrics["accuracy"],
        prior_precision=prior_metrics["precision"],
        calibrated_precision=cal_metrics["precision"],
        prior_recall=prior_metrics["recall"],
        calibrated_recall=cal_metrics["recall"],
        epochs=epochs,
        scorer=scorer,
        top_changes=changes,
    )


def _evaluate(probabilities: Iterable[float], labels: list[int], threshold: float = 0.5) -> dict[str, float]:
    preds = [1 if p >= threshold else 0 for p in probabilities]
    tp = sum(1 for p, y in zip(preds, labels) if p == 1 and y == 1)
    fp = sum(1 for p, y in zip(preds, labels) if p == 1 and y == 0)
    fn = sum(1 for p, y in zip(preds, labels) if p == 0 and y == 1)
    total = len(labels) or 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    accuracy = sum(1 for p, y in zip(preds, labels) if p == y) / total
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
    }
