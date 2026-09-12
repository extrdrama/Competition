"""凭据对关联引擎。

## 为什么这是必要的

绝大多数凭据扫描工具的输出是一条条**孤立的字符串**。但从攻击者视角看：

- 单独一个 AWS Access Key ID **无法利用**——必须配上 Secret Access Key 才能调用 API；
- 单独一个 OAuth Client ID 只是公开标识——配上 Client Secret 才能冒充应用；
- 单独一个 JWT 只是会话凭证——配上签名密钥就能**伪造任意身份**；
- 一张加密私钥没有口令打不开——私钥与口令同时泄露才是完整事故。

也就是说，**两条中风险凭据同时出现，实际风险高于任意一条严重凭据单独出现**。
这个"组合风险"是 1 + 1 > 2 的，而现有工具普遍不做这层关联。

## 两级关联范围

| 范围 | 含义 | 可信度 |
| --- | --- | --- |
| `document` | 同一文件内成对出现 | 高——几乎必然是同一次硬编码 |
| `origin` | 同一仓库 / 同一工程目录 / 同一镜像内成对出现 | 中——跨文件引用同样可用 |

例如 AK 写在 `.env`、SK 写在 `config/settings.py`，
两个文件都在同一个仓库里，攻击者拿到整个仓库就能拼出完整凭据。
只做同文件关联会漏掉这类真实事故。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .models import Finding, max_severity

# --------------------------------------------------------------------- 配对规则


@dataclass(frozen=True)
class PairSpec:
    """一类凭据对的定义。"""

    key: str
    label: str
    left_rules: frozenset[str]
    right_rules: frozenset[str]
    impact: str
    upgraded_severity: str = "critical"
    allow_origin_scope: bool = True


PAIR_SPECS: tuple[PairSpec, ...] = (
    PairSpec(
        key="aws_access_pair",
        label="AWS 访问密钥对（Access Key ID + Secret）",
        left_rules=frozenset({"aws-access-key-id"}),
        right_rules=frozenset({"aws-secret-access-key", "aws-session-token"}),
        impact="凭据对完整，攻击者可直接以该身份调用 AWS API，"
               "枚举并操作云上资源（起实例、读对象存储、改权限）。",
    ),
    PairSpec(
        key="aliyun_access_pair",
        label="阿里云 AccessKey 对（AccessKeyId + AccessKeySecret）",
        left_rules=frozenset({"aliyun-access-key-id"}),
        right_rules=frozenset({"aliyun-access-key-secret"}),
        impact="凭据对完整，可直接调用阿里云 OpenAPI 操作账号下全部资源。",
    ),
    PairSpec(
        key="tencent_access_pair",
        label="腾讯云密钥对（SecretId + SecretKey）",
        left_rules=frozenset({"tencent-cloud-secret-id"}),
        right_rules=frozenset({"tencent-cloud-secret-key"}),
        impact="凭据对完整，可直接调用腾讯云 API 操作账号下资源。",
    ),
    PairSpec(
        key="huawei_access_pair",
        label="华为云密钥对（AK + SK）",
        left_rules=frozenset({"huawei-cloud-ak"}),
        right_rules=frozenset({"huawei-cloud-sk"}),
        impact="凭据对完整，可直接调用华为云 API 操作账号下资源。",
    ),
    PairSpec(
        key="oauth_client_pair",
        label="OAuth 应用凭据对（Client ID + Client Secret）",
        left_rules=frozenset({"oauth-client-id-generic", "firebase-config"}),
        right_rules=frozenset({"oauth-client-secret-generic", "gcp-oauth-client-secret",
                               "azure-client-secret"}),
        impact="可冒充该应用完成 OAuth 授权流程，以用户身份获取访问令牌。",
    ),
    PairSpec(
        key="jwt_token_and_secret",
        label="JWT 令牌 + 签名密钥",
        left_rules=frozenset({"jwt-token", "argocd-token"}),
        right_rules=frozenset({"jwt-signing-secret", "flask-secret-key",
                               "django-secret-key"}),
        impact="持签名密钥可自行签发任意身份的合法令牌，绕过全部认证与鉴权。",
    ),
    PairSpec(
        key="encrypted_key_and_passphrase",
        label="加密私钥 + 保护口令",
        left_rules=frozenset({"private-key-encrypted-pem"}),
        right_rules=frozenset({"pgp-passphrase-var"}),
        impact="加密私钥的保护口令同时泄露，等同于明文私钥泄露。",
        allow_origin_scope=False,
    ),
    PairSpec(
        key="alipay_merchant_pair",
        label="支付宝商户凭据对（APPID + 应用私钥）",
        left_rules=frozenset({"alipay-app-id-keyword"}),
        right_rules=frozenset({"alipay-private-key"}),
        impact="可伪造商户签名发起支付相关请求，直接造成资金风险。",
    ),
    PairSpec(
        key="wechatpay_merchant_pair",
        label="微信支付商户凭据对（商户号 + API 密钥）",
        left_rules=frozenset({"wechatpay-mch-id"}),
        right_rules=frozenset({"wechatpay-api-key"}),
        impact="可构造合法支付回调与查询请求，存在资金与订单篡改风险。",
    ),
)

SPEC_BY_KEY: dict[str, PairSpec] = {spec.key: spec for spec in PAIR_SPECS}

# origin 归属键的提取模式
_ORIGIN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"git(?:hub|lab)\.com/([^/]+/[^/#?]+)", re.I),
    re.compile(r"gitee\.com/([^/]+/[^/#?]+)", re.I),
    re.compile(r"hub\.docker\.com/r/([^/#?]+/[^/#?]+)", re.I),
)


def origin_key(url: str, path_hint: str = "") -> str:
    """从 URL 或路径推导"同一来源"的键。

    - 代码托管：`owner/repo`
    - 镜像仓库：`namespace/image`
    - 本地文件：路径的第一级目录（相当于工程名）
    """
    for pattern in _ORIGIN_PATTERNS:
        m = pattern.search(url or "")
        if m:
            return m.group(1).rstrip("/")
    clean = (path_hint or "").replace("\\", "/")
    parts = [p for p in clean.split("/") if p and p not in (".", "..")]
    if len(parts) >= 2:
        return parts[0]
    if parts:
        return parts[0]
    # 退化为 URL 目录
    base = (url or "").split("#", 1)[0]
    parts = [p for p in base.replace("\\", "/").split("/") if p]
    return "/".join(parts[-2:-1]) if len(parts) >= 2 else ""


# --------------------------------------------------------------------- 结果结构


@dataclass
class CredentialPair:
    """一组关联到的凭据对。"""

    spec_key: str
    label: str
    severity: str
    scope: str
    scope_key: str
    members: list[str] = field(default_factory=list)
    member_rules: list[str] = field(default_factory=list)
    masked_values: list[str] = field(default_factory=list)
    location: str = ""
    impact: str = ""
    confidence: float = 0.0

    def to_record(self) -> dict[str, Any]:
        return {
            "pair_type": self.spec_key,
            "label": self.label,
            "severity": self.severity,
            "scope": self.scope,
            "scope_key": self.scope_key,
            "members": self.members,
            "member_rules": self.member_rules,
            "masked_values": self.masked_values,
            "location": self.location,
            "impact": self.impact,
            "confidence": self.confidence,
        }


@dataclass
class CorrelationResult:
    pairs: list[CredentialPair] = field(default_factory=list)
    upgraded_findings: int = 0
    grouped_documents: int = 0
    grouped_origins: int = 0

    def to_record(self) -> dict[str, Any]:
        return {
            "pairs": [p.to_record() for p in self.pairs],
            "pair_count": len(self.pairs),
            "upgraded_findings": self.upgraded_findings,
            "grouped_documents": self.grouped_documents,
            "grouped_origins": self.grouped_origins,
            "by_type": _count_by(self.pairs, lambda p: p.label),
        }


def _count_by(items: Iterable[Any], key) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in items:
        k = key(item)
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


# --------------------------------------------------------------------- 关联引擎


class PairCorrelator:
    """在发现集合上做凭据对关联。"""

    def __init__(self, include_origin_scope: bool = True) -> None:
        self.include_origin_scope = include_origin_scope

    def correlate(self, findings: Iterable[Finding]) -> CorrelationResult:
        result = CorrelationResult()
        items = list(findings)
        if not items:
            return result

        by_doc: dict[str, list[Finding]] = {}
        by_origin: dict[str, list[Finding]] = {}
        for finding in items:
            by_doc.setdefault(finding.evidence.url, []).append(finding)
            origin = origin_key(finding.evidence.url, finding.evidence.path_hint)
            if origin:
                by_origin.setdefault(origin, []).append(finding)

        result.grouped_documents = len(by_doc)
        result.grouped_origins = len(by_origin)

        pairs: list[CredentialPair] = []
        matched_doc_members: set[tuple[str, str]] = set()

        # 第一级：同文件关联（强）
        for url, group in by_doc.items():
            for pair in self._match_specs(group, scope="document", scope_key=url,
                                          location=url):
                pairs.append(pair)
                for member in pair.members:
                    matched_doc_members.add((url, member))

        # 第二级：同来源（仓库/工程目录）关联（中），排除已同文件匹配过的组合
        if self.include_origin_scope:
            for origin, group in by_origin.items():
                if len(group) < 2:
                    continue
                for pair in self._match_specs(group, scope="origin", scope_key=origin,
                                              location=origin):
                    # 若该组合已在同文件范围命中过，说明证据更精确，跳过重复项
                    if any(
                        p.spec_key == pair.spec_key and p.scope == "document"
                        for p in pairs
                    ):
                        continue
                    pairs.append(pair)

        self._apply_upgrades(items, pairs)
        result.pairs = sorted(
            pairs,
            key=lambda p: (p.scope != "document", -p.confidence),
        )
        return result

    # ------------------------------------------------------------------ 内部

    def _match_specs(
        self, group: list[Finding], *, scope: str, scope_key: str, location: str
    ) -> list[CredentialPair]:
        out: list[CredentialPair] = []
        for spec in PAIR_SPECS:
            if scope == "origin" and not spec.allow_origin_scope:
                continue
            lefts = [f for f in group if f.rule_id in spec.left_rules]
            rights = [f for f in group if f.rule_id in spec.right_rules]
            if not lefts or not rights:
                continue
            out.append(
                CredentialPair(
                    spec_key=spec.key,
                    label=spec.label,
                    severity=spec.upgraded_severity,
                    scope=scope,
                    scope_key=scope_key,
                    members=[f.fingerprint for f in lefts + rights],
                    member_rules=[f.rule_id for f in lefts + rights],
                    masked_values=[f.masked for f in lefts + rights],
                    location=location,
                    impact=spec.impact,
                    confidence=self._pair_confidence(lefts + rights, scope),
                )
            )
        return out

    @staticmethod
    def _pair_confidence(members: list[Finding], scope: str) -> float:
        """配对可信度：同文件更高；成员本身越可信，配对越可信。"""
        base = 0.72 if scope == "document" else 0.55
        avg = sum(f.confidence for f in members) / len(members)
        return round(min(1.0, base + 0.28 * avg), 3)

    @staticmethod
    def _apply_upgrades(findings: list[Finding], pairs: list[CredentialPair]) -> None:
        """把配对信息写回成员发现，并提升风险等级。

        这里是组合风险的核心体现：单独一条 AWS Secret 是 high，
        一旦确认同仓库里有配对的 Access Key ID，整组升级为 critical。
        """
        index: dict[str, list[CredentialPair]] = {}
        for pair in pairs:
            for fp in pair.members:
                index.setdefault(fp, []).append(pair)

        for finding in findings:
            related = index.get(finding.fingerprint)
            if not related:
                continue
            finding.severity = max_severity(
                finding.severity, max((p.severity for p in related), key=_sev_rank)
            )
            finding.metadata["credential_pairs"] = [
                {
                    "pair_type": p.spec_key,
                    "label": p.label,
                    "scope": p.scope,
                    "location": p.location,
                    "impact": p.impact,
                }
                for p in related
            ]
            # 配对是强证据：置信度向上限靠拢
            finding.confidence = round(min(1.0, finding.confidence + 0.12), 3)


_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_rank(value: str) -> int:
    return _SEV_ORDER.get(value, 0)


def pair_statistics(pairs: Iterable[CredentialPair]) -> dict[str, Any]:
    pairs = list(pairs)
    by_type = _count_by(pairs, lambda p: p.label)
    by_scope: dict[str, int] = {}
    for pair in pairs:
        by_scope[pair.scope] = by_scope.get(pair.scope, 0) + 1
    return {
        "pairs": len(pairs),
        "by_type": by_type,
        "by_scope": by_scope,
        "document_scope": by_scope.get("document", 0),
        "origin_scope": by_scope.get("origin", 0),
    }
