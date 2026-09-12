"""归属识别。

赛题评审看"作品的应用价值"。一条"AKIA****1234 泄露在某个仓库"和一条
"某企业（XX 科技）的云账号密钥泄露在 GitHub 仓库 xxx 的 .env 文件里，
可通过仓库 issue 或 security@ 联系"——后者的实用价值完全不同。

本模块从证据中抽取归属线索：平台、仓库/项目主体、域名、组织类型，
并给出**负责任披露**的建议接收方。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .models import Finding

# 常见域名 → 组织名称（可按需扩充为配置文件）
DOMAIN_ORG_MAP: dict[str, str] = {
    "aliyun.com": "阿里云",
    "alibaba.com": "阿里巴巴",
    "tencent.com": "腾讯",
    "qq.com": "腾讯",
    "huawei.com": "华为",
    "huaweicloud.com": "华为云",
    "baidu.com": "百度",
    "bytedance.com": "字节跳动",
    "jd.com": "京东",
    "meituan.com": "美团",
    "xiaomi.com": "小米",
    "bilibili.com": "哔哩哔哩",
    "163.com": "网易",
    "sina.com.cn": "新浪",
    "weibo.com": "微博",
    "github.com": "GitHub",
    "gitlab.com": "GitLab",
    "gitee.com": "Gitee",
    "amazonaws.com": "AWS",
    "azure.com": "Microsoft Azure",
    "googleapis.com": "Google Cloud",
}

# 域名后缀 → 组织类型
ORG_TYPE_SUFFIXES: tuple[tuple[str, str], ...] = (
    (".edu.cn", "教育机构"),
    (".edu", "教育机构"),
    (".gov.cn", "政府机构"),
    (".gov", "政府机构"),
    (".org.cn", "社会组织"),
    (".org", "社会组织"),
    (".mil", "军事机构"),
    (".ac.cn", "科研机构"),
    (".com.cn", "企业"),
    (".com", "企业"),
    (".cn", "企业或机构"),
    (".net", "企业或机构"),
    (".io", "科技企业"),
    (".ai", "科技企业"),
)

# 从 URL / 路径中提取主体
GITHUB_REPO_RE = re.compile(r"github\.com/([^/]+)/([^/#?]+)")
GITEE_REPO_RE = re.compile(r"gitee\.com/([^/]+)/([^/#?]+)")
GITLAB_REPO_RE = re.compile(r"gitlab\.com/([^/]+)/([^/#?]+)")
DOMAIN_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+(?:com|cn|net|org|io|ai|edu|gov|dev|co))", re.I)

# 平台对应的披露建议
DISCLOSURE_CHANNELS: dict[str, str] = {
    "github": "通过仓库 Security 页面或 GitHub 官方私密漏洞报告渠道告知责任人",
    "github_gist": "通过 Gist 作者主页公开联系方式告知",
    "gitee": "通过 Gitee 仓库负责人主页联系方式告知",
    "gitlab": "通过 GitLab 项目维护者联系方式或实例管理员告知",
    "container_registry": "通过镜像仓库维护者联系方式或平台投诉通道告知",
    "npm_registry": "通过 npm 包维护者邮箱（package.json maintainers）告知",
    "pypi_registry": "通过 PyPI 项目维护者邮箱告知",
    "paste_site": "Paste 站点通常无法联系作者，建议同时通知平台方删除内容",
    "mediawiki": "通过 Wiki 站点管理员或页面历史中的作者告知",
    "confluence": "通过企业内部 IT/安全团队告知",
    "weibo": "通过微博博主私信或平台举报通道告知",
    "local_dir": "通过所在单位安全负责人告知",
    "mobile_app": "通过应用市场开发者联系方式或工信部备案主体告知",
    "mini_program": "通过小程序主体（微信开放平台）告知",
    "doc_share": "通过内容平台作者联系方式告知",
}

# 各云厂商凭据应通知的对象
CLOUD_DISCLOSURE: dict[str, str] = {
    "aliyun": "阿里云安全应急响应中心（云盾）",
    "tencent": "腾讯云安全应急响应中心",
    "aws": "AWS Security（aws-security@amazon.com）",
    "huawei": "华为云安全应急响应中心",
    "gcp": "Google Cloud Security",
    "azure": "Microsoft Security Response Center",
}

# 渠道风险权重：越"不该出现凭据"的渠道，其证据越能代表真实归属
SOURCE_RISK_WEIGHT: dict[str, float] = {
    "container_registry": 1.0,
    "mobile_app": 0.95,
    "mini_program": 0.95,
    "github": 0.9,
    "gitee": 0.9,
    "gitlab": 0.9,
    "npm_registry": 0.9,
    "pypi_registry": 0.9,
    "paste_site": 0.85,
    "mediawiki": 0.7,
    "confluence": 0.7,
    "doc_share": 0.6,
    "weibo": 0.6,
    "search_engine": 0.4,
    "local_dir": 0.5,
}


@dataclass
class Attribution:
    """一条发现的归属信息。"""

    platform: str = ""
    owner: str = ""
    project: str = ""
    org_name: str = ""
    org_type: str = ""
    domain: str = ""
    confidence: float = 0.0
    disclosure_hint: str = ""
    notes: list[str] = field(default_factory=list)

    def to_record(self) -> dict:
        return {
            "platform": self.platform,
            "owner": self.owner,
            "project": self.project,
            "org_name": self.org_name,
            "org_type": self.org_type,
            "domain": self.domain,
            "confidence": self.confidence,
            "disclosure_hint": self.disclosure_hint,
            "notes": self.notes,
        }

    @property
    def display(self) -> str:
        parts = [p for p in (self.org_name or self.owner, self.project) if p]
        return " / ".join(parts) if parts else "未识别主体"


class AttributionEngine:
    """从证据中抽取归属线索。"""

    def attribute_from_cluster(self, cluster: Any) -> Attribution:
        """对聚类结果做归属识别。

        取"最可信的那条暴露证据"（渠道风险权重最高、且发布时间最早）作为
        归属判断依据——因为凭据最初出现在哪里，最能反映真实归属。
        """
        from .models import Evidence, Finding

        if not cluster.exposures:
            platform = next(iter(cluster.sources), "") if cluster.sources else ""
            return Attribution(platform=platform)

        def _weight(exposure: dict) -> int:
            return int(SOURCE_RISK_WEIGHT.get(exposure.get("source", ""), 0.5) * 100)

        best = sorted(
            cluster.exposures,
            key=lambda e: (-_weight(e), e.get("published_at") or "9999-12-31"),
        )[0]
        proxy = Finding(
            rule_id=cluster.rule_name,
            rule_name=cluster.rule_name,
            category=cluster.category,
            severity=cluster.severity,
            confidence=cluster.confidence,
            detector=cluster.detector,
            masked=cluster.masked,
            fingerprint=cluster.fingerprint,
            evidence=Evidence(
                url=best.get("url") or "",
                path_hint=best.get("path") or "",
                line_no=best.get("line"),
                snippet=best.get("snippet") or "",
            ),
            source=best.get("source") or "",
        )
        attribution = self.attribute(proxy)
        attribution.notes.append(f"归属依据取自 {best.get('source')} 渠道的最早暴露点")
        if cluster.multi_channel:
            attribution.notes.append(f"该凭据已在 {cluster.channel_count} 个渠道扩散")
        return attribution

    def attribute(self, finding: Finding) -> Attribution:
        url = finding.evidence.url or ""
        path = finding.evidence.path_hint or ""
        result = Attribution(platform=finding.source)
        notes: list[str] = []

        # 1) 代码托管平台：从 URL 提取 组织/仓库
        for pattern, name in (
            (GITHUB_REPO_RE, "github"),
            (GITEE_REPO_RE, "gitee"),
            (GITLAB_REPO_RE, "gitlab"),
        ):
            m = pattern.search(url)
            if m:
                result.owner, result.project = m.group(1), m.group(2)
                result.confidence += 0.5
                notes.append(f"主体来自 {name} 仓库路径")
                break

        # 2) 域名与组织
        host = urlparse(url).netloc or ""
        if not host:
            m = DOMAIN_RE.search(url)
            host = m.group(1) if m else ""
        if host:
            host = host.split(":")[0].lower()
            result.domain = host
            for domain, org in DOMAIN_ORG_MAP.items():
                if host == domain or host.endswith("." + domain):
                    result.org_name = org
                    result.confidence += 0.2
                    break
            result.org_type = self._guess_org_type(host)
            if not result.org_type:
                result.org_type = "未知"
            notes.append(f"域名 {host} 推断组织类型：{result.org_type}")

        # 3) 沙箱/示例域名不算有效归属
        if re.search(r"(?i)(example|localhost|test|demo|invalid|foo|bar)\.", host):
            result.confidence = max(0.0, result.confidence - 0.4)
            notes.append("疑似示例域名，归属可信度下调")

        # 4) 本地路径：优先用归档文件名作为项目名
        #    （归档成员的 URL 形如 .../demo-app.apk#res/values/strings.xml，
        #     真正有意义的主体是归档本身，而不是成员在包内的路径）
        if not result.project and path:
            archive = ""
            if "#" in url:
                import re as _re

                head = url.split("#", 1)[0]
                archive = _re.split(r"[/\\]", head)[-1].strip()
            clean = path.split("#")[0].replace("\\", "/")
            parts = [p for p in clean.split("/") if p]
            if archive:
                result.project = archive
                result.confidence += 0.15
            elif len(parts) >= 2:
                result.project = parts[0] if "." not in parts[0] else parts[-1]
                result.confidence += 0.1
            elif parts:
                result.project = parts[0]
                result.confidence += 0.1

        # 5) 云厂商凭据的披露对象
        rule_id = finding.rule_id.lower()
        for key, target in CLOUD_DISCLOSURE.items():
            if key in rule_id or key in finding.rule_name.lower():
                result.disclosure_hint = f"同时通知 {target}"
                break

        # 6) 平台披露建议
        base_hint = DISCLOSURE_CHANNELS.get(finding.source, "通过平台公开渠道告知责任人")
        result.disclosure_hint = (
            f"{base_hint}；{result.disclosure_hint}" if result.disclosure_hint else base_hint
        )

        result.notes = notes
        result.confidence = round(min(result.confidence, 1.0), 2)
        return result

    @staticmethod
    def _guess_org_type(host: str) -> str:
        for suffix, org_type in ORG_TYPE_SUFFIXES:
            if host.endswith(suffix):
                return org_type
        return ""


__all__ = ["Attribution", "AttributionEngine"]
