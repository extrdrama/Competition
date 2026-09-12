"""修复建议引擎。

赛题的评分点里有"作品的应用价值"。一个只会喊"你泄露了"的工具，
和一个能告诉运维"改哪一行、改成什么、改完怎么验证"的工具，
价值完全不同。

本模块按**凭据类型 + 命中位置**推导出具体的处置方案，分三个层次：

1. **应急处置**（立刻做）：吊销、轮换、评估影响面
2. **根因修复**（今天做）：把硬编码改成密钥管理服务 / 临时凭据 / 构建注入
3. **长期加固**（本周做）：加检测基线、加 pre-commit 钩子、改 CI 规范

给出的代码片段都是可直接复制改造的，而不是"建议使用密钥管理服务"这种空话。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

# --------------------------------------------------------------------- 结构


@dataclass
class RemediationStep:
    """一条处置动作。"""

    phase: str          # 应急处置 / 根因修复 / 长期加固
    action: str
    detail: str
    snippet: str = ""
    reference: str = ""

    def to_record(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "action": self.action,
            "detail": self.detail,
            "snippet": self.snippet,
            "reference": self.reference,
        }


@dataclass
class RemediationPlan:
    """针对一条发现的完整处置方案。"""

    subject: str
    severity: str
    steps: list[RemediationStep] = field(default_factory=list)

    def to_record(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "severity": self.severity,
            "steps": [s.to_record() for s in self.steps],
        }

    def render_markdown(self) -> str:
        lines = [f"**{self.subject}**（{self.severity}）", ""]
        current = ""
        for step in self.steps:
            if step.phase != current:
                current = step.phase
                lines.append(f"*{current}*")
            lines.append(f"- **{step.action}**：{step.detail}")
            if step.snippet:
                lines.append("")
                lines.append("  ```")
                lines.extend(f"  {line}" for line in step.snippet.splitlines())
                lines.append("  ```")
        return "\n".join(lines)


# --------------------------------------------------------------------- 方案模板
#
# 键为匹配器：优先按规则 ID 精确匹配，其次按凭据大类 / 类型匹配。

PLAYBOOKS: dict[str, list[RemediationStep]] = {
    # -------------------------------------------------- 云厂商访问密钥
    "cloud_aksk": [
        RemediationStep(
            "应急处置", "立即停用该密钥",
            "在云控制台禁用（而非仅删除副本）该 AccessKey，阻止继续被使用；"
            "先禁用后删除，便于观察是否有业务依赖。",
        ),
        RemediationStep(
            "应急处置", "审计密钥的实际使用轨迹",
            "调取操作审计日志，确认密钥被使用的来源 IP、时间窗口与调用过的接口，"
            "判断是否已发生未授权访问。参考云厂商的操作审计与安全中心。",
        ),
        RemediationStep(
            "应急处置", "新建密钥并替换业务侧配置",
            "创建新密钥后通过配置中心/密钥管理服务下发，避免再次写入代码或镜像。",
        ),
        RemediationStep(
            "根因修复", "改用临时凭据替代长期密钥",
            "长期 AccessKey 永不过期，一旦泄露即永久可用。"
            "容器/K8s 场景改用工作负载身份，CI 场景改用 OIDC 联合身份，"
            "本地开发改用 SSO 短期凭据。",
            snippet="# K8s：通过服务账户角色获取临时凭据，无需静态密钥\n"
                    "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: app\n"
                    "  annotations:\n"
                    "    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/app-role",
            reference="AWS IAM Roles for Service Accounts / 阿里云 RRSA",
        ),
        RemediationStep(
            "长期加固", "开启密钥轮换并设置有效期",
            "为仍必须使用的长期密钥配置 90 天轮换策略，并对超期密钥告警。",
        ),
    ],
    # -------------------------------------------------- 私钥与密钥材料
    "private_key": [
        RemediationStep(
            "应急处置", "立即吊销并更换密钥对",
            "把新公钥部署到目标主机（authorized_keys / 服务端证书），"
            "确认业务正常后再从所有服务器的 authorized_keys 中移除旧公钥。",
        ),
        RemediationStep(
            "应急处置", "检查是否存在非授权登录",
            "在目标主机上检查 auth.log / secure 日志中的异常来源 IP 与登录时间。",
            snippet="# 查找使用该指纹的登录记录\n"
                    "ssh-keygen -lf ~/.ssh/id_rsa.pub\n"
                    "grep -i 'Accepted publickey' /var/log/auth.log | tail -50",
        ),
        RemediationStep(
            "根因修复", "禁止把私钥放入代码仓库",
            "私钥统一由密钥管理服务下发（Vault / KMS / 云厂商密钥管理），"
            "CI 中以文件挂载方式临时提供。",
        ),
        RemediationStep(
            "长期加固", "为私钥增加口令保护并加 pre-commit 检查",
            "私钥至少设置口令；在开发机上安装 pre-commit 钩子，"
            "在提交前拦截私钥文件。",
            snippet="# .pre-commit-config.yaml\nrepos:\n"
                    "  - repo: local\n    hooks:\n"
                    "      - id: block-private-keys\n"
                    "        name: 阻止提交私钥文件\n        language: system\n"
                    "        entry: bash -c 'grep -rl \"BEGIN .*PRIVATE KEY\" --include=\"*\" . && exit 1 || exit 0'\n"
                    "        pass_filenames: false",
        ),
    ],
    # -------------------------------------------------- 数据库凭据
    "database": [
        RemediationStep(
            "应急处置", "轮换数据库口令",
            "修改口令后同步更新所有使用方（应用配置、定时任务、BI 工具），"
            "确认真实口令不再出现在任何文本中。",
        ),
        RemediationStep(
            "应急处置", "限制该账号的网络可达范围",
            "在数据库侧收紧白名单，只允许应用所在网段访问，"
            "并开启连接审计，排查是否存在异常来源的连接。",
        ),
        RemediationStep(
            "根因修复", "改用短期数据库凭据",
            "通过云厂商的数据库凭据托管能力生成自动轮换的短期账号，"
            "应用启动时获取，避免任何静态口令落盘。",
            snippet="# 应用侧：启动时获取短期数据库凭据（示意）\n"
                    "creds = secrets_manager.get_secret('prod/app-db')\n"
                    "engine = create_engine(\n"
                    "    f\"mysql+pymysql://{creds['user']}:{creds['password']}@{creds['host']}/app\"\n"
                    ")",
            reference="AWS RDS IAM 认证 / 阿里云 RDS 凭据托管",
        ),
        RemediationStep(
            "长期加固", "按最小权限拆分数据库账号",
            "读写、只读、迁移使用不同账号，避免单一口令泄露导致全库失控。",
        ),
    ],
    # -------------------------------------------------- 平台令牌
    "platform_token": [
        RemediationStep(
            "应急处置", "立即吊销该令牌",
            "在平台设置页撤销该令牌；令牌撤销即时生效，比改密码更快。",
        ),
        RemediationStep(
            "应急处置", "审计令牌权限与使用记录",
            "确认令牌的权限范围（scope）是否过大，检查平台的审计日志有无异常调用。",
        ),
        RemediationStep(
            "根因修复", "改用最小权限 + 短期令牌",
            "令牌只授予必要的 scope，并设置最短有效期；"
            "CI 中使用平台的 OIDC 联合身份而非长期令牌。",
        ),
        RemediationStep(
            "长期加固", "令牌统一由 CI 变量/密钥管理注入",
            "禁止在代码、配置、镜像中出现令牌；CI 中使用掩码变量，"
            "并对泄露的变量出现在日志中的情况告警。",
        ),
    ],
    # -------------------------------------------------- 支付商户密钥
    "payment": [
        RemediationStep(
            "应急处置", "立即在商户平台重置密钥",
            "支付密钥泄露直接关联资金风险，应**最高优先级**处理，"
            "重置后核对近期交易流水，排查有无异常订单或伪造回调。",
        ),
        RemediationStep(
            "应急处置", "核对回调来源与签名校验逻辑",
            "确认服务端严格校验收款回调的签名，避免密钥泄露后被伪造支付成功通知。",
            snippet="# 回调必须验签，不能只信任回调内容\n"
                    "if not alipay.verify(params, params.pop('sign')):\n"
                    "    raise PermissionDenied('回调签名校验失败')",
        ),
        RemediationStep(
            "根因修复", "私钥只保存在服务端密钥服务中",
            "商户私钥绝不能进入客户端、代码仓库或日志；"
            "仅通过密钥管理服务在服务端运行时读取。",
        ),
        RemediationStep(
            "长期加固", "建立资金类密钥的独立审计与轮换周期",
            "对支付相关密钥单独设置轮换周期（建议不超过 180 天）与变更审批。",
        ),
    ],
    # -------------------------------------------------- Webhook
    "webhook": [
        RemediationStep(
            "应急处置", "删除并重建 Webhook",
            "Webhook 地址等同于发送权限，泄露后可用于向团队群注入钓鱼消息。",
        ),
        RemediationStep(
            "根因修复", "改为从配置中心读取，不入代码",
            "Webhook 地址放进配置中心或密钥管理服务，按环境区分。",
        ),
    ],
}

# 规则 ID → 方案键（精确匹配优先）
RULE_PLAYBOOK: dict[str, str] = {
    "aws-access-key-id": "cloud_aksk",
    "aws-secret-access-key": "cloud_aksk",
    "aws-session-token": "cloud_aksk",
    "aliyun-access-key-id": "cloud_aksk",
    "aliyun-access-key-secret": "cloud_aksk",
    "tencent-cloud-secret-id": "cloud_aksk",
    "tencent-cloud-secret-key": "cloud_aksk",
    "huawei-cloud-ak": "cloud_aksk",
    "huawei-cloud-sk": "cloud_aksk",
    "gcp-service-account-json": "cloud_aksk",
    "azure-storage-account-key": "cloud_aksk",
    "private-key-rsa-pem": "private_key",
    "private-key-pkcs8-pem": "private_key",
    "private-key-openssh": "private_key",
    "private-key-encrypted-pem": "private_key",
    "putty-private-key": "private_key",
    "mysql-uri": "database",
    "postgresql-uri": "database",
    "mongodb-uri": "database",
    "redis-uri": "database",
    "jdbc-connection-string": "database",
    "generic-db-password-var": "database",
    "datadog-api-key": "platform_token",
    "slack-bot-token": "platform_token",
    "npm-token": "platform_token",
    "pypi-token": "platform_token",
    "stripe-secret-key": "payment",
    "alipay-private-key": "payment",
    "wechatpay-api-key": "payment",
    "slack-webhook": "webhook",
    "dingtalk-webhook": "webhook",
    "wecom-webhook": "webhook",
    "feishu-webhook": "webhook",
}

# 凭据大类兜底
CATEGORY_PLAYBOOK: dict[str, str] = {
    "cloud": "cloud_aksk",
    "crypto_keys": "private_key",
    "database": "database",
    "api_service": "platform_token",
    "vcs_ci": "platform_token",
}

# 命中位置 → 根因修复方案（按路径特征匹配）
LOCATION_FIXES: list[tuple[str, RemediationStep]] = [
    (
        r"(?:^|/)\.env",
        RemediationStep(
            "根因修复", "把 .env 从仓库中彻底移除",
            "把配置改为运行时注入：本地开发用 direnv/密钥管理 CLI，"
            "CI 与生产用密钥管理服务。.env 模板只保留键名、不保留值。",
            snippet="# 1) 加入 .gitignore（确认已被忽略，而不是只删除文件）\n"
                    "echo '.env' >> .gitignore\n"
                    "echo '.env.*' >> .gitignore\n"
                    "echo '!.env.example' >> .gitignore\n\n"
                    "# 2) 只保留键名的模板文件 .env.example\n"
                    "AWS_ACCESS_KEY_ID=\nAWS_SECRET_ACCESS_KEY=\n\n"
                    "# 3) 从历史中清除（注意：历史清除不能替代密钥轮换！）\n"
                    "git filter-repo --invert-paths --path .env",
            reference="git-filter-repo / BFG Repo-Cleaner",
        ),
    ),
    (
        r"docker-compose",
        RemediationStep(
            "根因修复", "compose 中改用 env_file 或 secrets 引用",
            "docker compose 支持 `env_file` 与 `secrets`，"
            "把明文改为引用外部文件/密钥对象，避免配置本身携带凭据。",
            snippet="services:\n  api:\n"
                    "    env_file: [./.env.local]   # 不进仓库\n"
                    "    secrets: [db_password]\n"
                    "secrets:\n  db_password:\n    file: ./run/secrets/db_password",
        ),
    ),
    (
        r"(?:^|/)Dockerfile|\.tar$|^layer",
        RemediationStep(
            "根因修复", "构建期改用 BuildKit secret 挂载",
            "`ENV`/`ARG` 会被完整记录进镜像历史，任何人都能读出。"
            "改用 BuildKit 的 `--mount=type=secret`，密钥不会进入任何镜像层。",
            snippet="# Dockerfile\n"
                    "RUN --mount=type=secret,id=npm_token \\\n"
                    "    NPM_TOKEN=$(cat /run/secrets/npm_token) npm ci\n\n"
                    "# 构建命令\ndocker build --secret id=npm_token,src=$HOME/.npm_token .",
            reference="Docker BuildKit secrets",
        ),
    ),
    (
        r"secret\.ya?ml|k8s",
        RemediationStep(
            "根因修复", "K8s Secret 改用外部密钥管理",
            "原生 Secret 只是 Base64，等同于明文，且会随清单进入 Git。"
            "改用 External Secrets Operator 或 Sealed Secrets，"
            "以加密形式入库、运行时从密钥管理服务同步。",
            snippet="apiVersion: external-secrets.io/v1beta1\nkind: ExternalSecret\n"
                    "metadata:\n  name: app-db\nspec:\n"
                    "  secretStoreRef:\n    name: cloud-kms\n"
                    "  target:\n    name: app-db\n"
                    "  data:\n    - secretKey: password\n"
                    "      remoteRef:\n        key: prod/app-db\n        property: password",
            reference="External Secrets Operator / Sealed Secrets",
        ),
    ),
    (
        r"\.gitlab-ci\.yml|\.github/workflows|jenkins|\.travis",
        RemediationStep(
            "根因修复", "CI 变量改为掩码变量或 OIDC",
            "CI 配置中的明文变量会随仓库可见；改用平台提供的掩码变量，"
            "或直接使用 OIDC 换取云上短期凭据。",
            snippet="# GitLab CI：使用掩码变量 + OIDC 换取短期凭据\n"
                    "deploy:\n  id_tokens:\n    AWS_TOKEN:\n      aud: https://gitlab.example.com\n"
                    "  script:\n    - export AWS_ROLE_ARN=arn:aws:iam::123456789012:role/gitlab\n"
                    "    - ./ci/aws-oidc-login.sh $AWS_TOKEN",
        ),
    ),
    (
        r"strings\.xml|\.apk$|\.dex|assets/|\.wxapkg|mini",
        RemediationStep(
            "根因修复", "移动端不得内置任何第三方密钥",
            "APK 与小程序包可被任何人下载并反编译，客户端内置的密钥等同于公开。"
            "改为由自己的服务端做代理调用，密钥只存在于服务端；"
            "确需客户端直连的，使用短期令牌并在服务端做二次校验。",
            snippet="// 反例：客户端硬编码密钥\n"
                    "const token = \"sk-xxxx\";\n\n"
                    "// 正例：客户端只持有短期会话票据，真实密钥在服务端\n"
                    "const res = await fetch('/api/proxy/amap?path=...', {\n"
                    "  headers: { Authorization: `Bearer ${sessionTicket}` }\n"
                    "});",
        ),
    ),
    (
        r"package\.json|\.npmrc|\.pypirc|setup\.py|MANIFEST",
        RemediationStep(
            "根因修复", "发布包排除敏感文件",
            "检查 .npmignore / files 字段 / MANIFEST.in，"
            "确保 .env、.npmrc、测试脚本不会被打进发布包；"
            "发布前用 `npm pack --dry-run` 核对文件清单。",
            snippet="# package.json\n\"files\": [\"dist\", \"README.md\", \"LICENSE\"]\n\n"
                    "# 核对将要发布的文件\nnpm pack --dry-run",
        ),
    ),
]


class RemediationEngine:
    """按发现内容生成处置方案。"""

    def plan(
        self,
        *,
        rule_id: str = "",
        category: str = "",
        kind: str = "",
        location: str = "",
        severity: str = "high",
    ) -> RemediationPlan:
        subject = kind or rule_id or "凭据泄露"
        steps: list[RemediationStep] = []

        key = RULE_PLAYBOOK.get(rule_id) or CATEGORY_PLAYBOOK.get(category)
        if key:
            steps.extend(PLAYBOOKS.get(key, []))
        else:
            steps.extend(self._generic_playbook())

        # 追加与命中位置相关的根因修复
        import re

        for pattern, step in LOCATION_FIXES:
            if location and re.search(pattern, location, re.IGNORECASE):
                steps.append(step)
                break

        steps.append(
            RemediationStep(
                "长期加固", "把该类凭据纳入持续监测",
                "把本次发现的特征（文件路径、变量名、凭据类型）加入本平台的"
                "检测基线，后续定期扫描并在再次出现时即时告警。",
            )
        )
        return RemediationPlan(subject=subject, severity=severity, steps=steps)

    @staticmethod
    def _generic_playbook() -> list[RemediationStep]:
        return [
            RemediationStep(
                "应急处置", "确认凭据有效性并吊销",
                "先判断该凭据是否仍然有效；有效的立即吊销，"
                "无效的也建议清理副本，避免被误认为可用而造成管理混乱。",
            ),
            RemediationStep(
                "应急处置", "排查是否已被使用",
                "查阅对应平台的登录/调用审计日志，确认是否存在异常访问。",
            ),
            RemediationStep(
                "根因修复", "改为运行时注入而非硬编码",
                "凭据统一由密钥管理服务（Vault / KMS / 云厂商密钥管理）在运行时下发，"
                "代码与配置中只保留引用。",
            ),
        ]

    def plans_for_clusters(
        self, clusters: Iterable[Any], limit: int = 20
    ) -> list[RemediationPlan]:
        """为风险最高的若干条发现生成方案（避免报告过长）。"""
        plans: list[RemediationPlan] = []
        for cluster in list(clusters)[:limit]:
            plans.append(
                self.plan(
                    rule_id=getattr(cluster, "rule_id", "") or "",
                    category=getattr(cluster, "category", "") or "",
                    kind=getattr(cluster, "kind", "") or "",
                    location=(cluster.exposures[0].get("url") if cluster.exposures else "")
                    or "",
                    severity=getattr(cluster, "severity", "high"),
                )
            )
        return plans


__all__ = [
    "LOCATION_FIXES",
    "PLAYBOOKS",
    "RemediationEngine",
    "RemediationPlan",
    "RemediationStep",
]
