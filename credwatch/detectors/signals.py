"""上下文信号正则库。

本模块只做一件事：**定义"什么样的上下文说明它可能是真实凭据"的判定模式**。
打分逻辑在 `scoring.py`，抽特征时从这里取模式。

把"信号定义"与"评分算法"分开，好处是新增一条上下文线索时
只需要在这里加一个正则 + 在 `scoring.py` 的权重表里加一行，
不需要碰任何评分代码。
"""

from __future__ import annotations

import re

# 命中位置左侧出现的"敏感标识符"（变量名 / 字典键 / 配置键）
SECRET_IDENT_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|token|key|credential|auth|apikey|api_key|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret|app[_-]?secret|dsn|conn(?:ection)?[_-]?string)"
    r"[a-z0-9_\-]*\s*[=:>\s]{0,4}$"
)

# 赋值运算符紧邻命中左侧
ASSIGN_RE = re.compile(r"[=:]\s*['\"]?$")

# 敏感文件路径（命中即视为强证据）
SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:\.env(?:\.[a-z]+)?|\.aws[/\\]credentials|credentials\.json|\.npmrc|\.pypirc|"
    r"\.netrc|\.docker[/\\]config\.json|service[_-]?account[^/\\]*\.json|"
    r"application\.(?:yml|yaml|properties)|settings\.py|wp-config\.php|"
    r"\.git-credentials|kubeconfig|docker-compose|secrets?\.(?:ya?ml|json|env|txt))"
)

# 属于"文档/示例/测试"的路径，降低置信度
DOC_PATH_RE = re.compile(
    r"(?i)(?:readme|/docs?/|^docs?/|/tests?/|fixture|sample|example|mock|changelog|"
    r"\.md$|tutorial)"
)

# 邻近的业务关键词
NEARBY_KEYWORD_RE = re.compile(
    r"(?i)(?:aws|aliyun|阿里云|tencent|腾讯云|huawei|huaweicloud|华为云|gcp|azure|"
    r"password|passwd|pwd|secret|token|credential|apikey|api[_-]?key|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret|database|mysql|postgres|"
    r"redis|mongo|jdbc|jwt|oauth|ssh|ftp|smtp|sts|sigv4)"
)

# 明显的哈希/摘要串上下文，降低置信度
HASH_CONTEXT_RE = re.compile(r"(?i)(?:sha1|sha256|sha512|md5|checksum|digest|integrity|etag)")

# 明确无害的说明性词汇
BENIGN_NEARBY_RE = re.compile(
    r"(?i)(?:your[_-]|placeholder|replace[_-]?me|示例|example|<[a-z_]+>|xxxx|todo)"
)

# 上下文窗口半径（字符）
IDENT_WINDOW = 90
CONTEXT_WINDOW = 120


def context_slice(text: str, start: int, end: int, radius: int = CONTEXT_WINDOW) -> str:
    """取命中位置两侧的上下文窗口。"""
    return text[max(0, start - radius) : min(len(text), end + radius)]


def left_slice(text: str, start: int, radius: int = IDENT_WINDOW) -> str:
    """取命中位置左侧的标识符窗口。"""
    return text[max(0, start - radius) : start]
