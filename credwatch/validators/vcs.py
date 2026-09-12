"""代码托管平台令牌的只读活性验证。

使用的都是各平台的"读取当前用户"接口（等价于 GetCallerIdentity），
属于最轻量的只读端点，不会读取任何仓库内容。
"""

from __future__ import annotations

import logging
from typing import Any

from .base import INVALID, UNKNOWN, VALID, ValidationOutcome, validators

logger = logging.getLogger("credwatch.validators.vcs")


def _requests():
    import requests

    return requests


@validators.register("github", "GitHub GET /user（只读读取当前令牌归属账号）")
def validate_github(secret: str, finding: Any, timeout: int = 8) -> ValidationOutcome:
    requests = _requests()
    headers = {
        "Authorization": f"Bearer {secret.strip()}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "CredWatch/1.0 (defensive-leak-detection)",
    }
    try:
        resp = requests.get("https://api.github.com/user", headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        return ValidationOutcome(UNKNOWN, f"GitHub 验证请求失败：{type(exc).__name__}")

    if resp.status_code == 200:
        data = resp.json()
        scopes = resp.headers.get("X-OAuth-Scopes", "")
        return ValidationOutcome(
            VALID,
            f"GitHub 令牌有效，归属账号 {data.get('login')}，权限范围 [{scopes or '未返回'}]",
        )
    if resp.status_code == 401:
        return ValidationOutcome(INVALID, "GitHub 令牌无效或已吊销（401）")
    if resp.status_code == 403:
        return ValidationOutcome(UNKNOWN, "GitHub 令牌受限或触发限流（403）")
    return ValidationOutcome(UNKNOWN, f"GitHub 返回状态码 {resp.status_code}")


@validators.register("gitlab", "GitLab GET /user（只读读取当前令牌归属账号）")
def validate_gitlab(secret: str, finding: Any, timeout: int = 8) -> ValidationOutcome:
    requests = _requests()
    token = secret.strip()
    base_url = (finding.metadata or {}).get("gitlab_base_url") or "https://gitlab.com"
    for header_name in ("PRIVATE-TOKEN", "Authorization"):
        headers = (
            {"PRIVATE-TOKEN": token}
            if header_name == "PRIVATE-TOKEN"
            else {"Authorization": f"Bearer {token}"}
        )
        try:
            resp = requests.get(f"{base_url}/api/v4/user", headers=headers, timeout=timeout)
        except requests.RequestException as exc:
            return ValidationOutcome(UNKNOWN, f"GitLab 验证请求失败：{type(exc).__name__}")
        if resp.status_code == 200:
            data = resp.json()
            return ValidationOutcome(
                VALID,
                f"GitLab 令牌有效，归属账号 {data.get('username')}（{base_url}）",
            )
        if resp.status_code == 401:
            return ValidationOutcome(INVALID, "GitLab 令牌无效或已吊销（401）")
    return ValidationOutcome(UNKNOWN, "GitLab 未能完成验证")


@validators.register("gitee", "Gitee GET /api/v5/user（只读读取当前令牌归属账号）")
def validate_gitee(secret: str, finding: Any, timeout: int = 8) -> ValidationOutcome:
    requests = _requests()
    try:
        resp = requests.get(
            "https://gitee.com/api/v5/user",
            params={"access_token": secret.strip()},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return ValidationOutcome(UNKNOWN, f"Gitee 验证请求失败：{type(exc).__name__}")

    if resp.status_code == 200:
        try:
            data = resp.json()
        except ValueError:
            return ValidationOutcome(UNKNOWN, "Gitee 返回内容非 JSON")
        return ValidationOutcome(VALID, f"Gitee 令牌有效，归属账号 {data.get('login')}")
    if resp.status_code == 401:
        return ValidationOutcome(INVALID, "Gitee 令牌无效或已吊销（401）")
    return ValidationOutcome(UNKNOWN, f"Gitee 返回状态码 {resp.status_code}")


@validators.register("dockerhub", "Docker Hub 令牌只读验证（读取当前账号）")
def validate_dockerhub(secret: str, finding: Any, timeout: int = 8) -> ValidationOutcome:
    requests = _requests()
    username = (finding.metadata or {}).get("dockerhub_username") or ""
    if not username:
        return ValidationOutcome(UNKNOWN, "缺少 Docker Hub 用户名，无法验证 PAT")
    try:
        resp = requests.post(
            "https://hub.docker.com/v2/users/login",
            json={"username": username, "password": secret.strip()},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return ValidationOutcome(UNKNOWN, f"Docker Hub 验证失败：{type(exc).__name__}")
    if resp.status_code == 200:
        return ValidationOutcome(VALID, f"Docker Hub PAT 有效，账号 {username}")
    if resp.status_code in (401, 403):
        return ValidationOutcome(INVALID, "Docker Hub PAT 无效或已吊销")
    return ValidationOutcome(UNKNOWN, f"Docker Hub 返回状态码 {resp.status_code}")


__all__ = ["validate_dockerhub", "validate_gitee", "validate_gitlab", "validate_github"]
