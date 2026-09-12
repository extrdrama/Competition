"""第三方 API 服务凭据的只读活性验证。

选取标准：该平台必须提供一个"只读、无副作用、不消耗额度"的身份或
权限查询端点。凡是需要发送消息、创建资源、产生费用的接口一律不使用。
"""

from __future__ import annotations

import logging
from typing import Any

from .base import INVALID, UNKNOWN, VALID, ValidationOutcome, validators

logger = logging.getLogger("credwatch.validators.api")


def _requests():
    import requests

    return requests


@validators.register("slack", "Slack auth.test（只读校验令牌有效性）")
def validate_slack(secret: str, finding: Any, timeout: int = 8) -> ValidationOutcome:
    requests = _requests()
    try:
        resp = requests.post(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {secret.strip()}"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return ValidationOutcome(UNKNOWN, f"Slack 验证请求失败：{type(exc).__name__}")
    if resp.status_code != 200:
        return ValidationOutcome(UNKNOWN, f"Slack 返回状态码 {resp.status_code}")
    try:
        data = resp.json()
    except ValueError:
        return ValidationOutcome(UNKNOWN, "Slack 返回内容非 JSON")
    if data.get("ok"):
        return ValidationOutcome(
            VALID,
            f"Slack 令牌有效，团队 {data.get('team')}，用户 {data.get('user')}",
        )
    return ValidationOutcome(INVALID, f"Slack 令牌无效：{data.get('error')}")


@validators.register("openai", "OpenAI GET /v1/models（只读列出模型，不产生费用）")
def validate_openai(secret: str, finding: Any, timeout: int = 8) -> ValidationOutcome:
    requests = _requests()
    try:
        resp = requests.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {secret.strip()}"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return ValidationOutcome(UNKNOWN, f"OpenAI 验证请求失败：{type(exc).__name__}")
    if resp.status_code == 200:
        try:
            count = len((resp.json() or {}).get("data") or [])
        except ValueError:
            count = 0
        return ValidationOutcome(VALID, f"OpenAI 密钥有效，可访问 {count} 个模型")
    if resp.status_code == 401:
        return ValidationOutcome(INVALID, "OpenAI 密钥无效或已吊销（401）")
    if resp.status_code == 429:
        return ValidationOutcome(UNKNOWN, "OpenAI 触发限流（429），无法判定")
    return ValidationOutcome(UNKNOWN, f"OpenAI 返回状态码 {resp.status_code}")


@validators.register("anthropic", "Anthropic GET /v1/models（只读列出模型）")
def validate_anthropic(secret: str, finding: Any, timeout: int = 8) -> ValidationOutcome:
    requests = _requests()
    try:
        resp = requests.get(
            "https://api.anthropic.com/v1/models",
            headers={
                "x-api-key": secret.strip(),
                "anthropic-version": "2023-06-01",
            },
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return ValidationOutcome(UNKNOWN, f"Anthropic 验证请求失败：{type(exc).__name__}")
    if resp.status_code == 200:
        return ValidationOutcome(VALID, "Anthropic 密钥有效")
    if resp.status_code == 401:
        return ValidationOutcome(INVALID, "Anthropic 密钥无效或已吊销（401）")
    return ValidationOutcome(UNKNOWN, f"Anthropic 返回状态码 {resp.status_code}")


@validators.register("stripe", "Stripe GET /v1/balance（只读查询余额，不产生交易）")
def validate_stripe(secret: str, finding: Any, timeout: int = 8) -> ValidationOutcome:
    requests = _requests()
    try:
        resp = requests.get(
            "https://api.stripe.com/v1/balance",
            headers={"Authorization": f"Bearer {secret.strip()}"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return ValidationOutcome(UNKNOWN, f"Stripe 验证请求失败：{type(exc).__name__}")
    if resp.status_code == 200:
        mode = "测试环境" if "_test_" in secret else "生产环境"
        return ValidationOutcome(VALID, f"Stripe 密钥有效（{mode}）")
    if resp.status_code == 401:
        return ValidationOutcome(INVALID, "Stripe 密钥无效或已吊销（401）")
    return ValidationOutcome(UNKNOWN, f"Stripe 返回状态码 {resp.status_code}")


@validators.register("sendgrid", "SendGrid GET /v3/scopes（只读查询权限范围）")
def validate_sendgrid(secret: str, finding: Any, timeout: int = 8) -> ValidationOutcome:
    requests = _requests()
    try:
        resp = requests.get(
            "https://api.sendgrid.com/v3/scopes",
            headers={"Authorization": f"Bearer {secret.strip()}"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return ValidationOutcome(UNKNOWN, f"SendGrid 验证请求失败：{type(exc).__name__}")
    if resp.status_code == 200:
        try:
            scopes = (resp.json() or {}).get("scopes") or []
        except ValueError:
            scopes = []
        return ValidationOutcome(
            VALID, f"SendGrid 密钥有效，权限范围 {len(scopes)} 项（可代发邮件，风险高）"
        )
    if resp.status_code == 401:
        return ValidationOutcome(INVALID, "SendGrid 密钥无效或已吊销（401）")
    return ValidationOutcome(UNKNOWN, f"SendGrid 返回状态码 {resp.status_code}")


@validators.register("twilio", "Twilio 凭据验证（需要 Account SID，缺失时不发起请求）")
def validate_twilio(secret: str, finding: Any, timeout: int = 8) -> ValidationOutcome:
    sid = (finding.metadata or {}).get("twilio_account_sid") or ""
    if not sid:
        return ValidationOutcome(UNKNOWN, "缺少 Twilio Account SID，无法验证 API Key")
    requests = _requests()
    try:
        resp = requests.get(
            f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json",
            auth=(sid, secret.strip()),
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return ValidationOutcome(UNKNOWN, f"Twilio 验证请求失败：{type(exc).__name__}")
    if resp.status_code == 200:
        return ValidationOutcome(VALID, f"Twilio 凭据有效，账号 {sid}")
    if resp.status_code == 401:
        return ValidationOutcome(INVALID, "Twilio 凭据无效或已吊销（401）")
    return ValidationOutcome(UNKNOWN, f"Twilio 返回状态码 {resp.status_code}")


__all__ = [
    "validate_anthropic",
    "validate_openai",
    "validate_sendgrid",
    "validate_slack",
    "validate_stripe",
    "validate_twilio",
]
