"""云厂商凭据的只读活性验证。

**只调用各云厂商的 GetCallerIdentity 类接口**——语义是"查询当前身份是谁"，
返回账号 ID / 用户名 / ARN，不具备列举、读取或修改任何资源的能力。

为什么这很重要：一个"已确认有效"的 AK 与一个"疑似泄露的字符串"，
在评审和应急响应中的价值完全不同；而过滤掉已吊销的凭据，
能显著提升"发现凭据数量"这一指标的有效性。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlencode

from .base import INVALID, UNKNOWN, VALID, ValidationOutcome, validators

logger = logging.getLogger("credwatch.validators.cloud")

# ---------------------------------------------------------------- 工具函数


def _hmac(key: bytes, msg: str, algo=hashlib.sha256) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), algo).digest()


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}****{value[-4:]}"


# ---------------------------------------------------------------- AWS SigV4


def _aws_sigv4(
    ak: str, sk: str, region: str, service: str, host: str, payload: str
) -> dict[str, str]:
    """按 AWS Signature V4 构造请求头。"""
    now = datetime.now(timezone.utc)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    content_type = "application/x-www-form-urlencoded; charset=utf-8"

    canonical_headers = (
        f"content-type:{content_type}\n" f"host:{host}\n" f"x-amz-date:{amzdate}\n"
    )
    signed_headers = "content-type;host;x-amz-date"
    canonical_request = "\n".join(
        [
            "POST",
            "/",
            "",
            canonical_headers,
            signed_headers,
            _sha256_hex(payload),
        ]
    )
    credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amzdate,
            credential_scope,
            _sha256_hex(canonical_request),
        ]
    )
    k_date = _hmac(("AWS4" + sk).encode("utf-8"), datestamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    k_signing = _hmac(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    return {
        "Content-Type": content_type,
        "X-Amz-Date": amzdate,
        "Authorization": (
            f"AWS4-HMAC-SHA256 Credential={ak}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        ),
    }


# AWS STS 端点依次尝试（含中国区与 GovCloud）
AWS_STS_ENDPOINTS: tuple[tuple[str, str], ...] = (
    ("sts.amazonaws.com", "us-east-1"),
    ("sts.cn-north-1.amazonaws.com.cn", "cn-north-1"),
    ("sts.us-gov-west-1.amazonaws.com", "us-gov-west-1"),
)


@validators.register(
    "aws",
    "AWS STS GetCallerIdentity（只读查询当前身份，返回账号与 ARN）",
)
def validate_aws(secret: str, finding: Any, timeout: int = 8) -> ValidationOutcome:
    """验证 AWS Access Key ID（需要配对的 Secret 时由调用方提供）。"""
    ak = secret.strip()
    sk = (finding.metadata or {}).get("aws_secret") or ""
    if not sk:
        return ValidationOutcome(
            UNKNOWN, f"仅命中 Access Key ID（{_mask(ak)}），缺少 Secret 无法验证"
        )

    import requests

    payload = "Action=GetCallerIdentity&Version=2011-06-15"
    for host, region in AWS_STS_ENDPOINTS:
        headers = _aws_sigv4(ak, sk, region, "sts", host, payload)
        try:
            resp = requests.post(
                f"https://{host}/", headers=headers, data=payload, timeout=timeout
            )
        except requests.RequestException as exc:
            logger.debug("AWS 验证请求失败：%s", exc)
            continue
        if resp.status_code == 200:
            account = _xml_field(resp.text, "Account")
            arn = _xml_field(resp.text, "Arn")
            return ValidationOutcome(
                VALID, f"AWS 凭据有效，账号 {account}，主体 {arn}"
            )
        if resp.status_code in (401, 403):
            return ValidationOutcome(INVALID, f"AWS 凭据无效或已吊销（{resp.status_code}）")
    return ValidationOutcome(UNKNOWN, "AWS 验证请求未能完成")


def _xml_field(text: str, tag: str) -> str:
    start = text.find(f"<{tag}>")
    end = text.find(f"</{tag}>")
    if start == -1 or end == -1:
        return "未知"
    return text[start + len(tag) + 2 : end]


# ---------------------------------------------------------------- 阿里云


def _aliyun_percent_encode(value: str) -> str:
    return quote(str(value), safe="").replace("+", "%20").replace("*", "%2A").replace("%7E", "~")


@validators.register(
    "aliyun",
    "阿里云 STS GetCallerIdentity（只读查询当前身份，返回账号与 ARN）",
)
def validate_aliyun(secret: str, finding: Any, timeout: int = 8) -> ValidationOutcome:
    sk = (finding.metadata or {}).get("aliyun_secret") or ""
    ak = secret.strip()
    if not sk:
        return ValidationOutcome(
            UNKNOWN, f"仅命中 AccessKey ID（{_mask(ak)}），缺少 Secret 无法验证"
        )

    params = {
        "Action": "GetCallerIdentity",
        "Format": "JSON",
        "Version": "2015-04-01",
        "AccessKeyId": ak,
        "SignatureMethod": "HMAC-SHA1",
        "SignatureVersion": "1.0",
        "SignatureNonce": str(uuid.uuid4()),
        "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    canonical = "&".join(
        f"{_aliyun_percent_encode(k)}={_aliyun_percent_encode(v)}"
        for k, v in sorted(params.items())
    )
    string_to_sign = f"GET&{_aliyun_percent_encode('/')}&{_aliyun_percent_encode(canonical)}"
    signature = base64.b64encode(
        hmac.new((sk + "&").encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha1).digest()
    ).decode()
    params["Signature"] = signature

    import requests

    try:
        resp = requests.get(
            "https://sts.aliyuncs.com/?" + urlencode(params), timeout=timeout
        )
    except requests.RequestException as exc:
        return ValidationOutcome(UNKNOWN, f"阿里云验证请求失败：{type(exc).__name__}")

    if resp.status_code == 200:
        try:
            data = resp.json()
        except ValueError:
            return ValidationOutcome(UNKNOWN, "阿里云返回内容非 JSON")
        account = data.get("AccountId", "未知")
        arn = data.get("Arn", "未知")
        return ValidationOutcome(VALID, f"阿里云凭据有效，账号 {account}，主体 {arn}")
    if resp.status_code in (400, 401, 403):
        return ValidationOutcome(INVALID, f"阿里云凭据无效或已吊销（{resp.status_code}）")
    return ValidationOutcome(UNKNOWN, f"阿里云返回状态码 {resp.status_code}")


# ---------------------------------------------------------------- 腾讯云 TC3


@validators.register(
    "tencent",
    "腾讯云 STS GetCallerIdentity（只读查询当前身份，返回账号与 ARN）",
)
def validate_tencent(secret: str, finding: Any, timeout: int = 8) -> ValidationOutcome:
    sk = (finding.metadata or {}).get("tencent_secret") or ""
    ak = secret.strip()
    if not sk:
        return ValidationOutcome(
            UNKNOWN, f"仅命中 SecretId（{_mask(ak)}），缺少 SecretKey 无法验证"
        )

    host = "sts.tencentcloudapi.com"
    service = "sts"
    payload = "{}"
    now = int(datetime.now(timezone.utc).timestamp())
    date = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d")

    canonical_headers = (
        "content-type:application/json; charset=utf-8\n"
        f"host:{host}\n"
        "x-tc-action:getcalleridentity\n"
    )
    signed_headers = "content-type;host;x-tc-action"
    canonical_request = "\n".join(
        ["POST", "/", "", canonical_headers, signed_headers, _sha256_hex(payload)]
    )
    credential_scope = f"{date}/{service}/tc3_request"
    string_to_sign = "\n".join(
        ["TC3-HMAC-SHA256", str(now), credential_scope, _sha256_hex(canonical_request)]
    )
    k_date = _hmac(("TC3" + sk).encode("utf-8"), date)
    k_service = _hmac(k_date, service)
    k_signing = _hmac(k_service, "tc3_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    headers = {
        "Authorization": (
            f"TC3-HMAC-SHA256 Credential={ak}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        ),
        "Content-Type": "application/json; charset=utf-8",
        "Host": host,
        "X-TC-Action": "GetCallerIdentity",
        "X-TC-Timestamp": str(now),
        "X-TC-Version": "2018-08-13",
    }

    import requests

    try:
        resp = requests.post(f"https://{host}/", headers=headers, data=payload, timeout=timeout)
    except requests.RequestException as exc:
        return ValidationOutcome(UNKNOWN, f"腾讯云验证请求失败：{type(exc).__name__}")

    try:
        data = resp.json().get("Response", {})
    except ValueError:
        return ValidationOutcome(UNKNOWN, "腾讯云返回内容非 JSON")

    if data.get("AccountId"):
        return ValidationOutcome(
            VALID,
            f"腾讯云凭据有效，账号 {data.get('AccountId')}，主体 {data.get('Arn', '未知')}",
        )
    code = data.get("Error", {}).get("Code")
    if code and code.startswith(("AuthFailure", "InvalidCredential", "UnauthorizedOperation")):
        return ValidationOutcome(INVALID, f"腾讯云凭据无效或已吊销（{code}）")
    return ValidationOutcome(UNKNOWN, f"腾讯云返回：{code or '未知错误'}")


@validators.register("huawei", "华为云凭据验证（当前版本暂不实现，仅标记待人工复核）")
def validate_huawei(secret: str, finding: Any, timeout: int = 8) -> ValidationOutcome:
    """华为云 STS 接口需按不同区域端点签名，且无统一的匿名验证入口，
    为避免误判，此处统一返回"无法判定"，不发起任何请求。"""
    return ValidationOutcome(UNKNOWN, "华为云凭据验证未实现，建议人工复核")


@validators.register("aws_pair", "AWS 密钥对验证（需要同时具备 AK 与 SK）")
def validate_aws_pair(secret: str, finding: Any, timeout: int = 8) -> ValidationOutcome:
    """Secret 单独无法验证，需要配对的 Access Key ID。"""
    return ValidationOutcome(UNKNOWN, "Secret 需与 Access Key ID 配对后验证")


@validators.register("google_api_key", "Google API Key 只读验证")
def validate_google_api_key(secret: str, finding: Any, timeout: int = 8) -> ValidationOutcome:
    """Google API Key 的可用性取决于启用的服务，无统一判定方式，
    因此不做请求，避免把"未启用某项服务"误判为"密钥无效"。"""
    return ValidationOutcome(UNKNOWN, "Google API Key 可用性依赖具体启用的服务，未做判定")


__all__ = [
    "validate_aliyun",
    "validate_aws",
    "validate_aws_pair",
    "validate_google_api_key",
    "validate_huawei",
    "validate_tencent",
]
