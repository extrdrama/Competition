"""验证层基础设施：只读活性验证框架与安全护栏。

安全护栏是本模块最重要的部分。活性验证会向第三方发起真实请求，
因此必须满足以下约束（全部在代码层面强制，而非仅靠文档约定）：

1. **默认关闭**：只有显式设置 `CREDWATCH_ENABLE_VALIDATION=true` 才生效。
2. **白名单接口**：只有注册在册的、语义为"读取自身身份"的只读接口可被调用，
   不提供任何列举资源、读写数据的能力。
3. **限速**：全局令牌桶限制每分钟验证数量，避免对第三方造成压力。
4. **不打点敏感信息**：验证结果只记录"有效/无效/无法判定"与身份标识，
   不记录任何返回的业务数据。
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable

from ..models import Finding

logger = logging.getLogger("credwatch.validators")

VALID = "有效"
INVALID = "无效/已吊销"
UNKNOWN = "无法判定"
SKIPPED = "未启用验证"


@dataclass
class ValidationOutcome:
    """单个凭据的验证结论。"""

    status: str
    detail: str = ""

    @property
    def is_valid(self) -> bool:
        return self.status == VALID


class ValidationGuard:
    """限速与开关护栏。"""

    def __init__(self, enabled: bool, per_minute: int = 20) -> None:
        self.enabled = enabled
        self.per_minute = max(1, per_minute)
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    def allow(self) -> bool:
        if not self.enabled:
            return False
        with self._lock:
            now = time.monotonic()
            self._timestamps = [t for t in self._timestamps if now - t < 60]
            if len(self._timestamps) >= self.per_minute:
                logger.warning("验证频率达到上限 %s/min，跳过后续验证", self.per_minute)
                return False
            self._timestamps.append(now)
            return True


ValidatorCallable = Callable[[str, Finding], ValidationOutcome]


class ValidatorRegistry:
    """验证器注册表：按规则中的 `validator` 字段名查找。"""

    def __init__(self) -> None:
        self._validators: dict[str, ValidatorCallable] = {}
        self._descriptions: dict[str, str] = {}

    def register(self, name: str, description: str = "") -> Callable:
        def decorator(func: ValidatorCallable) -> ValidatorCallable:
            if name in self._validators:
                raise ValueError(f"验证器 {name} 重复注册")
            self._validators[name] = func
            self._descriptions[name] = description
            return func

        return decorator

    def get(self, name: str) -> ValidatorCallable | None:
        return self._validators.get(name)

    def names(self) -> list[str]:
        return sorted(self._validators)

    def describe(self) -> dict[str, str]:
        return dict(sorted(self._descriptions.items()))


validators = ValidatorRegistry()


def make_validator(settings) -> Callable[[Finding], tuple[bool | None, str]] | None:
    """构建注入到检测流水线的验证函数。

    返回 None 表示未启用验证，流水线将跳过该环节。
    """
    if not getattr(settings, "enable_validation", False):
        logger.info("活性验证未启用（设置 CREDWATCH_ENABLE_VALIDATION=true 可开启）")
        return None

    guard = ValidationGuard(
        enabled=True, per_minute=getattr(settings, "validate_rate_limit", 20)
    )
    timeout = getattr(settings, "validate_timeout", 8)

    # 延迟导入，避免未启用验证时产生任何网络相关副作用
    from . import api, cloud, vcs  # noqa: F401

    def validate(finding: Finding) -> tuple[bool | None, str]:
        if not guard.allow():
            return None, SKIPPED
        name = (finding.metadata or {}).get("validator") or finding.metadata.get("rule_validator")
        if not name:
            # 规则未声明验证方式时，按凭据类别做通用判断
            return None, UNKNOWN
        func = validators.get(name)
        if func is None:
            return None, f"无对应验证器（{name}）"
        try:
            outcome = func(finding.raw or "", finding, timeout=timeout)
        except TypeError:
            outcome = func(finding.raw or "", finding)
        except Exception as exc:  # noqa: BLE001 - 验证失败不应中断扫描
            logger.debug("验证异常：%s", exc)
            return None, f"验证异常：{type(exc).__name__}"
        if outcome.status == VALID:
            return True, outcome.detail
        if outcome.status == INVALID:
            return False, outcome.detail
        return None, outcome.detail or UNKNOWN

    return validate
