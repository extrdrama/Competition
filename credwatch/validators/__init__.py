"""验证层：只读活性验证器集合。

导入本包即完成全部验证器注册。所有验证器都遵守同一约束：
**只调用目标平台的"读取自身身份/权限"接口，不做任何写操作。**
"""

from .base import (
    INVALID,
    SKIPPED,
    UNKNOWN,
    VALID,
    ValidationGuard,
    ValidationOutcome,
    ValidatorRegistry,
    make_validator,
    validators,
)

# 逐模块导入，触发验证器自注册
from . import cloud  # noqa: F401
from . import vcs  # noqa: F401
from . import api  # noqa: F401

__all__ = [
    "INVALID",
    "SKIPPED",
    "UNKNOWN",
    "VALID",
    "ValidationGuard",
    "ValidationOutcome",
    "ValidatorRegistry",
    "make_validator",
    "validators",
]
