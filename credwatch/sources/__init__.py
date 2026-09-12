"""采集层：渠道适配器集合与注册表。

导入本包即完成全部渠道的注册。新增渠道的标准做法：
1. 新建模块，定义继承 `SourceAdapter` 的类；
2. 在类上标注 `meta = SourceMeta(...)`；
3. 用 `@registry.register` 装饰；
4. 在本文件末尾补一行 import。
"""

from .base import (
    HttpClient,
    RateLimiter,
    SourceAdapter,
    SourceMeta,
    SourceRegistry,
    TokenPool,
    registry,
)

# 逐渠道导入，触发自注册
from . import local  # noqa: F401
from . import github  # noqa: F401
from . import gitee_gitlab  # noqa: F401
from . import paste  # noqa: F401
from . import registry_image  # noqa: F401
from . import package_repo  # noqa: F401
from . import knowledge  # noqa: F401
from . import social  # noqa: F401
from . import artifact  # noqa: F401

__all__ = [
    "HttpClient",
    "RateLimiter",
    "SourceAdapter",
    "SourceMeta",
    "SourceRegistry",
    "TokenPool",
    "registry",
    "load_all_sources",
]

# 渠道分类顺序，用于生成交付文档时的稳定排序
CATEGORY_ORDER = [
    "代码托管平台",
    "容器镜像",
    "包仓库",
    "公开分享与代码片段",
    "Wiki 与知识库",
    "内容共享平台",
    "社交媒体",
    "搜索引擎",
    "App 与小程序",
    "本地与企业内网",
]


def load_all_sources(settings, config: dict | None = None) -> dict[str, SourceAdapter]:
    """按配置实例化全部已启用的渠道。

    config 形如：
        {"github": {"enabled": true, "mode": "recent", "max_items": 50},
         "gitee": {"enabled": false}}
    未在配置中出现的渠道按 `enabled_by_default` 决定是否启用。
    """
    config = config or {}
    instances: dict[str, SourceAdapter] = {}
    for name in registry.names():
        adapter_cls = registry.get(name)
        options = dict(config.get(name) or {})
        enabled = options.pop("enabled", adapter_cls.meta.enabled_by_default)
        if not enabled:
            continue
        try:
            instances[name] = adapter_cls(settings, **options)
        except Exception as exc:  # noqa: BLE001 - 单个渠道初始化失败不影响整体
            import logging

            logging.getLogger("credwatch.sources").warning(
                "渠道 %s 初始化失败：%s", name, exc
            )
    return instances
