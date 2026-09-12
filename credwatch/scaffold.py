"""渠道脚手架：一条命令生成可运行的渠道适配器骨架。

存在意义有两个：

1. **降低扩展成本**。新增渠道是本赛题的明确评分项，把成本压到
   "实现一个 discover 方法"，扩展意愿才可能真正转化为覆盖率。
2. **让扩展过程可演示**。答辩现场可以当场执行
   `python -m credwatch new-source 某平台`，30 秒内得到一个能跑通的渠道骨架，
   这比口头说"我们的架构很灵活"有说服力得多。

生成内容：
- `credwatch/sources/<name>.py`：渠道实现骨架（可直接运行，首次运行会打印提示）
- 在 `credwatch/sources/__init__.py` 中追加 import（触发自注册）
- 在 `config/sources.yaml` 中追加默认配置块
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .config import PROJECT_ROOT

SOURCES_DIR = PROJECT_ROOT / "credwatch" / "sources"
SOURCES_INIT = SOURCES_DIR / "__init__.py"
SOURCES_YAML = PROJECT_ROOT / "config" / "sources.yaml"

NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")


@dataclass
class ScaffoldResult:
    name: str
    module_path: Path
    class_name: str
    yaml_updated: bool
    init_updated: bool

    def to_record(self) -> dict[str, object]:
        return {
            "name": self.name,
            "module": str(self.module_path),
            "class": f"{self.class_name}Source",
            "yaml_updated": self.yaml_updated,
            "init_updated": self.init_updated,
        }

    def next_steps(self) -> list[str]:
        return [
            f"1. 编辑 {self.module_path.relative_to(PROJECT_ROOT)}，实现 discover() 中的 TODO",
            f"2. 在 config/sources.yaml 的 {self.name} 段填好查询关键词",
            f"3. 运行 python -m credwatch sources --health 确认渠道被识别",
            f"4. 运行 python -m credwatch scan --source {self.name} 验证端到端",
        ]


MODULE_TEMPLATE = '''"""{label}渠道适配器。

本文件由 `python -m credwatch new-source {name}` 生成。
只需实现 `discover()` 一个方法即可产出可用渠道：

- `normalize()`：内容归一化。基类已实现文本抽取，
  若渠道内容为归档（zip/tar/镜像层/wxapkg），基类会自动展开成员。
- `next_cursor()`：增量游标。基类默认记录最新 ID 与发布时间。

如需覆盖默认行为（例如内容需要特殊解包），再覆写对应方法即可。
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Iterator

from ..models import RawDoc
from .base import SourceAdapter, SourceMeta, registry

logger = logging.getLogger("credwatch.sources.{name}")


@registry.register
class {class_name}Source(SourceAdapter):
    """{label}渠道。

    实现要点：
    1. 只访问**公开可访问**的内容，不登录、不绕过访问控制；
    2. 通过 `self.limiter.acquire()` 做限速，避免对第三方造成压力；
    3. 用 `cursor` 做增量，避免重复上报同一条凭据。
    """

    meta = SourceMeta(
        name="{name}",
        label="{label}",
        category="{category}",
        description="{description}",
        requires_token={requires_token},
        rate_limit_per_minute={rate_limit},
        enabled_by_default=False,
        homepage="{homepage}",
    )

    def __init__(self, settings: Any, **options: Any) -> None:
        super().__init__(settings, **options)
        # 令牌统一从 settings / 环境变量读取，不写死在代码里
        self.token = getattr(settings, "{name}_token", "") or options.get("token", "")
        self.queries = options.get("queries") or ["password", "access_key", "token"]
        self.max_items = int(options.get("max_items", 200))

    # ---------------------------------------------------------------- 主流程

    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        """产出本轮的原始文档。

        cursor 中保存上次的进度（例如 {cursor_key}），据此只拉取新增内容。
        """
        if self.meta.requires_token and not self.token:
            logger.info("未配置 {name} 令牌，跳过该渠道")
            return

        cursor = cursor or {{}}
        seen: set[str] = set(cursor.get("seen_ids") or [])

        for query in self.queries:
            self.limiter.acquire()

            # TODO: 替换为真实的公开检索接口
            response = self.http.get(
                "{homepage}/api/search",
                params={{"q": query, "limit": 20}},
                headers={{"Authorization": f"Bearer {{self.token}}"}} if self.token else {{}},
            )
            if response is None or response.status_code != 200:
                logger.debug("{name} 检索失败：%s", query)
                continue

            try:
                items = (response.json() or {{}}).get("items") or []
            except ValueError:
                continue

            for item in items[: self.max_items]:
                external_id = str(item.get("id") or item.get("url") or "")
                if not external_id or external_id in seen:
                    continue
                seen.add(external_id)

                yield RawDoc(
                    source=self.meta.name,
                    external_id=external_id,
                    url=str(item.get("url") or ""),
                    content=str(item.get("content") or "").encode("utf-8"),
                    author=item.get("author"),
                    published_at=datetime.now(timezone.utc),
                    metadata={{
                        "filename": item.get("filename") or f"{{external_id}}.txt",
                        "path_hint": item.get("path") or external_id,
                    }},
                )

    def next_cursor(self, raw: RawDoc) -> dict[str, Any]:
        """增量游标：记录已处理的 ID 与时间。"""
        return {{
            "last_id": raw.external_id,
            "last_seen_at": datetime.now(timezone.utc).isoformat(),
        }}

    def _has_token(self) -> bool:
        return bool(self.token)

    def health_check(self) -> tuple[bool, str]:
        if self.meta.requires_token and not self.token:
            return False, "未配置令牌"
        return True, "配置就绪"
'''


def _class_name(name: str) -> str:
    return "".join(part.capitalize() for part in name.split("_"))


def create_source(
    name: str,
    *,
    label: str = "",
    category: str = "内容共享平台",
    description: str = "（待补充：说明该渠道采集什么内容、为什么值得监控）",
    requires_token: bool = False,
    rate_limit: int = 20,
    homepage: str = "",
    force: bool = False,
) -> ScaffoldResult:
    """生成渠道骨架，并接入注册表与配置文件。"""
    if not NAME_RE.match(name):
        raise ValueError(
            f"渠道标识 `{name}` 不合法：只能使用小写字母、数字与下划线，且以字母开头"
        )

    class_name = _class_name(name)
    module_path = SOURCES_DIR / f"{name}.py"
    if module_path.exists() and not force:
        raise FileExistsError(f"渠道模块已存在：{module_path}（使用 --force 覆盖）")

    module_path.write_text(
        MODULE_TEMPLATE.format(
            name=name,
            label=label or f"{class_name} 渠道",
            class_name=class_name,
            category=category,
            description=description,
            requires_token=requires_token,
            rate_limit=rate_limit,
            homepage=homepage,
            cursor_key="last_id",
        ),
        encoding="utf-8",
    )

    init_updated = _append_import(name)
    yaml_updated = _append_yaml_block(
        name=name,
        category=category,
        queries=["password", "access_key", "token"],
        requires_token=requires_token,
    )
    return ScaffoldResult(
        name=name,
        module_path=module_path,
        class_name=class_name,
        yaml_updated=yaml_updated,
        init_updated=init_updated,
    )


def _append_import(name: str) -> bool:
    """在 sources/__init__.py 中追加 import，触发渠道自注册。"""
    text = SOURCES_INIT.read_text(encoding="utf-8")
    marker = f"from . import {name}"
    if marker in text:
        return False
    anchor = "# 逐渠道导入，触发自注册"
    if anchor not in text:
        # 兜底：直接追加到文件末尾
        SOURCES_INIT.write_text(text.rstrip() + f"\n{marker}  # noqa: F401\n", encoding="utf-8")
        return True
    line = f"from . import {name}  # noqa: F401"
    text = text.replace(anchor, f"{anchor}\n{line}", 1)
    SOURCES_INIT.write_text(text, encoding="utf-8")
    return True


def _append_yaml_block(
    name: str, *, category: str, queries: list[str], requires_token: bool
) -> bool:
    """在 config/sources.yaml 中追加默认配置块。"""
    text = SOURCES_YAML.read_text(encoding="utf-8")
    if re.search(rf"(?m)^\s{{2}}{re.escape(name)}:", text):
        return False
    query_lines = "\n".join(f"      - {q}" for q in queries)
    block = (
        f"\n  # ------------------------------------------------------- {category}\n"
        f"  {name}:\n"
        f"    enabled: false          # 填好查询关键词、确认接口可用后再开启\n"
        f"    max_items: 200\n"
        f"    queries:\n{query_lines}\n"
    )
    text = text.rstrip() + "\n" + block
    SOURCES_YAML.write_text(text, encoding="utf-8")
    return True


__all__ = ["ScaffoldResult", "create_source"]
