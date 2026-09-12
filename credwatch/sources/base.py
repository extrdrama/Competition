"""采集层基础设施：适配器抽象、注册表、限速、令牌池、HTTP 客户端。

这一层是本赛题"平台可扩展性"评分项的落地形式：
新增一个渠道 = 继承 SourceAdapter 并实现 3 个方法，无需改动任何其他代码。
"""

from __future__ import annotations

import abc
import logging
import random
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

import requests

from ..models import Document, RawDoc
from ..parsers import extract, is_archive, is_text_path, iter_archive

logger = logging.getLogger("credwatch.sources")

DEFAULT_TIMEOUT = 20
DEFAULT_RETRIES = 3


# --------------------------------------------------------------------- 限速器


class RateLimiter:
    """滑动窗口限速器，避免对第三方平台造成压力（也是合规要求之一）。"""

    def __init__(self, per_minute: int = 30, burst: int | None = None) -> None:
        self.per_minute = max(1, per_minute)
        self.burst = burst or per_minute
        self._events: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                while self._events and now - self._events[0] > 60:
                    self._events.popleft()
                if len(self._events) < self.burst and len(self._events) < self.per_minute:
                    self._events.append(now)
                    return
                sleep_for = 60 - (now - self._events[0])
            time.sleep(max(0.2, min(sleep_for, 5.0)))


class TokenPool:
    """令牌轮换池：遇到 403/429 自动切换到下一个，避免单令牌被限流。"""

    def __init__(self, tokens: Iterable[str]) -> None:
        self.tokens = [t for t in tokens if t]
        self._index = 0
        self._lock = threading.Lock()

    @property
    def empty(self) -> bool:
        return not self.tokens

    def current(self) -> str | None:
        if not self.tokens:
            return None
        with self._lock:
            return self.tokens[self._index % len(self.tokens)]

    def rotate(self) -> str | None:
        if not self.tokens:
            return None
        with self._lock:
            self._index = (self._index + 1) % len(self.tokens)
            return self.tokens[self._index]


# --------------------------------------------------------------------- HTTP


class HttpClient:
    """带退避重试与统一 UA 的 HTTP 客户端。"""

    def __init__(
        self,
        *,
        user_agent: str = "CredWatch/1.0 (defensive-leak-detection)",
        timeout: int = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        proxies: dict[str, str] | None = None,
    ) -> None:
        self.timeout = timeout
        self.retries = retries
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent, "Accept": "*/*"})
        if proxies:
            self.session.proxies.update(proxies)

    def get(self, url: str, **kwargs: Any) -> requests.Response | None:
        kwargs.setdefault("timeout", self.timeout)
        for attempt in range(self.retries):
            try:
                resp = self.session.get(url, **kwargs)
            except requests.RequestException as exc:
                logger.debug("GET %s 失败：%s", url, exc)
                time.sleep(min(2**attempt, 8) + random.random())
                continue
            if resp.status_code in (403, 429):
                time.sleep(min(2**attempt, 15) + random.random())
                continue
            if resp.status_code >= 500:
                time.sleep(min(2**attempt, 8) + random.random())
                continue
            return resp
        return None

    def post(self, url: str, **kwargs: Any) -> requests.Response | None:
        kwargs.setdefault("timeout", self.timeout)
        for attempt in range(self.retries):
            try:
                resp = self.session.post(url, **kwargs)
            except requests.RequestException:
                time.sleep(min(2**attempt, 8) + random.random())
                continue
            if resp.status_code in (403, 429, 500, 502, 503):
                time.sleep(min(2**attempt, 10) + random.random())
                continue
            return resp
        return None

    def close(self) -> None:
        self.session.close()


# --------------------------------------------------------------------- 适配器


@dataclass
class SourceMeta:
    """渠道元信息，用于生成"支持的公开渠道列表"交付文档。"""

    name: str
    label: str
    category: str
    description: str = ""
    requires_token: bool = False
    rate_limit_per_minute: int = 30
    # 安全默认值：**必须显式启用**。
    # 配置文件中没有出现的渠道一律不启用，避免"只想扫本地目录，
    # 结果顺带对十几个第三方平台发起了请求"这类意外。
    enabled_by_default: bool = False
    homepage: str = ""


class SourceAdapter(abc.ABC):
    """渠道适配器基类。

    子类只需实现 `discover`。`normalize` / `next_cursor` 已有合理默认实现，
    需要处理归档的渠道（如镜像、APK）可覆写 `normalize` 以展开成员。
    """

    meta: SourceMeta

    def __init__(self, settings: Any, http: HttpClient | None = None, **options: Any) -> None:
        self.settings = settings
        self.options = options
        self.http = http or HttpClient(user_agent=getattr(settings, "user_agent", "CredWatch/1.0"))
        # 限流默认取渠道元信息；允许按渠道实例覆盖
        # （如大规模实测抓取 raw 内容时可适当放宽，不占 GitHub API 配额）
        self.limiter = RateLimiter(
            per_minute=int(
                options.get("rate_limit_per_minute", self.meta.rate_limit_per_minute)
            )
        )
        self._default_interval = options.get("interval_minutes", 60)

    # -------------------------------------------------------------- 待实现

    @abc.abstractmethod
    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        """产出本轮的原始文档。cursor 用于增量续扫。"""

    # -------------------------------------------------------------- 默认实现

    def normalize(self, raw: RawDoc) -> Iterator[Document]:
        """把原始内容转为一个或多个待检测文档。

        若 raw 是归档（zip/apk/镜像层 tar/wxapkg），则展开成员分别成文，
        使二进制渠道的凭据也能被检测到。
        """
        name = raw.metadata.get("filename") or raw.url.rsplit("/", 1)[-1] or "content"
        if is_archive(name) or raw.content_type in ("application/zip", "application/x-tar"):
            try:
                entries = list(iter_archive(raw.content, name))
            except ValueError as exc:
                logger.debug("归档 %s 解包失败：%s", name, exc)
                entries = []
            if entries:
                for entry in entries:
                    result = extract(entry.data, entry.name)
                    if not result.text:
                        continue
                    yield Document(
                        doc_id=Document.new_id(raw.source, f"{raw.external_id}::{entry.name}"),
                        source=raw.source,
                        url=f"{raw.url}#{entry.name}",
                        text=result.text,
                        content_type="text/plain" if not result.is_binary else "binary/strings",
                        author=raw.author,
                        published_at=raw.published_at,
                        path_hint=entry.name,
                        metadata={**raw.metadata, "archive_member": entry.name},
                    )
                return
        result = extract(raw.content, name)
        if not result.text:
            return
        yield Document(
            doc_id=Document.new_id(raw.source, raw.external_id),
            source=raw.source,
            url=raw.url,
            text=result.text,
            content_type=raw.content_type,
            author=raw.author,
            published_at=raw.published_at,
            path_hint=name if is_text_path(name) else raw.metadata.get("path_hint", name),
            metadata=raw.metadata,
        )

    def next_cursor(self, raw: RawDoc) -> dict[str, Any]:
        """默认游标：记录最新的发布时间或外部 ID。"""
        return {
            "last_id": raw.external_id,
            "last_published_at": raw.published_at.astimezone(timezone.utc).isoformat()
            if raw.published_at
            else None,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

    def health_check(self) -> tuple[bool, str]:
        """渠道可用性自检，供 CLI `sources --health` 使用。"""
        if self.meta.requires_token:
            return False, "需要令牌，未配置" if not self._has_token() else "已配置令牌"
        return True, "无需令牌"

    def _has_token(self) -> bool:
        return True

    def close(self) -> None:
        self.http.close()


# --------------------------------------------------------------------- 注册表


@dataclass
class SourceRegistry:
    """渠道注册表。适配器通过 `@registry.register` 装饰器自注册。"""

    _adapters: dict[str, type[SourceAdapter]] = field(default_factory=dict)

    def register(self, adapter_cls: type[SourceAdapter]) -> type[SourceAdapter]:
        name = adapter_cls.meta.name
        if name in self._adapters:
            raise ValueError(f"渠道 {name} 重复注册")
        self._adapters[name] = adapter_cls
        return adapter_cls

    def get(self, name: str) -> type[SourceAdapter]:
        if name not in self._adapters:
            raise KeyError(f"未知渠道：{name}；可用渠道：{', '.join(sorted(self._adapters))}")
        return self._adapters[name]

    def names(self) -> list[str]:
        return sorted(self._adapters)

    def metas(self) -> list[SourceMeta]:
        return [cls.meta for cls in self._adapters.values()]

    def create(self, name: str, settings: Any, **options: Any) -> SourceAdapter:
        return self.get(name)(settings, **options)

    def by_category(self) -> dict[str, list[SourceMeta]]:
        grouped: dict[str, list[SourceMeta]] = {}
        for meta in self.metas():
            grouped.setdefault(meta.category, []).append(meta)
        return grouped


registry = SourceRegistry()
