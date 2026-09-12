"""社交媒体与内容社区渠道。

合规说明（重要）：
本模块只调用平台**官方开放 API**，不进行任何形式的页面爬取，
不绕过登录、风控或访问限制，严格遵守各平台的接口调用频率限制。
若未配置令牌，该渠道自动跳过，不会退化为主力爬虫。
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Iterator
from urllib.parse import quote_plus

from ..models import RawDoc
from .base import SourceAdapter, SourceMeta, registry

logger = logging.getLogger("credwatch.sources.social")


@registry.register
class WeiboSource(SourceAdapter):
    """微博渠道（走开放平台 API）。"""

    meta = SourceMeta(
        name="weibo",
        label="微博开放平台",
        category="社交媒体",
        description="通过微博开放平台公开搜索接口检索公开博文，"
        "检测以截图文字、代码片段形式外泄的配置与凭据。仅使用官方 API。",
        requires_token=True,
        rate_limit_per_minute=10,
        homepage="https://open.weibo.com",
    )

    API = "https://api.weibo.com/2"

    def __init__(self, settings: Any, **options: Any) -> None:
        super().__init__(settings, **options)
        self.token = getattr(settings, "weibo_token", "") or ""
        self.keywords = options.get("keywords") or [
            "AKSK 泄露",
            "accessKey 配置",
            "服务器密码",
        ]
        self.max_items = int(options.get("max_items", 60))

    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        if not self.token:
            logger.info("未配置 WEIBO_ACCESS_TOKEN，跳过微博渠道")
            return
        yielded = 0
        for keyword in self.keywords:
            self.limiter.acquire()
            resp = self.http.get(
                f"{self.API}/search/topics.json",
                params={"access_token": self.token, "q": keyword, "count": 20},
            )
            if resp is None or resp.status_code != 200:
                continue
            try:
                statuses = (resp.json() or {}).get("statuses") or []
            except ValueError:
                continue
            for item in statuses[:20]:
                text = item.get("text") or ""
                if not text:
                    continue
                yielded += 1
                if yielded > self.max_items:
                    return
                yield RawDoc(
                    source=self.meta.name,
                    external_id=str(item.get("id") or item.get("midstr") or ""),
                    url=f"https://weibo.com/{item.get('user', {}).get('id', '')}/"
                    f"{item.get('mid', '')}",
                    content=json.dumps(
                        {
                            "text": text,
                            "pic_urls": item.get("pic_urls"),
                            "long_text": (item.get("longText") or {}).get("longTextContent"),
                        },
                        ensure_ascii=False,
                    ).encode("utf-8"),
                    author=(item.get("user") or {}).get("screen_name"),
                    published_at=self._parse_time(item.get("created_at")),
                    metadata={
                        "filename": f"weibo_{item.get('id', 'post')}.json",
                        "path_hint": f"weibo/{keyword}",
                        "keyword": keyword,
                    },
                )

    @staticmethod
    def _parse_time(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.strptime(value, "%a %b %d %H:%M:%S %z %Y")
        except ValueError:
            return None

    def _has_token(self) -> bool:
        return bool(self.token)

    def health_check(self) -> tuple[bool, str]:
        return (True, "已配置访问令牌") if self.token else (False, "未配置 WEIBO_ACCESS_TOKEN")


@registry.register
class SearchEngineSource(SourceAdapter):
    """通用搜索引擎渠道（可配置引擎端点）。

    作用：官方 API 覆盖不到的边缘渠道，可通过搜索引擎的
    `site:` 语法做定向补充（例如 site:pastebin.com "AKIA"）。
    需要在配置中提供可用的搜索 API 端点，未配置则跳过。
    """

    meta = SourceMeta(
        name="search_engine",
        label="通用搜索引擎定向检索",
        category="搜索引擎",
        description="以 site: 语法对难以直接接入的站点做定向补充检索，"
        "需要配置可用的搜索 API 端点；未配置时该渠道自动跳过。",
        requires_token=True,
        rate_limit_per_minute=10,
        homepage="",
    )

    def __init__(self, settings: Any, **options: Any) -> None:
        super().__init__(settings, **options)
        self.endpoint = options.get("endpoint") or ""
        self.api_key = options.get("api_key") or ""
        self.queries = options.get("queries") or []
        self.max_items = int(options.get("max_items", 40))

    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        if not self.endpoint or not self.api_key:
            logger.info("未配置搜索引擎端点，跳过该渠道")
            return
        yielded = 0
        for query in self.queries:
            self.limiter.acquire()
            resp = self.http.get(
                self.endpoint.replace("{query}", quote_plus(query)),
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            if resp is None or resp.status_code != 200:
                continue
            try:
                payload = resp.json()
            except ValueError:
                continue
            for item in (payload.get("items") or payload.get("results") or [])[:20]:
                title = item.get("title") or ""
                snippet = item.get("snippet") or item.get("description") or ""
                link = item.get("link") or item.get("url") or ""
                if not (title or snippet):
                    continue
                yielded += 1
                if yielded > self.max_items:
                    return
                yield RawDoc(
                    source=self.meta.name,
                    external_id=link or f"{query}:{yielded}",
                    url=link,
                    content=f"{title}\n{snippet}".encode("utf-8"),
                    published_at=datetime.now(timezone.utc),
                    metadata={
                        "filename": "search_result.txt",
                        "path_hint": f"search/{query[:40]}",
                        "query": query,
                    },
                )

    def _has_token(self) -> bool:
        return bool(self.endpoint and self.api_key)

    def health_check(self) -> tuple[bool, str]:
        if not self.endpoint:
            return False, "未配置搜索引擎端点"
        return True, f"端点：{self.endpoint}"
