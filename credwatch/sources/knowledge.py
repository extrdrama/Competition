"""知识共享与 Wiki 渠道。

覆盖：
- MediaWiki 系（Wikipedia、各类企业/社区 Wiki）：标准 api.php 搜索接口。
- Confluence 系（含企业自建实例）：REST /rest/api/search 接口。
- 通用 JSON 搜索型内容平台：通过可配置的端点模板适配不同站点，
  例如掘金、CSDN 等具备公开搜索接口的平台。

合规说明：仅调用各站点**公开搜索接口**、只读取公开可见内容，
不登录、不绕过访问限制、不抓取需要授权的空间。
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Iterator
from urllib.parse import quote_plus

from ..models import RawDoc
from .base import SourceAdapter, SourceMeta, registry

logger = logging.getLogger("credwatch.sources.knowledge")

DEFAULT_WIKI_SITES = [
    "https://en.wikipedia.org",
    "https://zh.wikipedia.org",
]

DEFAULT_QUERIES = [
    "AKIA access key",
    "aws_secret_access_key example",
    "mysql root password",
    "SSH private key",
    "database connection string password",
]


@registry.register
class MediaWikiSource(SourceAdapter):
    """MediaWiki 系 Wiki 渠道。"""

    meta = SourceMeta(
        name="mediawiki",
        label="Wiki / MediaWiki 站点",
        category="Wiki 与知识库",
        description="通过 MediaWiki 标准 api.php 搜索接口检索公开 Wiki 页面，"
        "检测页面内容中粘贴的配置片段与凭据。",
        requires_token=False,
        rate_limit_per_minute=30,
        homepage="https://www.mediawiki.org",
    )

    def __init__(self, settings: Any, **options: Any) -> None:
        super().__init__(settings, **options)
        self.sites = options.get("sites") or DEFAULT_WIKI_SITES
        self.queries = options.get("queries") or DEFAULT_QUERIES
        self.max_items = int(options.get("max_items", 60))
        self.fetch_full_text = bool(options.get("fetch_full_text", True))

    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        yielded = 0
        for site in self.sites:
            for query in self.queries:
                for doc in self._search(site, query):
                    yielded += 1
                    if yielded > self.max_items:
                        return
                    yield doc

    def _search(self, site: str, query: str) -> Iterator[RawDoc]:
        self.limiter.acquire()
        resp = self.http.get(
            f"{site}/w/api.php",
            params={
                "action": "query",
                "list": "search",
                "srsearch": query,
                "srlimit": 20,
                "format": "json",
                "formatversion": 2,
            },
        )
        if resp is None or resp.status_code != 200:
            logger.debug("MediaWiki 搜索失败：%s", site)
            return
        try:
            results = (resp.json().get("query") or {}).get("search") or []
        except ValueError:
            return
        for item in results:
            title = item.get("title")
            if not title:
                continue
            snippet = item.get("snippet") or ""
            body = self._fetch_page(site, title) or snippet
            yield RawDoc(
                source=self.meta.name,
                external_id=f"{site}:{title}",
                url=f"{site}/wiki/{quote_plus(title.replace(' ', '_'))}",
                content=body.encode("utf-8"),
                published_at=self._parse_time(item.get("timestamp")),
                metadata={
                    "filename": f"{title.replace(' ', '_')}.wiki",
                    "path_hint": f"wiki/{title}",
                    "site": site,
                },
            )

    def _fetch_page(self, site: str, title: str) -> str | None:
        if not self.fetch_full_text:
            return None
        self.limiter.acquire()
        resp = self.http.get(
            f"{site}/w/api.php",
            params={
                "action": "query",
                "prop": "revisions",
                "rvprop": "content",
                "rvslots": "main",
                "titles": title,
                "format": "json",
                "formatversion": 2,
            },
        )
        if resp is None or resp.status_code != 200:
            return None
        try:
            pages = (resp.json().get("query") or {}).get("pages") or []
        except ValueError:
            return None
        if not pages:
            return None
        revisions = pages[0].get("revisions") or []
        if not revisions:
            return None
        content = (revisions[0].get("slots") or {}).get("main", {}).get("content")
        return content if isinstance(content, str) else None

    @staticmethod
    def _parse_time(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            return None

    def health_check(self) -> tuple[bool, str]:
        return True, f"目标站点 {len(self.sites)} 个"


@registry.register
class ConfluenceSource(SourceAdapter):
    """Confluence 渠道（含企业自建实例）。"""

    meta = SourceMeta(
        name="confluence",
        label="Confluence 知识库",
        category="Wiki 与知识库",
        description="通过 Confluence REST 搜索接口检索公开空间页面，"
        "检测运维文档、部署手册中粘贴的明文凭据。",
        requires_token=True,
        rate_limit_per_minute=20,
        homepage="https://www.atlassian.com/software/confluence",
    )

    def __init__(self, settings: Any, **options: Any) -> None:
        super().__init__(settings, **options)
        self.base_url = (options.get("base_url") or "").rstrip("/")
        self.token = options.get("token") or ""
        self.username = options.get("username") or ""
        self.queries = options.get("queries") or DEFAULT_QUERIES
        self.max_items = int(options.get("max_items", 60))

    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        if not self.base_url:
            logger.info("未配置 Confluence 地址，跳过该渠道")
            return
        headers: dict[str, str] = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        yielded = 0
        for query in self.queries:
            self.limiter.acquire()
            resp = self.http.get(
                f"{self.base_url}/rest/api/search",
                params={"cql": f'text ~ "{query}"', "limit": 25},
                headers=headers,
            )
            if resp is None or resp.status_code != 200:
                continue
            try:
                results = (resp.json().get("results") or [])[:25]
            except ValueError:
                continue
            for item in results:
                body = json.dumps(
                    {
                        "title": item.get("title"),
                        "excerpt": item.get("excerpt"),
                        "body": (item.get("body") or {}).get("view", {}).get("value"),
                        "url": item.get("url"),
                    },
                    ensure_ascii=False,
                )
                yielded += 1
                if yielded > self.max_items:
                    return
                yield RawDoc(
                    source=self.meta.name,
                    external_id=str(item.get("content", {}).get("id") or item.get("url")),
                    url=f"{self.base_url}{item.get('url') or ''}",
                    content=body.encode("utf-8"),
                    metadata={
                        "filename": f"{item.get('title', 'confluence-page')}.json",
                        "path_hint": f"confluence/{item.get('title', '')}",
                    },
                )

    def _has_token(self) -> bool:
        return bool(self.token)

    def health_check(self) -> tuple[bool, str]:
        if not self.base_url:
            return False, "未配置 Confluence 实例地址"
        return True, f"实例：{self.base_url}"


@registry.register
class DocShareSource(SourceAdapter):
    """通用知识共享平台渠道（搜索接口型）。

    不同平台的搜索接口形态各异，这里用"端点模板 + JSON 路径"的方式配置化，
    新增一个平台只需在 sources.yaml 里增加一段配置，无需改代码。
    """

    meta = SourceMeta(
        name="doc_share",
        label="知识共享平台（可配置搜索接口）",
        category="内容共享平台",
        description="以可配置的端点模板适配掘金、CSDN 等具备公开搜索接口的内容平台，"
        "检测技术博客、运维笔记中粘贴的凭据。",
        requires_token=False,
        rate_limit_per_minute=15,
        homepage="",
    )

    # 预置平台：search_url 中的 {query} / {page} 会被替换
    PRESET_PLATFORMS: dict[str, dict[str, Any]] = {
        "juejin": {
            "label": "掘金",
            "search_url": "https://api.juejin.cn/search_api/v1/search?query={query}&id_type=0&cursor=0&limit=20&search_type=0",
            "items_path": "data",
            "text_fields": ["title", "content", "result_type"],
            "url_template": "https://juejin.cn/post/{item_id}",
            "id_field": "result_id",
        },
    }

    def __init__(self, settings: Any, **options: Any) -> None:
        super().__init__(settings, **options)
        self.platforms = options.get("platforms") or []
        self.custom = options.get("custom_platforms") or {}
        self.queries = options.get("queries") or [
            "accessKey secret 配置",
            "数据库密码 配置",
        ]
        self.max_items = int(options.get("max_items", 60))

    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        yielded = 0
        for name in self.platforms:
            platform = self.custom.get(name) or self.PRESET_PLATFORMS.get(name)
            if not platform:
                logger.debug("未知内容平台：%s", name)
                continue
            for query in self.queries:
                for doc in self._search(name, platform, query):
                    yielded += 1
                    if yielded > self.max_items:
                        return
                    yield doc

    def _search(self, name: str, platform: dict[str, Any], query: str) -> Iterator[RawDoc]:
        url = platform["search_url"].replace("{query}", quote_plus(query))
        self.limiter.acquire()
        resp = self.http.get(url, headers={"Accept": "application/json"})
        if resp is None or resp.status_code != 200:
            return
        try:
            data = resp.json()
        except ValueError:
            return
        items: Any = data
        for key in platform.get("items_path", "").split("."):
            if not key:
                break
            items = (items or {}).get(key) if isinstance(items, dict) else None
        if not isinstance(items, list):
            return
        for item in items[:20]:
            if not isinstance(item, dict):
                continue
            text = "\n".join(
                str(item.get(field, "")) for field in platform.get("text_fields", [])
            )
            if not text.strip():
                continue
            item_id = str(item.get(platform.get("id_field", "id")) or "")
            yield RawDoc(
                source=self.meta.name,
                external_id=f"{name}:{item_id}",
                url=str(platform.get("url_template", "")).format(item_id=item_id),
                content=text.encode("utf-8"),
                published_at=datetime.now(timezone.utc),
                metadata={
                    "filename": f"{name}_{item_id}.json",
                    "path_hint": f"{name}/{item_id}",
                    "platform": name,
                },
            )

    def health_check(self) -> tuple[bool, str]:
        configured = [p for p in self.platforms if p in self.PRESET_PLATFORMS or p in self.custom]
        if not configured:
            return False, "未配置任何内容平台"
        return True, f"已启用平台：{', '.join(configured)}"
