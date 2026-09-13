"""通用 RSS/Atom 订阅渠道。

技术博客、企业安全公告、邮件列表归档、个人站点的 RSS/Atom 输出里
同样会出现"贴配置求救"式的凭据泄露。本适配器是**可配置的通用渠道**：
在 sources.yaml 里填任意数量的订阅源即可纳入监控，无需写新适配器。

合规说明：仅获取站点主动 syndicate 的公开 feed，不登录、不抓取
未公开内容，遵循 robots 语义（feed 本身即供订阅）。
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Iterator
from xml.etree import ElementTree

from ..models import RawDoc
from .base import SourceAdapter, SourceMeta, registry

logger = logging.getLogger("credwatch.sources.rss")

TAG_RE = re.compile(r"<[^>]+>")
CDATA_RE = re.compile(r"<!\[CDATA\[(.*?)\]\]>", re.S)

# RSS 2.0 的 <item> 与 Atom 的 <entry> 统一按元素提取
ITEM_TAGS = ("item", "entry")
TEXT_CHILD_TAGS = ("title", "description", "content:encoded", "content", "summary")
DATE_CHILD_TAGS = ("pubDate", "updated", "published")
LINK_TAGS = ("link",)


def _strip_html(fragment: str) -> str:
    if not fragment:
        return ""
    fragment = CDATA_RE.sub(r"\1", fragment)
    return TAG_RE.sub(" ", fragment).replace("&amp;", "&").replace(
        "&lt;", "<"
    ).replace("&gt;", ">").replace("&quot;", '"').replace("&#39;", "'").strip()


def _parse_date(raw: str) -> datetime | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        return parsedate_to_datetime(raw)  # RFC 822（RSS 2.0）
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))  # ISO 8601（Atom）
    except ValueError:
        return None


@registry.register
class RssFeedSource(SourceAdapter):
    """通用 RSS/Atom 订阅渠道（feed 列表由配置驱动）。"""

    meta = SourceMeta(
        name="rss_feed",
        label="RSS/Atom 订阅源",
        category="自托管与公告",
        description="通用 RSS/Atom 订阅渠道：在配置中填入任意数量的订阅源"
        "（技术博客、安全公告、邮件列表归档等）即可纳入监控，"
        "检测博客与公告中误贴的凭据。仅获取站点主动发布的公开 feed。",
        requires_token=False,
        rate_limit_per_minute=30,
        enabled_by_default=False,
        homepage="",
    )

    def __init__(self, settings: Any, **options: Any) -> None:
        super().__init__(settings, **options)
        self.feeds = [f for f in (options.get("feeds") or []) if f]
        self.max_items = int(options.get("max_items", 100))

    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        cursor = cursor or {}
        seen: set[str] = set(cursor.get("seen_links") or [])
        yielded = 0

        for feed_url in self.feeds:
            if yielded > self.max_items:
                break
            self.limiter.acquire()
            resp = self.http.get(feed_url)
            if resp is None or resp.status_code != 200 or not resp.text:
                logger.debug("feed 不可访问：%s", feed_url)
                continue
            try:
                items = self._parse_feed(resp.text)
            except ElementTree.ParseError:
                logger.debug("feed XML 解析失败：%s", feed_url)
                continue

            feed_label = self._feed_label(feed_url)
            for link, published, text in items:
                key = link or text[:60]
                if key in seen:
                    continue
                seen.add(key)
                yielded += 1
                if yielded > self.max_items:
                    break
                yield RawDoc(
                    source=self.meta.name,
                    external_id=f"rss:{hashlib_sha1(link or text[:80])}",
                    url=link or feed_url,
                    content=text.encode("utf-8", errors="ignore"),
                    published_at=published or datetime.now(timezone.utc),
                    metadata={
                        "filename": f"{feed_label}.txt",
                        "path_hint": f"rss/{feed_label}",
                        "feed": feed_url,
                    },
                )

        cursor["seen_links"] = list(seen)[-500:]

    def _parse_feed(self, text: str) -> list[tuple[str, datetime | None, str]]:
        """解析 RSS 2.0 / Atom，返回 [(链接, 发布时间, 正文)]。"""
        root = ElementTree.fromstring(text)
        items: list[tuple[str, datetime | None, str]] = []
        for elem in root.iter():
            if elem.tag.rsplit("}", 1)[-1] not in ITEM_TAGS:
                continue
            title, body, link, published = "", "", "", None
            for child in elem.iter():
                tag = child.tag.rsplit("}", 1)[-1]
                if tag == "title" and not title:
                    title = _strip_html(child.text or "")
                elif tag in ("description", "summary", "encoded") and not body:
                    body = _strip_html(child.text or "")
                elif tag == "content" and not body:
                    body = _strip_html(child.text or "")
                elif tag == "link" and not link:
                    link = (child.text or "").strip() or (child.get("href") or "")
                elif tag in ("pubDate", "updated", "published") and published is None:
                    published = _parse_date(child.text or "")
            combined = f"{title}\n{body}".strip()
            if combined:
                items.append((link, published, combined[:100_000] + "\n"))
        return items

    @staticmethod
    def _feed_label(feed_url: str) -> str:
        host = re.sub(r"^https?://", "", feed_url).split("/")[0]
        return re.sub(r"[^A-Za-z0-9_.-]", "_", host)

    def health_check(self) -> tuple[bool, str]:
        return True, f"订阅源 {len(self.feeds)} 个"


def hashlib_sha1(text: str) -> str:
    """短哈希用于外部 ID（非安全用途）。"""
    import hashlib

    return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()[:16]
