"""Telegram 公开频道渠道。

大量开发者/运维"图省事"把配置、脚本、数据库 dump 发到公开 Telegram 频道，
这些频道通过 t.me/s/<频道名> 的**网页预览**无需登录即可访问。

合规说明：本适配器只访问公开网页预览页，不登录、不使用 Bot API 读取
私有内容、不绕过任何访问控制。
"""

from __future__ import annotations

import html as html_mod
import logging
import re
from datetime import datetime, timezone
from typing import Any, Iterator

from ..models import RawDoc
from .base import SourceAdapter, SourceMeta, registry

logger = logging.getLogger("credwatch.sources.telegram")

# 每条消息块：data-post 属性携带 "频道名/消息ID"
MESSAGE_RE = re.compile(
    r'<div[^>]*class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>',
    re.S,
)
POST_ATTR_RE = re.compile(r'data-post="([^"]+/[0-9]+)"')
TIME_RE = re.compile(r'<time[^>]*datetime="([^"]+)"')
TAG_RE = re.compile(r"<[^>]+>")
WHITESPACE_RE = re.compile(r"\n{3,}")


@registry.register
class TelegramPublicSource(SourceAdapter):
    """Telegram 公开频道网页预览渠道。"""

    meta = SourceMeta(
        name="telegram",
        label="Telegram 公开频道",
        category="社交媒体",
        description="扫描公开 Telegram 频道的网页预览（t.me/s/<频道>），"
        "检测其中张贴的配置、数据库 dump 与脚本中的凭据泄露。"
        "仅访问公开预览页，不登录、不使用 Bot API。",
        requires_token=False,
        rate_limit_per_minute=10,
        enabled_by_default=False,
        homepage="https://t.me",
    )

    def __init__(self, settings: Any, **options: Any) -> None:
        super().__init__(settings, **options)
        # 默认监控几个公开的技术/泄露相关频道；可在 sources.yaml 覆盖
        self.channels = options.get("channels") or ["durov"]
        self.max_items = int(options.get("max_items", 80))
        self.max_message_len = int(options.get("max_message_len", 100_000))

    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        cursor = cursor or {}
        last_post: dict[str, int] = cursor.get("last_post") or {}
        yielded = 0

        for channel in self.channels:
            channel = channel.strip().lstrip("@")
            if not channel:
                continue
            self.limiter.acquire()
            resp = self.http.get(f"https://t.me/s/{channel}")
            if resp is None or resp.status_code != 200 or not resp.text:
                logger.debug("频道 %s 预览页不可访问", channel)
                continue

            posts = self._parse_page(resp.text, channel)
            floor = int(last_post.get(channel, 0))
            new_posts = [p for p in posts if p[0] > floor] or posts

            for msg_id, published_at, text in new_posts[: self.max_items]:
                last_post[channel] = max(last_post.get(channel, 0), msg_id)
                yielded += 1
                if yielded > self.max_items:
                    break
                yield RawDoc(
                    source=self.meta.name,
                    external_id=f"tg:{channel}:{msg_id}",
                    url=f"https://t.me/{channel}/{msg_id}",
                    content=text.encode("utf-8", errors="ignore"),
                    author=channel,
                    published_at=published_at,
                    metadata={
                        "filename": f"tg_{channel}_{msg_id}.txt",
                        "path_hint": f"telegram/{channel}/{msg_id}",
                        "channel_name": channel,
                    },
                )
            if yielded > self.max_items:
                break

        # 光标回写：调度器会把同一 dict 持久化，实现增量去重
        cursor["last_post"] = last_post

    @staticmethod
    def _parse_page(page_html: str, channel: str) -> list[tuple[int, datetime, str]]:
        """解析预览页，返回 [(消息ID, 发布时间, 文本)]，按 ID 升序。

        按 data-post 出现位置把页面切成消息块，**在块内**匹配时间与文本——
        不能把全文的 post/time/text 三个列表按下标拉齐：
        纯媒体消息没有文本 div，会让后续所有消息错位（逻辑审查发现）。
        """
        marks = [
            (m.start(), int(m.group(1).rsplit("/", 1)[1]))
            for m in POST_ATTR_RE.finditer(page_html)
        ]
        out: list[tuple[int, datetime, str]] = []
        seen: set[int] = set()
        for idx, (pos, msg_id) in enumerate(marks):
            if msg_id in seen:
                continue
            seen.add(msg_id)
            seg_end = marks[idx + 1][0] if idx + 1 < len(marks) else len(page_html)
            segment = page_html[pos:seg_end]

            published = datetime.now(timezone.utc)
            tm = TIME_RE.search(segment)
            if tm:
                try:
                    published = datetime.fromisoformat(tm.group(1).replace("Z", "+00:00"))
                except ValueError:
                    pass

            text_m = MESSAGE_RE.search(segment)
            if not text_m:
                continue  # 纯媒体消息：无文本可扫
            text = html_mod.unescape(TAG_RE.sub("", text_m.group(1))).strip()
            if len(text) < 8:
                continue
            text = WHITESPACE_RE.sub("\n\n", text)[:100_000]
            out.append((msg_id, published, f"{text}\n"))
        out.sort(key=lambda x: x[0])
        return out

    def health_check(self) -> tuple[bool, str]:
        return True, f"监控频道：{', '.join(self.channels)}"
