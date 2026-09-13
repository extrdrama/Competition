"""Paste 类公开分享渠道。

Pastebin 这类"一次性贴代码"服务是凭据泄露重灾区：
开发者调试时把配置贴上去，以为链接不公开就安全，实际会被爬虫收录。

合规说明：本适配器只访问各站点**公开列表页与公开 Raw 页**，
不登录、不绕过任何访问控制、不抓取私有或加密内容。
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Iterator

from ..models import RawDoc
from .base import SourceAdapter, SourceMeta, registry

logger = logging.getLogger("credwatch.sources.paste")

PASTE_ID_RE = re.compile(r'href="/?(?:archive/)?([A-Za-z0-9]{6,12})["#?/>]')

PASTE_SITES: dict[str, dict[str, Any]] = {
    "pastebin": {
        "archive": "https://pastebin.com/archive",
        "raw": "https://pastebin.com/raw/{id}",
        "label": "Pastebin",
        # pastebin 公开贴 ID 恰为 8 位字母数字；导航链接（signup/archive 等）
        # 长度或构成不同，据此过滤——曾因导航链接淹没真 ID 导致整渠道抓取为 0
        "id_len": (8, 8),
        "junk": {"archive", "languages", "signup", "login", "faq", "api",
                 "tools", "privacy", "dmca", "contact", "themes", "assets",
                 "scopes", "domains"},
    },
}


@registry.register
class PasteSiteSource(SourceAdapter):
    """公开 Paste 站点渠道。"""

    meta = SourceMeta(
        name="paste_site",
        label="公开 Paste 分享站点",
        category="公开分享与代码片段",
        description="扫描 Pastebin 等公开 Paste 服务的最新公开列表，"
        "检测其中的凭据泄露。仅访问公开页面。",
        requires_token=False,
        rate_limit_per_minute=12,
        homepage="https://pastebin.com",
    )

    def __init__(self, settings: Any, **options: Any) -> None:
        super().__init__(settings, **options)
        self.sites = options.get("sites") or ["pastebin"]
        self.max_items = int(options.get("max_items", 120))
        self.recent_hours = int(options.get("recent_hours", 24))

    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        cursor = cursor or {}
        seen: set[str] = set(cursor.get("seen_ids") or [])
        yielded = 0
        for site in self.sites:
            config = PASTE_SITES.get(site)
            if not config:
                continue
            self.limiter.acquire()
            listing = self.http.get(config["archive"])
            if listing is None or listing.status_code != 200:
                logger.debug("%s 列表页不可访问", site)
                continue
            ids = self._extract_ids(listing.text)
            for paste_id in ids:
                key = f"{site}:{paste_id}"
                if key in seen:
                    continue
                seen.add(key)
                raw = self._fetch_paste(site, config, paste_id)
                if raw is None:
                    continue
                yielded += 1
                if yielded > self.max_items:
                    return
                yield raw

    @staticmethod
    def _extract_ids(html: str) -> list[str]:
        ids = [m.group(1) for m in PASTE_ID_RE.finditer(html)]
        # 去重且保持顺序
        out: list[str] = []
        seen: set[str] = set()
        for i in ids:
            if i not in seen and not i.isdigit():
                seen.add(i)
                out.append(i)
        return out[:60]

    def _fetch_paste(self, site: str, config: dict[str, str], paste_id: str) -> RawDoc | None:
        raw_url = config["raw"].format(id=paste_id)
        self.limiter.acquire()
        resp = self.http.get(raw_url)
        if resp is None or resp.status_code != 200 or not resp.content:
            return None
        # 过大内容跳过（贴大文件通常不是配置泄露）
        if len(resp.content) > 1_000_000:
            return None
        return RawDoc(
            source=self.meta.name,
            external_id=f"{site}:{paste_id}",
            url=f"{config['raw'].replace('/raw/', '/')}".format(id=paste_id)
            if site == "pastebin"
            else raw_url,
            content=resp.content,
            published_at=datetime.now(timezone.utc),
            metadata={
                "filename": f"{site}_{paste_id}.txt",
                "path_hint": f"{site}/{paste_id}",
                "site": site,
                "site_label": config["label"],
            },
        )

    def health_check(self) -> tuple[bool, str]:
        return True, f"目标站点：{', '.join(self.sites)}"
