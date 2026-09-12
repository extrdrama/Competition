"""包仓库渠道：npm 与 PyPI。

为什么包仓库是凭据渠道：开发者发布包时，`.npmignore` / `MANIFEST.in`
配置不全，会把 `.env`、`.npmrc`、`config.json`、测试脚本一起打包上传。
这些包一旦发布就永久可下载，且会被镜像站二次分发。
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Iterator

from ..models import RawDoc
from .base import SourceAdapter, SourceMeta, registry

logger = logging.getLogger("credwatch.sources.package")

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_JSON = "https://pypi.org/pypi"
PYPI_UPDATES_RSS = "https://pypi.org/rss/updates.xml"

RSS_ITEM_RE = re.compile(r"<item>[\s\S]*?<title>([^<]+)</title>[\s\S]*?</item>")

DEFAULT_NPM_SEARCH = ["config secrets", "dotenv config", "internal tool"]


@registry.register
class NpmPackageSource(SourceAdapter):
    """npm 包仓库渠道。"""

    meta = SourceMeta(
        name="npm_registry",
        label="npm 包仓库",
        category="包仓库",
        description="检索 npm 公开包并下载 tarball，检测误打包进发布包的"
        "配置与凭据文件；支持按关键词搜索最新发布的包。",
        requires_token=False,
        rate_limit_per_minute=20,
        homepage="https://www.npmjs.com",
    )

    def __init__(self, settings: Any, **options: Any) -> None:
        super().__init__(settings, **options)
        self.packages = options.get("packages") or []
        self.search_queries = options.get("search_queries") or DEFAULT_NPM_SEARCH
        self.max_items = int(options.get("max_items", 40))
        self.max_tarball_bytes = int(options.get("max_tarball_bytes", 20_000_000))

    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        targets = list(self.packages) or self._search()
        for name in targets[: self.max_items]:
            doc = self._fetch_package(name)
            if doc is not None:
                yield doc

    def _search(self) -> list[str]:
        found: list[str] = []
        for query in self.search_queries:
            self.limiter.acquire()
            resp = self.http.get(
                f"{NPM_REGISTRY}/-/v1/search", params={"text": query, "size": 20}
            )
            if resp is None or resp.status_code != 200:
                continue
            try:
                objects = resp.json().get("objects") or []
            except ValueError:
                continue
            found.extend((o.get("package") or {}).get("name", "") for o in objects)
        return [n for n in dict.fromkeys(found) if n]

    def _fetch_package(self, name: str) -> RawDoc | None:
        self.limiter.acquire()
        resp = self.http.get(f"{NPM_REGISTRY}/{name}")
        if resp is None or resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        latest = (data.get("dist-tags") or {}).get("latest")
        version_meta = (data.get("versions") or {}).get(latest) or {}
        tarball = (version_meta.get("dist") or {}).get("tarball")
        if not tarball:
            return None
        self.limiter.acquire()
        pkg = self.http.get(tarball)
        if pkg is None or pkg.status_code != 200:
            return None
        if len(pkg.content) > self.max_tarball_bytes:
            return None
        published = self._parse_time((data.get("time") or {}).get(latest))
        return RawDoc(
            source=self.meta.name,
            external_id=f"{name}@{latest}",
            url=f"https://www.npmjs.com/package/{name}",
            content=pkg.content,
            content_type="application/x-tar.gz",
            published_at=published,
            metadata={
                "filename": f"{name.replace('/', '__')}-{latest}.tgz",
                "path_hint": f"npm/{name}/package.tar.gz",
                "channel": "package_tarball",
                "package": name,
                "version": latest,
            },
        )

    @staticmethod
    def _parse_time(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            return None

    def health_check(self) -> tuple[bool, str]:
        return True, f"目标包 {len(self.packages) or '（按关键词搜索）'}"


@registry.register
class PyPiPackageSource(SourceAdapter):
    """PyPI 包仓库渠道。"""

    meta = SourceMeta(
        name="pypi_registry",
        label="PyPI 包仓库",
        category="包仓库",
        description="通过 PyPI 最近更新榜单与指定包名拉取源码分发包（sdist），"
        "检测误打包的 .env / 凭据配置。",
        requires_token=False,
        rate_limit_per_minute=20,
        homepage="https://pypi.org",
    )

    def __init__(self, settings: Any, **options: Any) -> None:
        super().__init__(settings, **options)
        self.packages = options.get("packages") or []
        self.max_items = int(options.get("max_items", 40))
        self.prefer_sdist = bool(options.get("prefer_sdist", True))

    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        targets = list(self.packages) or self._recent()
        for name in targets[: self.max_items]:
            doc = self._fetch_package(name)
            if doc is not None:
                yield doc

    def _recent(self) -> list[str]:
        """读取 PyPI 官方"最近更新"RSS，天然是增量且时效性最好。"""
        self.limiter.acquire()
        resp = self.http.get(PYPI_UPDATES_RSS)
        if resp is None or resp.status_code != 200:
            return []
        names = [m.group(1).strip() for m in RSS_ITEM_RE.finditer(resp.text)]
        # RSS 标题形如 "package 1.2.3"
        return [n.rsplit(" ", 1)[0] for n in names if n]

    def _fetch_package(self, name: str) -> RawDoc | None:
        self.limiter.acquire()
        resp = self.http.get(f"{PYPI_JSON}/{name}/json")
        if resp is None or resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        info = data.get("info") or {}
        urls = data.get("urls") or []
        chosen = self._pick_artifact(urls)
        if chosen is None:
            return None
        self.limiter.acquire()
        artifact = self.http.get(chosen["url"])
        if artifact is None or artifact.status_code != 200:
            return None
        if len(artifact.content) > 20_000_000:
            return None
        return RawDoc(
            source=self.meta.name,
            external_id=f"{name}=={info.get('version')}",
            url=info.get("project_url") or f"https://pypi.org/project/{name}/",
            content=artifact.content,
            content_type="application/x-tar.gz",
            published_at=None,
            metadata={
                "filename": chosen["filename"],
                "path_hint": f"pypi/{name}/{chosen['filename']}",
                "channel": "package_tarball",
                "package": name,
                "version": info.get("version"),
            },
        )

    def _pick_artifact(self, urls: list[dict[str, Any]]) -> dict[str, Any] | None:
        if not urls:
            return None
        if self.prefer_sdist:
            for item in urls:
                if item.get("packagetype") == "sdist" and item.get("url"):
                    return item
        for item in urls:
            if item.get("url"):
                return item
        return None

    def health_check(self) -> tuple[bool, str]:
        return True, f"目标包 {len(self.packages) or '（按最近更新榜单）'}"
