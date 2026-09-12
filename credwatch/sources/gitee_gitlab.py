"""Gitee 与 GitLab 渠道适配器。

两个平台都提供代码搜索接口（需令牌）：
- Gitee：GET /api/v5/search/code
- GitLab：GET /api/v4/search?scope=blobs（支持自建实例，改 base_url 即可）
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Iterator
from urllib.parse import quote

from ..models import RawDoc
from .base import SourceAdapter, SourceMeta, registry
from .github import INTERESTING_PATH_RE

logger = logging.getLogger("credwatch.sources.vcs")

GITEE_API = "https://gitee.com/api/v5"

DEFAULT_GITEE_QUERIES = [
    "AWS_ACCESS_KEY_ID",
    "aws_secret_access_key",
    "glpat-",
    "accessKeySecret",
]

DEFAULT_GITLAB_QUERIES = [
    "AWS_ACCESS_KEY_ID",
    "glpat-",
    "BEGIN RSA PRIVATE KEY",
    "password",
]


@registry.register
class GiteeSource(SourceAdapter):
    """Gitee 代码托管平台渠道。"""

    meta = SourceMeta(
        name="gitee",
        label="Gitee 代码托管平台",
        category="代码托管平台",
        description="通过 Gitee 开放 API 的代码搜索接口检索公开仓库中的凭据泄露。",
        requires_token=True,
        rate_limit_per_minute=20,
        homepage="https://gitee.com",
    )

    def __init__(self, settings: Any, **options: Any) -> None:
        super().__init__(settings, **options)
        self.token = getattr(settings, "gitee_token", "") or ""
        self.queries = options.get("queries") or DEFAULT_GITEE_QUERIES
        self.max_items = int(options.get("max_items", 200))
        self.per_page = int(options.get("per_page", 20))

    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        if not self.token:
            logger.info("未配置 GITEE_TOKEN，跳过 gitee 渠道")
            return
        cursor = cursor or {}
        done = set(cursor.get("done_queries") or [])
        yielded = 0
        for query in self.queries:
            if query in done:
                continue
            for page in range(1, 6):
                self.limiter.acquire()
                resp = self.http.get(
                    f"{GITEE_API}/search/code",
                    params={
                        "access_token": self.token,
                        "q": query,
                        "page": page,
                        "per_page": self.per_page,
                    },
                )
                if resp is None or resp.status_code != 200:
                    break
                items = resp.json() if isinstance(resp.json(), list) else []
                if not items:
                    break
                for item in items:
                    raw = self._to_rawdoc(item, query)
                    if raw is not None:
                        yielded += 1
                        if yielded > self.max_items:
                            return
                        yield raw

    def _to_rawdoc(self, item: dict[str, Any], query: str) -> RawDoc | None:
        repo = (item.get("repository") or {}).get("full_name") or item.get("repo")
        path = item.get("path")
        if not repo or not path:
            return None
        html_url = item.get("html_url") or f"https://gitee.com/{repo}/blob/HEAD/{path}"
        return RawDoc(
            source=self.meta.name,
            external_id=f"{repo}:{path}",
            url=html_url,
            content=self._build_search_content(item, query),
            author=repo.split("/")[0],
            published_at=self._parse_time(item.get("updated_at")),
            metadata={"filename": path.rsplit("/", 1)[-1], "path_hint": path, "repo": repo},
        )

    @staticmethod
    def _build_search_content(item: dict[str, Any], query: str) -> bytes:
        """搜索结果通常只返回片段，拼装为可检测文本。"""
        parts = []
        for key in ("content", "snippet", "text_matches", "highlight"):
            value = item.get(key)
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, list):
                parts.extend(str(v) for v in value)
        parts.append(f"# query: {query}")
        parts.append(f"# file: {item.get('path', '')}")
        return "\n".join(parts).encode("utf-8")

    @staticmethod
    def _parse_time(value: str | None) -> datetime | None:
        if not value:
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(value, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                continue
        return None

    def _has_token(self) -> bool:
        return bool(self.token)

    def health_check(self) -> tuple[bool, str]:
        return (True, "已配置令牌") if self.token else (False, "未配置 GITEE_TOKEN")


@registry.register
class GitLabSource(SourceAdapter):
    """GitLab 渠道（兼容自建实例）。"""

    meta = SourceMeta(
        name="gitlab",
        label="GitLab（含自建实例）",
        category="代码托管平台",
        description="通过 GitLab Blob 搜索 API 检索公开项目中的凭据；"
        "修改 GITLAB_BASE_URL 后即可覆盖企业内部自建 GitLab 实例。",
        requires_token=True,
        rate_limit_per_minute=20,
        homepage="https://gitlab.com",
    )

    def __init__(self, settings: Any, **options: Any) -> None:
        super().__init__(settings, **options)
        self.token = getattr(settings, "gitlab_token", "") or ""
        self.base_url = (options.get("base_url") or getattr(settings, "gitlab_base_url", "")
                         or "https://gitlab.com").rstrip("/")
        self.queries = options.get("queries") or DEFAULT_GITLAB_QUERIES
        self.max_items = int(options.get("max_items", 200))

    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        if not self.token:
            logger.info("未配置 GITLAB_TOKEN，跳过 gitlab 渠道")
            return
        headers = {"PRIVATE-TOKEN": self.token}
        yielded = 0
        for query in self.queries:
            for page in range(1, 6):
                self.limiter.acquire()
                resp = self.http.get(
                    f"{self.base_url}/api/v4/search",
                    params={"scope": "blobs", "search": query, "page": page, "per_page": 20},
                    headers=headers,
                )
                if resp is None or resp.status_code != 200:
                    break
                payload = resp.json()
                if not isinstance(payload, list) or not payload:
                    break
                for item in payload:
                    raw = self._to_rawdoc(item, query)
                    if raw is None:
                        continue
                    yielded += 1
                    if yielded > self.max_items:
                        return
                    yield raw

    def _to_rawdoc(self, item: dict[str, Any], query: str) -> RawDoc | None:
        project_id = item.get("project_id")
        path = item.get("path")
        if project_id is None or not path:
            return None
        ref = item.get("ref") or "HEAD"
        content = (item.get("data") or "") + f"\n# file: {path}\n# query: {query}"
        start_line = item.get("startline")
        return RawDoc(
            source=self.meta.name,
            external_id=f"{project_id}:{ref}:{path}:{start_line}",
            url=f"{self.base_url}/-/project/{project_id}/blob/{quote(ref)}/{quote(path)}"
            + (f"#L{start_line}" if start_line else ""),
            content=content.encode("utf-8"),
            published_at=None,
            metadata={
                "filename": path.rsplit("/", 1)[-1],
                "path_hint": path,
                "project_id": project_id,
                "ref": ref,
            },
        )

    def _has_token(self) -> bool:
        return bool(self.token)

    def health_check(self) -> tuple[bool, str]:
        if not self.token:
            return False, "未配置 GITLAB_TOKEN"
        return True, f"实例：{self.base_url}"
