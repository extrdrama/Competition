"""GitHub 渠道适配器。

三种采集模式，对应不同的时效性/覆盖度取舍：
- `search`：按查询语句使用代码搜索 API，覆盖存量历史泄露（广度优先）。
- `repo`  ：遍历指定仓库的文件树，适合针对已确认的高风险仓库深挖。
- `recent`：读取公共事件流，抓取**刚刚推送**的内容（时效性最优，
  是 MTTD 指标能做到分钟级的关键）。
- `gist`  ：扫描公开 Gist，这类文件最容易被误当作"一次性分享"而泄露凭据。
"""

from __future__ import annotations

import base64
import logging
import re
from datetime import datetime, timezone
from typing import Any, Iterator
from urllib.parse import quote

from ..models import RawDoc
from .base import SourceAdapter, SourceMeta, TokenPool, registry

logger = logging.getLogger("credwatch.sources.github")

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"

# 值得拉取的路径特征（凭据高发区）
INTERESTING_PATH_RE = re.compile(
    r"(?i)(?:\.env|\.env\.|credentials|\.npmrc|\.pypirc|\.netrc|\.docker/config\.json|"
    r"service[_-]?account|kubeconfig|secret|password|token|api[_-]?key|"
    r"\.pem$|\.key$|\.ppk$|\.p12$|docker-compose|\.ya?ml$|\.properties$|"
    r"\.ini$|\.conf$|\.cfg$|application\.(?:yml|yaml|properties)|settings\.py|"
    r"\.git-credentials|\.htpasswd|wp-config\.php|config\.(?:json|php|py|js|ts)$)"
)

DEFAULT_QUERIES = [
    # 使用 GitHub 代码搜索语法，缩小到"文件名 + 关键词"的组合
    'filename:.env "AWS_ACCESS_KEY_ID"',
    'filename:.env "SECRET_KEY"',
    'filename:credentials "aws_access_key_id"',
    'filename:docker-compose.yml "password"',
    '"glpat-" in:file',
    '"AKIA" in:file filename:.env',
    'filename:.npmrc "_authToken"',
]


@registry.register
class GitHubSource(SourceAdapter):
    """GitHub 代码托管渠道。"""

    meta = SourceMeta(
        name="github",
        label="GitHub 代码托管平台",
        category="代码托管平台",
        description="通过代码搜索 API、仓库树遍历、公共事件流与公开 Gist "
        "四个子通道检索公开仓库中的凭据泄露。",
        requires_token=True,
        rate_limit_per_minute=24,
        homepage="https://github.com",
    )

    def __init__(self, settings: Any, **options: Any) -> None:
        super().__init__(settings, **options)
        self.tokens = TokenPool(getattr(settings, "github_tokens", []) or [])
        self.mode = options.get("mode", "search")
        self.queries = options.get("queries") or DEFAULT_QUERIES
        self.repos = options.get("repos") or []
        self.max_items = int(options.get("max_items", 200))
        self.per_page = int(options.get("per_page", 30))
        self.include_gist = bool(options.get("include_gist", True))
        self.fetch_content = bool(options.get("fetch_content", True))

    # ------------------------------------------------------------------ 主流程

    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        cursor = cursor or {}
        yielded = 0
        if self.mode == "recent":
            iterator = self._discover_recent(cursor)
        elif self.mode == "repo":
            iterator = self._discover_repos(cursor)
        else:
            iterator = self._discover_search(cursor)

        for doc in iterator:
            yielded += 1
            if yielded > self.max_items:
                return
            yield doc

        if self.include_gist and self.mode in ("search", "recent"):
            for doc in self._discover_gists(cursor):
                yielded += 1
                if yielded > self.max_items * 2:
                    return
                yield doc

    # ------------------------------------------------------------ 模式一：搜索

    def _discover_search(self, cursor: dict[str, Any]) -> Iterator[RawDoc]:
        done = set(cursor.get("done_queries") or [])
        for query in self.queries:
            if query in done:
                continue
            self.limiter.acquire()
            resp = self._api_get(
                "/search/code",
                params={"q": query, "per_page": self.per_page, "sort": "indexed"},
                accept="application/vnd.github.text-match+json",
            )
            if resp is None or resp.status_code != 200:
                logger.debug("代码搜索失败：%s", query)
                continue
            for item in (resp.json().get("items") or [])[: self.per_page]:
                raw = self._fetch_blob_from_item(item)
                if raw is not None:
                    yield raw

    # -------------------------------------------------------- 模式二：仓库深挖

    def _discover_repos(self, cursor: dict[str, Any]) -> Iterator[RawDoc]:
        done = set(cursor.get("done_repos") or [])
        for repo in self.repos:
            if repo in done:
                continue
            self.limiter.acquire()
            resp = self._api_get(f"/repos/{repo}/git/trees/HEAD", params={"recursive": "1"})
            if resp is None or resp.status_code != 200:
                logger.debug("仓库树读取失败：%s", repo)
                continue
            for node in resp.json().get("tree") or []:
                if node.get("type") != "blob":
                    continue
                path = node.get("path", "")
                if not INTERESTING_PATH_RE.search(path):
                    continue
                if node.get("size", 0) > 2_000_000:
                    continue
                raw = self._fetch_raw_file(repo, path, ref="HEAD")
                if raw is not None:
                    yield raw

    # ------------------------------------------------------ 模式三：事件流时效

    def _discover_recent(self, cursor: dict[str, Any]) -> Iterator[RawDoc]:
        """读取公共事件流，抓取刚刚推送的提交内容。"""
        seen_commits: set[str] = set(cursor.get("seen_commits") or [])
        resp = self._api_get("/events", params={"per_page": 100})
        if resp is None or resp.status_code != 200:
            logger.debug("事件流读取失败")
            return
        for event in resp.json() or []:
            if event.get("type") != "PushEvent":
                continue
            repo = (event.get("repo") or {}).get("name")
            if not repo:
                continue
            for commit in (event.get("payload") or {}).get("commits") or []:
                sha = commit.get("sha")
                if not sha or sha in seen_commits:
                    continue
                seen_commits.add(sha)
                for path in self._commit_files(repo, sha):
                    if not INTERESTING_PATH_RE.search(path):
                        continue
                    raw = self._fetch_raw_file(repo, path, ref=sha)
                    if raw is not None:
                        raw.metadata["commit"] = sha
                        raw.metadata["event_pushed_at"] = event.get("created_at")
                        yield raw

    def _commit_files(self, repo: str, sha: str) -> list[str]:
        self.limiter.acquire()
        resp = self._api_get(f"/repos/{repo}/commits/{sha}")
        if resp is None or resp.status_code != 200:
            return []
        data = resp.json()
        files = [f.get("filename", "") for f in (data.get("files") or [])]
        return [f for f in files if f]

    # ------------------------------------------------------------------ Gist

    def _discover_gists(self, cursor: dict[str, Any]) -> Iterator[RawDoc]:
        resp = self._api_get("/gists/public", params={"per_page": 100})
        if resp is None or resp.status_code != 200:
            return
        for gist in resp.json() or []:
            gist_id = gist.get("id")
            created = self._parse_time(gist.get("created_at"))
            for name, fileinfo in (gist.get("files") or {}).items():
                raw_url = fileinfo.get("raw_url")
                if not raw_url or fileinfo.get("size", 0) > 1_000_000:
                    continue
                self.limiter.acquire()
                content = self.http.get(raw_url)
                if content is None or content.status_code != 200:
                    continue
                yield RawDoc(
                    source=self.meta.name,
                    external_id=f"gist:{gist_id}:{name}",
                    url=gist.get("html_url") or raw_url,
                    content=content.content,
                    author=(gist.get("owner") or {}).get("login"),
                    published_at=created,
                    metadata={"filename": name, "path_hint": name, "channel": "gist"},
                )

    # ------------------------------------------------------------- 内容拉取

    def _fetch_blob_from_item(self, item: dict[str, Any]) -> RawDoc | None:
        repo_full = (item.get("repository") or {}).get("full_name")
        path = item.get("path")
        if not repo_full or not path:
            return None
        return self._fetch_raw_file(repo_full, path, ref="HEAD", html_url=item.get("html_url"))

    def _fetch_raw_file(
        self, repo: str, path: str, ref: str = "HEAD", html_url: str | None = None
    ) -> RawDoc | None:
        if not self.options.get("download_content", True):
            # 只上报命中位置，不下载内容（降低带宽与合规风险时使用）
            return None
        self.limiter.acquire()
        url = f"{RAW}/{repo}/{ref}/{quote(path)}"
        resp = self.http.get(url)
        if resp is None or resp.status_code != 200:
            # 回退到 Contents API（部分分支/私有路径只能走 API）
            resp = self._fetch_via_contents(repo, path, ref)
            if resp is None:
                return None
        return RawDoc(
            source=self.meta.name,
            external_id=f"{repo}:{ref}:{path}",
            url=html_url or f"https://github.com/{repo}/blob/{ref}/{path}",
            content=resp.content,
            author=repo.split("/")[0],
            published_at=None,
            metadata={
                "filename": path.rsplit("/", 1)[-1],
                "path_hint": path,
                "repo": repo,
                "ref": ref,
                "channel": "code",
            },
        )

    def _fetch_via_contents(self, repo: str, path: str, ref: str):
        self.limiter.acquire()
        resp = self._api_get(f"/repos/{repo}/contents/{quote(path)}", params={"ref": ref})
        if resp is None or resp.status_code != 200:
            return None
        data = resp.json()
        if isinstance(data, dict) and data.get("content"):
            try:
                payload = base64.b64decode(data["content"])
            except (ValueError, TypeError):
                return None
            return type("R", (), {"content": payload, "status_code": 200})()
        return None

    # ------------------------------------------------------------------ 工具

    def _api_get(self, path: str, params: dict[str, Any] | None = None, accept: str | None = None):
        headers = {"Accept": accept or "application/vnd.github+json"}
        token = self.tokens.current()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        resp = self.http.get(f"{API}{path}", params=params, headers=headers)
        if resp is not None and resp.status_code in (403, 429) and not self.tokens.empty:
            headers["Authorization"] = f"Bearer {self.tokens.rotate()}"
            resp = self.http.get(f"{API}{path}", params=params, headers=headers)
        return resp

    @staticmethod
    def _parse_time(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def _has_token(self) -> bool:
        return not self.tokens.empty

    def health_check(self) -> tuple[bool, str]:
        token_count = len(self.tokens.tokens)
        if token_count == 0:
            return False, "未配置 GITHUB_TOKENS，仅事件流与公开 Gist 可用"
        return True, f"已配置 {token_count} 个令牌，模式={self.mode}"
