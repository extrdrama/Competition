"""容器镜像仓库渠道。

这是凭据泄露里最容易被忽视、但危害最大的渠道之一：
1. 镜像**分层**存储，某层里写入过密钥，即使后面的层删掉文件，
   前面的层依然保留了完整内容（"删了不等于没有"）。
2. 镜像**构建历史**（config blob 的 history 字段）会记录每一层
   的构建命令，`ENV SECRET_KEY=...`、`ARG TOKEN=...` 会被完整保留。
3. 大量企业把内部镜像推到公开仓库，误以为"没人知道名字就安全"。

实现依据公开的 OCI / Docker Registry V2 HTTP API，
对公开镜像使用匿名令牌拉取，不涉及任何鉴权绕过。
"""

from __future__ import annotations

import gzip
import json
import logging
from datetime import datetime, timezone
from typing import Any, Iterator

from ..models import RawDoc
from .base import SourceAdapter, SourceMeta, registry

logger = logging.getLogger("credwatch.sources.registry")

DOCKER_HUB_API = "https://hub.docker.com/v2"
DOCKER_AUTH = "https://auth.docker.io/token"
DOCKER_REGISTRY = "https://registry-1.docker.io"

MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
    )
)

# 目标仓库：默认取一批常见基础镜像 + 配置中指定的业务镜像
DEFAULT_REPOSITORIES = ["library/nginx", "library/redis", "library/mysql"]


@registry.register
class ContainerRegistrySource(SourceAdapter):
    """容器镜像仓库渠道（Docker Hub 及兼容 Registry V2 的私仓）。"""

    meta = SourceMeta(
        name="container_registry",
        label="容器镜像仓库",
        category="容器镜像",
        description="拉取公开镜像的配置 blob 与文件系统层，检测构建历史"
        "（ENV/ARG 残留）与层内配置文件中的凭据；支持 Docker Hub 与兼容 "
        "Registry V2 API 的私有仓库。",
        requires_token=False,
        rate_limit_per_minute=20,
        homepage="https://hub.docker.com",
    )

    def __init__(self, settings: Any, **options: Any) -> None:
        super().__init__(settings, **options)
        self.repositories = options.get("repositories") or DEFAULT_REPOSITORIES
        self.search_queries = options.get("search_queries") or []
        self.tags_per_repo = int(options.get("tags_per_repo", 3))
        self.max_layer_bytes = int(options.get("max_layer_bytes", 80_000_000))
        self.scan_layers = bool(options.get("scan_layers", True))
        self.scan_history = bool(options.get("scan_history", True))
        self.registry_url = (options.get("registry_url") or DOCKER_REGISTRY).rstrip("/")
        self.auth_url = options.get("auth_url") or DOCKER_AUTH
        self.service = options.get("service") or "registry.docker.io"

    # ------------------------------------------------------------------ 主流程

    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        cursor = cursor or {}
        seen_tags: set[str] = set(cursor.get("seen_tags") or [])
        repositories = list(self.repositories)
        if self.search_queries:
            repositories.extend(self._search_repositories())

        for repo in dict.fromkeys(repositories):
            token = self._get_token(repo)
            for tag_info in self._list_tags(repo):
                tag = tag_info.get("name")
                key = f"{repo}:{tag}"
                if not tag or key in seen_tags:
                    continue
                seen_tags.add(key)
                manifest = self._get_manifest(repo, tag, token)
                if manifest is None:
                    continue
                published = self._parse_time(tag_info.get("last_updated"))

                if self.scan_history:
                    config = self._get_config_blob(repo, manifest, token)
                    if config is not None:
                        yield self._config_to_rawdoc(repo, tag, config, published)

                if self.scan_layers:
                    for layer_doc in self._iter_layers(repo, manifest, tag, token, published):
                        yield layer_doc

    # ------------------------------------------------------------ Docker Hub API

    def _search_repositories(self) -> list[str]:
        found: list[str] = []
        for query in self.search_queries:
            self.limiter.acquire()
            resp = self.http.get(
                f"{DOCKER_HUB_API}/search/repositories/",
                params={"query": query, "page_size": 25},
            )
            if resp is None or resp.status_code != 200:
                continue
            for item in (resp.json().get("results") or [])[:25]:
                name = item.get("repo_name") or ""
                if name:
                    found.append(name)
        return found

    def _list_tags(self, repo: str) -> list[dict[str, Any]]:
        self.limiter.acquire()
        resp = self.http.get(
            f"{DOCKER_HUB_API}/repositories/{repo}/tags",
            params={"page_size": max(self.tags_per_repo * 5, 25), "ordering": "last_updated"},
        )
        if resp is None or resp.status_code != 200:
            return []
        results = resp.json().get("results") or []
        # 过滤掉明显的临时/测试标签，优先最新
        return [r for r in results if r.get("name")][: self.tags_per_repo]

    # ------------------------------------------------------------ Registry V2

    def _get_token(self, repo: str) -> str | None:
        self.limiter.acquire()
        resp = self.http.get(
            self.auth_url,
            params={
                "service": self.service,
                "scope": f"repository:{repo}:pull",
            },
        )
        if resp is None or resp.status_code != 200:
            return None
        try:
            return resp.json().get("token")
        except ValueError:
            return None

    def _headers(self, token: str | None) -> dict[str, str]:
        headers = {"Accept": MANIFEST_ACCEPT}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _get_manifest(self, repo: str, tag: str, token: str | None) -> dict[str, Any] | None:
        self.limiter.acquire()
        resp = self.http.get(
            f"{self.registry_url}/v2/{repo}/manifests/{tag}", headers=self._headers(token)
        )
        if resp is None or resp.status_code != 200:
            return None
        try:
            manifest = resp.json()
        except ValueError:
            return None
        # manifest list / OCI index：下钻到具体架构
        if manifest.get("manifests"):
            children = manifest["manifests"]
            preferred = next(
                (
                    m
                    for m in children
                    if (m.get("platform") or {}).get("architecture") == "amd64"
                ),
                children[0],
            )
            digest = preferred.get("digest")
            if digest:
                self.limiter.acquire()
                resp = self.http.get(
                    f"{self.registry_url}/v2/{repo}/manifests/{digest}",
                    headers=self._headers(token),
                )
                if resp is not None and resp.status_code == 200:
                    try:
                        return resp.json()
                    except ValueError:
                        return None
        return manifest

    def _get_config_blob(self, repo: str, manifest: dict[str, Any], token: str | None) -> dict | None:
        digest = (manifest.get("config") or {}).get("digest")
        if not digest:
            return None
        payload = self._fetch_blob(repo, digest, token)
        if payload is None:
            return None
        try:
            return json.loads(payload.decode("utf-8", errors="ignore"))
        except ValueError:
            return None

    def _fetch_blob(self, repo: str, digest: str, token: str | None) -> bytes | None:
        self.limiter.acquire()
        resp = self.http.get(
            f"{self.registry_url}/v2/{repo}/blobs/{digest}",
            headers={"Authorization": f"Bearer {token}"} if token else {},
            stream=True,
        )
        if resp is None or resp.status_code != 200:
            return None
        try:
            return resp.content
        except Exception:  # noqa: BLE001 - 网络中断时返回空
            return None

    # ------------------------------------------------------------ 产出 RawDoc

    def _config_to_rawdoc(
        self, repo: str, tag: str, config: dict[str, Any], published: datetime | None
    ) -> RawDoc:
        """把镜像构建历史整理成文本——这是镜像渠道命中率最高的部分。"""
        lines: list[str] = [
            f"# 镜像：{repo}:{tag}",
            f"# 构建历史共 {len(config.get('history') or [])} 层",
        ]
        for entry in config.get("history") or []:
            created_by = entry.get("created_by") or ""
            if created_by:
                lines.append(created_by)
            comment = entry.get("comment")
            if comment:
                lines.append(f"# comment: {comment}")
        env_blob = json.dumps(config.get("config") or {}, ensure_ascii=False, indent=None)
        lines.append(env_blob)
        return RawDoc(
            source=self.meta.name,
            external_id=f"{repo}:{tag}:config",
            url=f"https://hub.docker.com/r/{repo}/blob/{tag}",
            content="\n".join(lines).encode("utf-8"),
            published_at=published or datetime.now(timezone.utc),
            metadata={
                "filename": f"{repo.replace('/', '_')}_{tag}_history.txt",
                "path_hint": f"{repo}/{tag}/Dockerfile.history",
                "channel": "image_history",
                "repo": repo,
                "tag": tag,
            },
        )

    def _iter_layers(
        self,
        repo: str,
        manifest: dict[str, Any],
        tag: str,
        token: str | None,
        published: datetime | None,
    ) -> Iterator[RawDoc]:
        for idx, layer in enumerate(manifest.get("layers") or []):
            size = int(layer.get("size") or 0)
            digest = layer.get("digest") or ""
            if size > self.max_layer_bytes:
                logger.debug("跳过过大层 %s（%.1f MB）", digest[:19], size / 1e6)
                continue
            payload = self._fetch_blob(repo, digest, token)
            if not payload:
                continue
            if payload[:2] == b"\x1f\x8b":
                try:
                    payload = gzip.decompress(payload)
                except (OSError, EOFError):
                    continue
            if payload[:265].find(b"ustar") == -1 and len(payload) > 265:
                if payload[257:262] != b"ustar":
                    continue
            yield RawDoc(
                source=self.meta.name,
                external_id=f"{repo}:{tag}:layer{idx}:{digest[:19]}",
                url=f"https://hub.docker.com/r/{repo}/blob/{tag}#layer{idx}",
                content=payload,
                content_type="application/x-tar",
                published_at=published or datetime.now(timezone.utc),
                metadata={
                    "filename": f"layer{idx}.tar",
                    "path_hint": f"{repo}/{tag}/layer{idx}",
                    "channel": "image_layer",
                    "repo": repo,
                    "tag": tag,
                    "layer_digest": digest,
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
        return True, f"目标仓库 {len(self.repositories)} 个；注册中心 {self.registry_url}"
