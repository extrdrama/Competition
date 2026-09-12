"""本地内容渠道。

虽然题目强调"公开渠道"，但本地目录渠道有两个不可替代的作用：
1. 支撑演示与回归测试（离线可复现，评审现场不依赖外网）；
2. 接入企业内部场景——开发者本机的工程目录、CI 产物目录同样是
   "凭据不该出现的位置"，属于同一检测能力的一部分。
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ..models import RawDoc
from .base import SourceAdapter, SourceMeta, registry

logger = logging.getLogger("credwatch.sources.local")

# 默认跳过的目录
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", ".tox",
    "dist", "build", ".idea", ".vscode", "target", ".mypy_cache", ".pytest_cache",
    ".next", ".nuxt", "site-packages", ".terraform",
}

# 单文件读取上限
MAX_FILE_BYTES = 32_000_000


@registry.register
class LocalDirectorySource(SourceAdapter):
    """递归扫描本地目录，产出可检测文档。用于离线演示与企业内网自查。"""

    meta = SourceMeta(
        name="local_dir",
        label="本地/内网目录",
        category="本地与企业内网",
        description="递归扫描指定目录中的源码、配置、脚本与归档文件，"
        "适用于企业内网自查与离线演示场景。",
        requires_token=False,
        rate_limit_per_minute=100000,
        homepage="",
    )

    def __init__(self, settings: Any, **options: Any) -> None:
        super().__init__(settings, **options)
        self.roots = [Path(p) for p in (options.get("paths") or [])]
        self.follow_symlinks = bool(options.get("follow_symlinks", False))
        self.max_files = int(options.get("max_files", 20000))
        self.include_archives = bool(options.get("include_archives", True))
        # 排除规则（相对路径 glob）。典型用法：把交由专用渠道处理的
        # 安装包/小程序包目录排除掉，避免同一份内容被重复上报。
        self.exclude_globs = list(options.get("exclude") or [])

    @property
    def targets(self) -> list[Path]:
        if self.roots:
            return self.roots
        demo = Path(self.options.get("demo_dir", "")) if self.options.get("demo_dir") else None
        return [p for p in [demo] if p and p.exists()]

    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        cursor = cursor or {}
        seen_hashes: set[str] = set(cursor.get("seen_hashes") or [])
        emitted = 0
        for root in self.targets:
            if not root.exists():
                logger.warning("路径不存在，跳过：%s", root)
                continue
            for path in self._walk(root):
                if emitted >= self.max_files:
                    return
                try:
                    stat = path.stat()
                except OSError:
                    continue
                if stat.st_size == 0 or stat.st_size > MAX_FILE_BYTES:
                    continue
                if self._should_skip(path):
                    continue
                try:
                    content = path.read_bytes()
                except OSError:
                    continue

                # 增量：按内容哈希跳过已扫描过的文件
                digest = hashlib.sha256(content).hexdigest()
                rel = self._relative(path, root)
                if self._is_excluded(rel):
                    continue
                if digest in seen_hashes:
                    continue
                seen_hashes.add(digest)

                emitted += 1
                yield RawDoc(
                    source=self.meta.name,
                    external_id=f"{digest[:16]}:{rel}",
                    url=f"file://{path.as_posix()}",
                    content=content,
                    content_type="application/octet-stream",
                    author=None,
                    published_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                    metadata={
                        "filename": path.name,
                        "path_hint": rel,
                        "root": str(root),
                        "size": stat.st_size,
                        "mtime": stat.st_mtime,
                        "content_hash": digest,
                    },
                )

    def next_cursor(self, raw: RawDoc) -> dict[str, Any]:
        return {"last_path": raw.external_id}

    def _walk(self, root: Path) -> Iterator[Path]:
        if root.is_file():
            yield root
            return
        for dirpath, dirnames, filenames in os.walk(root, followlinks=self.follow_symlinks):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            for name in filenames:
                yield Path(dirpath) / name

    # 明显不含凭据的纯媒体/字体文件，直接跳过以节省时间
    SKIP_SUFFIXES = (
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
        ".mp4", ".mp3", ".wav", ".avi", ".mov", ".mkv", ".flv",
        ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pyc", ".pyo",
        ".class", ".o", ".a", ".lib", ".exe", ".msi", ".dmg", ".iso",
    )

    def _should_skip(self, path: Path) -> bool:
        lowered = path.name.lower()
        if lowered.endswith(self.SKIP_SUFFIXES):
            return True
        # 归档文件只在允许时才展开
        if not self.include_archives and lowered.endswith(
            (".zip", ".tar", ".gz", ".tgz", ".jar", ".apk", ".whl", ".wxapkg")
        ):
            return True
        return False

    def _is_excluded(self, relative_path: str) -> bool:
        """按相对路径 glob 判断是否排除。"""
        if not self.exclude_globs:
            return False
        from fnmatch import fnmatch

        normalized = relative_path.replace("\\", "/")
        return any(
            fnmatch(normalized, pattern) or fnmatch("/" + normalized, pattern)
            for pattern in self.exclude_globs
        )

    @staticmethod
    def _relative(path: Path, root: Path) -> str:
        try:
            return path.relative_to(root).as_posix()
        except ValueError:
            return path.name

    def health_check(self) -> tuple[bool, str]:
        existing = [str(p) for p in self.targets if p.exists()]
        if not existing:
            return False, "未配置任何存在的扫描路径"
        return True, f"待扫描路径：{', '.join(existing)}"
