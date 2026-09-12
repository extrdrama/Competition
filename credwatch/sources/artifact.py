"""App 与小程序渠道。

这是渠道覆盖度的"高难度加分项"：移动端产物里的凭据危害更大，
因为 App 一旦上架，任何人都能下载并反编译。

实现路径：
- APK / AAB：APK 本质是 zip，直接解包后扫描 assets、res/raw、
  AndroidManifest、strings.xml，以及 classes.dex 中的可见字符串；
  若本机存在 jadx / apktool，则进一步反编译以获得可读源码。
- 微信小程序：解包 .wxapkg（未加密格式），扫描其中的 JS / JSON 配置。

合规说明：只处理**公开可下载**的安装包与选手自行提供的样本，
不做任何针对应用商店的批量抓取。
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ..models import RawDoc
from ..parsers import extract, iter_wxapkg, iter_zip
from .base import SourceAdapter, SourceMeta, registry

logger = logging.getLogger("credwatch.sources.artifact")

MAX_ARTIFACT_BYTES = 300_000_000

# 反编译产物中值得保留的文件类型
SOURCE_SUFFIXES = (".java", ".kt", ".smali", ".js", ".json", ".xml", ".ts", ".txt", ".env")


@registry.register
class MobileAppSource(SourceAdapter):
    """移动应用安装包渠道（APK / AAB）。"""

    meta = SourceMeta(
        name="mobile_app",
        label="移动应用安装包（APK）",
        category="App 与小程序",
        description="解包公开下载的 APK/AAB 安装包，扫描 assets、资源文件、"
        "Manifest 与 dex 中的可见字符串；本机存在 jadx 时自动反编译以提升命中率。",
        requires_token=False,
        rate_limit_per_minute=30,
        homepage="",
    )

    def __init__(self, settings: Any, **options: Any) -> None:
        super().__init__(settings, **options)
        self.artifacts = options.get("artifacts") or []
        self.decompile = bool(options.get("decompile", True))
        self.max_files_per_app = int(options.get("max_files_per_app", 3000))

    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        for artifact in self.artifacts:
            content, name = self._load(artifact)
            if content is None:
                continue
            yield RawDoc(
                source=self.meta.name,
                external_id=f"apk:{name}",
                url=artifact if str(artifact).startswith("http") else f"file://{artifact}",
                content=content,
                content_type="application/zip",
                published_at=datetime.now(timezone.utc),
                metadata={
                    "filename": name,
                    "path_hint": f"apk/{name}",
                    "channel": "apk",
                },
            )

    def normalize(self, raw: RawDoc):
        """APK 解包：先做 zip 成员扫描，再尝试反编译补充源码。"""
        name = raw.metadata.get("filename", "app.apk")
        try:
            entries = list(iter_zip(raw.content, only_interesting=False))
        except (ValueError, Exception):  # noqa: BLE001
            entries = []

        emitted = 0
        for entry in entries:
            if emitted >= self.max_files_per_app:
                break
            result = extract(entry.data, entry.name)
            if not result.text:
                continue
            emitted += 1
            yield self._make_doc(raw, name, entry.name, result.text)

        if self.decompile:
            for path, text in self._decompile(raw.content, name):
                emitted += 1
                if emitted >= self.max_files_per_app * 2:
                    break
                yield self._make_doc(raw, name, path, text)

    @staticmethod
    def _make_doc(raw: RawDoc, app_name: str, member: str, text: str):
        from ..models import Document

        return Document(
            doc_id=Document.new_id(raw.source, f"{app_name}::{member}"),
            source=raw.source,
            url=f"{raw.url}#{member}",
            text=text,
            content_type="text/plain",
            published_at=raw.published_at,
            path_hint=member,
            metadata={**raw.metadata, "archive_member": member},
        )

    def _load(self, artifact: str) -> tuple[bytes | None, str]:
        source = str(artifact)
        if source.startswith(("http://", "https://")):
            self.limiter.acquire()
            resp = self.http.get(source)
            if resp is None or resp.status_code != 200:
                return None, ""
            if len(resp.content) > MAX_ARTIFACT_BYTES:
                logger.warning("安装包过大，跳过：%s", source)
                return None, ""
            return resp.content, source.rsplit("/", 1)[-1] or "app.apk"
        path = Path(source)
        if not path.exists():
            logger.warning("安装包不存在：%s", source)
            return None, ""
        return path.read_bytes(), path.name

    def _decompile(self, content: bytes, name: str) -> Iterator[tuple[str, str]]:
        """若本机存在 jadx，则反编译 dex 获取可读源码。"""
        jadx = shutil.which("jadx")
        if not jadx:
            logger.debug("未安装 jadx，跳过反编译（仅做 dex 字符串抽取）")
            return
        with tempfile.TemporaryDirectory(prefix="credwatch_apk_") as tmp:
            apk_path = Path(tmp) / name
            apk_path.write_bytes(content)
            out_dir = Path(tmp) / "out"
            try:
                subprocess.run(
                    [jadx, "-d", str(out_dir), "--no-res", str(apk_path)],
                    capture_output=True,
                    timeout=600,
                    check=False,
                )
            except (subprocess.TimeoutExpired, OSError) as exc:
                logger.debug("jadx 执行失败：%s", exc)
                return
            if not out_dir.exists():
                return
            count = 0
            for file in out_dir.rglob("*"):
                if count > 2000:
                    return
                if not file.is_file() or file.suffix.lower() not in SOURCE_SUFFIXES:
                    continue
                try:
                    text = file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if not text.strip():
                    continue
                count += 1
                yield str(file.relative_to(out_dir)), text

    def health_check(self) -> tuple[bool, str]:
        if not self.artifacts:
            return False, "未配置安装包路径或下载地址"
        jadx = "已安装" if shutil.which("jadx") else "未安装"
        return True, f"目标 {len(self.artifacts)} 个；jadx {jadx}"


@registry.register
class MiniProgramSource(SourceAdapter):
    """微信小程序包渠道（.wxapkg）。"""

    meta = SourceMeta(
        name="mini_program",
        label="小程序包（wxapkg）",
        category="App 与小程序",
        description="解包微信小程序分包文件，扫描其中的 JS 业务代码与 JSON 配置，"
        "检测硬编码在小程序端的第三方密钥与后台地址。",
        requires_token=False,
        rate_limit_per_minute=30,
        homepage="",
    )

    def __init__(self, settings: Any, **options: Any) -> None:
        super().__init__(settings, **options)
        self.packages = options.get("packages") or []
        self.max_members = int(options.get("max_members", 5000))

    def discover(self, cursor: dict[str, Any] | None = None) -> Iterator[RawDoc]:
        for item in self.packages:
            content, name = self._load(item)
            if content is None:
                continue
            yield RawDoc(
                source=self.meta.name,
                external_id=f"wxapkg:{name}",
                url=str(item),
                content=content,
                content_type="application/octet-stream",
                published_at=datetime.now(timezone.utc),
                metadata={"filename": name, "path_hint": f"wxapkg/{name}", "channel": "wxapkg"},
            )

    def normalize(self, raw: RawDoc):
        from ..models import Document

        name = raw.metadata.get("filename", "app.wxapkg")
        try:
            entries = list(iter_wxapkg(raw.content))
        except ValueError as exc:
            logger.warning("%s 解包失败：%s", name, exc)
            return

        emitted = 0
        for entry in entries:
            if emitted >= self.max_members:
                return
            result = extract(entry.data, entry.name)
            if not result.text:
                continue
            emitted += 1
            yield Document(
                doc_id=Document.new_id(raw.source, f"{name}::{entry.name}"),
                source=raw.source,
                url=f"{raw.url}#{entry.name}",
                text=result.text,
                published_at=raw.published_at,
                path_hint=entry.name,
                metadata={**raw.metadata, "archive_member": entry.name},
            )

    def _load(self, item: str) -> tuple[bytes | None, str]:
        source = str(item)
        if source.startswith(("http://", "https://")):
            self.limiter.acquire()
            resp = self.http.get(source)
            if resp is None or resp.status_code != 200:
                return None, ""
            return resp.content, source.rsplit("/", 1)[-1] or "app.wxapkg"
        path = Path(source)
        if not path.exists():
            logger.warning("小程序包不存在：%s", source)
            return None, ""
        return path.read_bytes(), path.name

    def health_check(self) -> tuple[bool, str]:
        if not self.packages:
            return False, "未配置小程序包路径"
        return True, f"目标 {len(self.packages)} 个"
