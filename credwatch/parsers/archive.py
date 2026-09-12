"""解析层：归档与包文件解包。

覆盖：zip / jar / apk / war / tar / tar.gz / tgz / gz / 7z(可选)
以及微信小程序包 wxapkg。

安全约束：限制条目数、单文件大小与总解包体积，避免 zip bomb。
"""

from __future__ import annotations

import gzip
import io
import struct
import tarfile
import zipfile
from dataclasses import dataclass
from typing import Iterator

MAX_ENTRIES = 20_000
MAX_FILE_BYTES = 8_000_000
MAX_TOTAL_BYTES = 200_000_000
MAX_COMPRESSION_RATIO = 200

ARCHIVE_SUFFIXES = (
    ".zip", ".jar", ".war", ".apk", ".aar", ".xpi", ".crx", ".whl", ".egg",
    ".tar", ".tar.gz", ".tgz", ".gz", ".tgz2",
)
WXAPKG_SUFFIXES = (".wxapkg",)

# 归档中值得展开的成员（其余跳过，避免扫描大量无关二进制）
INTERESTING_MEMBER_RE = None  # 延迟导入避免循环


def _interesting(name: str) -> bool:
    from .text import is_text_path

    lowered = name.lower()
    if is_text_path(lowered):
        return True
    # 二进制但可能内嵌凭据的成员
    return lowered.endswith(
        (".so", ".dll", ".dylib", ".class", ".dex", ".jar", ".js", ".json",
         ".bin", ".dat", ".csv", ".xml", ".plist", ".strings", ".arsc")
    )


@dataclass
class ArchiveEntry:
    name: str
    data: bytes
    size: int


def is_archive(filename: str) -> bool:
    lowered = filename.lower()
    return lowered.endswith(ARCHIVE_SUFFIXES) or lowered.endswith(WXAPKG_SUFFIXES)


def _guard(entry_count: int, total: int, size: int, compressed: int) -> None:
    if entry_count > MAX_ENTRIES:
        raise ValueError(f"归档条目数超过上限 {MAX_ENTRIES}")
    if size > MAX_FILE_BYTES:
        raise ValueError(f"单文件超过上限 {MAX_FILE_BYTES}")
    if total > MAX_TOTAL_BYTES:
        raise ValueError(f"解包总量超过上限 {MAX_TOTAL_BYTES}")
    if compressed > 0 and size / max(compressed, 1) > MAX_COMPRESSION_RATIO:
        raise ValueError("压缩比异常，疑似 zip bomb")


def iter_zip(data: bytes, only_interesting: bool = True) -> Iterator[ArchiveEntry]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        count, total = 0, 0
        for info in zf.infolist():
            if info.is_dir():
                continue
            count += 1
            if only_interesting and not _interesting(info.filename):
                continue
            _guard(count, total, info.file_size, info.compress_size)
            try:
                payload = zf.read(info)
            except (zipfile.BadZipFile, RuntimeError):
                continue
            total += len(payload)
            yield ArchiveEntry(info.filename, payload, len(payload))


def iter_tar(data: bytes, only_interesting: bool = True) -> Iterator[ArchiveEntry]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        count, total = 0, 0
        for member in tf.getmembers():
            if not member.isfile():
                continue
            count += 1
            if only_interesting and not _interesting(member.name):
                continue
            _guard(count, total, member.size, member.size)
            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            payload = extracted.read(MAX_FILE_BYTES + 1)
            total += len(payload)
            yield ArchiveEntry(member.name, payload, len(payload))


def iter_gzip(data: bytes, name: str = "") -> Iterator[ArchiveEntry]:
    """单文件 gzip；若内部是 tar，则递归解 tar。"""
    try:
        payload = gzip.decompress(data)
    except (OSError, EOFError):
        return
    if name.lower().endswith(".tar.gz") or payload[:265].find(b"ustar") != -1:
        yield from iter_tar(payload)
    else:
        yield ArchiveEntry(name or "gunzip.out", payload, len(payload))


def iter_archive(data: bytes, filename: str) -> Iterator[ArchiveEntry]:
    """归档统一入口，按后缀分派。"""
    lowered = filename.lower()
    if lowered.endswith(WXAPKG_SUFFIXES):
        yield from iter_wxapkg(data)
        return
    if lowered.endswith((".tar", ".tar.gz", ".tgz")) or (
        not lowered.endswith(".gz") and _peek_tar(data)
    ):
        try:
            yield from iter_tar(data)
            return
        except (tarfile.TarError, ValueError):
            pass
    if lowered.endswith(".gz"):
        yield from iter_gzip(data, filename)
        return
    if zipfile.is_zipfile(io.BytesIO(data)):
        try:
            yield from iter_zip(data)
            return
        except (zipfile.BadZipFile, ValueError):
            return
    # 兜底：按 tar 再试一次
    try:
        yield from iter_tar(data)
    except (tarfile.TarError, ValueError):
        return


def _peek_tar(data: bytes) -> bool:
    return len(data) > 265 and data[257:262] == b"ustar"


# --------------------------------------------------------------------- wxapkg


def iter_wxapkg(data: bytes) -> Iterator[ArchiveEntry]:
    """解包微信小程序包（.wxapkg，未加密版）。

    结构：
      头部 14 字节：firstMark(0xBE) info1 indexInfoLength bodyInfoLength lastMark(0xED)
      索引信息：infoCount(4) 之后每项 nameLen(4) name offset(4) size(4)
    """
    if len(data) < 18:
        return
    first_mark = data[0]
    if first_mark != 0xBE:
        raise ValueError("非标准 wxapkg 包（或已被加密），当前版本不支持")
    index_len = struct.unpack(">I", data[5:9])[0]
    body_len = struct.unpack(">I", data[9:13])[0]
    body_start = 14 + index_len
    if body_start + body_len > len(data):
        raise ValueError("wxapkg 头部长度字段异常")
    if data[13] != 0xED:
        # 部分版本尾部标记不同，继续尝试解析
        pass

    pos = 14
    if pos + 4 > len(data):
        return
    info_count = struct.unpack(">I", data[pos : pos + 4])[0]
    pos += 4
    if not (0 < info_count < MAX_ENTRIES):
        raise ValueError(f"wxapkg 条目数异常：{info_count}")

    for _ in range(info_count):
        if pos + 12 > len(data):
            return
        name_len = struct.unpack(">I", data[pos : pos + 4])[0]
        pos += 4
        if pos + name_len + 8 > len(data):
            return
        name = data[pos : pos + name_len].decode("utf-8", errors="replace")
        pos += name_len
        offset, size = struct.unpack(">II", data[pos : pos + 8])
        pos += 8
        start = body_start + offset
        end = start + size
        if end > len(data) or size > MAX_FILE_BYTES:
            continue
        if not _interesting(name):
            continue
        yield ArchiveEntry(name, data[start:end], size)


def unpack_image_layers(layers: list[bytes]) -> Iterator[ArchiveEntry]:
    """按顺序解包容器镜像各层，产出带层号的成员。"""
    for idx, layer in enumerate(layers):
        for entry in iter_tar(layer):
            yield ArchiveEntry(f"layer{idx}/{entry.name}", entry.data, entry.size)
