"""解析层：文本抽取、归档解包、镜像层解包。"""

from .archive import (
    ArchiveEntry,
    is_archive,
    iter_archive,
    iter_tar,
    iter_wxapkg,
    iter_zip,
    unpack_image_layers,
)
from .text import (
    ExtractionResult,
    extract,
    extract_strings,
    is_text_path,
    looks_textual,
)

__all__ = [
    "ArchiveEntry",
    "ExtractionResult",
    "extract",
    "extract_strings",
    "is_archive",
    "is_text_path",
    "iter_archive",
    "iter_tar",
    "iter_wxapkg",
    "iter_zip",
    "looks_textual",
    "unpack_image_layers",
]
