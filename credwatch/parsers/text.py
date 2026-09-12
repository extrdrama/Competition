"""解析层：把任意形态的内容转成可检测的文本。

设计原则：对二进制内容做"字符串抽取"而不是放弃——
镜像层、APK、so 库里的凭据，绝大部分以可见字符串形式存在。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# 从二进制中抽取可见字符串的最小长度
MIN_STRING_LEN = 6

# 可打印 ASCII 串（含常见密钥字符集）
ASCII_STRING_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN)

# 常见文本编码的 BOM
BOMS: tuple[tuple[bytes, str], ...] = (
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
)

TEXT_EXTENSIONS = (
    ".txt", ".md", ".rst", ".log", ".env", ".ini", ".cfg", ".conf", ".config",
    ".yaml", ".yml", ".json", ".json5", ".toml", ".xml", ".properties",
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".kt", ".go", ".rs", ".rb",
    ".php", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".sql", ".pl",
    ".c", ".h", ".cpp", ".cc", ".hpp", ".cs", ".swift", ".m", ".mm", ".lua",
    ".tf", ".tfvars", ".gradle", ".pom", ".sbt", ".groovy", ".dart",
    ".pem", ".crt", ".cer", ".key", ".ppk", ".pub", ".pubxml",
    ".dockerfile", ".gitignore", ".npmrc", ".pypirc", ".netrc", ".htpasswd",
    ".vue", ".html", ".htm", ".css", ".scss", ".less", ".jsp", ".asp", ".aspx",
)

TEXT_FILENAMES = (
    "dockerfile", "makefile", "jenkinsfile", "vagrantfile", "gemfile",
    "procfile", "credentials", "config", "kubeconfig", ".env",
)


@dataclass
class ExtractionResult:
    text: str
    is_binary: bool
    encoding: str = "utf-8"
    truncated: bool = False


def detect_encoding(data: bytes) -> str:
    """按 BOM 与常见编码试探，优先 UTF-8。"""
    for bom, enc in BOMS:
        if data.startswith(bom):
            return enc
    for enc in ("utf-8", "gb18030", "big5", "latin-1"):
        try:
            data.decode(enc)
            return enc
        except (UnicodeDecodeError, LookupError):
            continue
    return "latin-1"


def looks_textual(data: bytes) -> bool:
    """通过不可打印字符占比判断是否为文本。"""
    if not data:
        return False
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126 or b >= 0x80)
    return printable / len(sample) > 0.85


def is_text_path(path: str) -> bool:
    """按文件名/扩展名判断是否应作为文本处理。"""
    lowered = path.lower().replace("\\", "/")
    name = lowered.rsplit("/", 1)[-1]
    if name in TEXT_FILENAMES or name.startswith(".env"):
        return True
    return lowered.endswith(TEXT_EXTENSIONS)


def extract_strings(data: bytes, min_len: int = MIN_STRING_LEN, limit: int = 8_000_000) -> str:
    """从二进制中抽取可见 ASCII 串，按行拼接。

    镜像层、APK、so、Java class 中的凭据多以明文串存在，
    这一步是"能否覆盖二进制渠道"的关键。
    """
    chunks: list[bytes] = []
    total = 0
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    for m in pattern.finditer(data):
        chunk = m.group(0)
        chunks.append(chunk)
        total += len(chunk)
        if total >= limit:
            break
    return "\n".join(c.decode("utf-8", errors="replace") for c in chunks)


def extract(data: bytes, path: str = "", max_bytes: int = 32_000_000) -> ExtractionResult:
    """统一入口：按路径语义与内容特征决定抽取策略。"""
    truncated = len(data) > max_bytes
    payload = data[:max_bytes]

    if not payload:
        return ExtractionResult(text="", is_binary=False, truncated=truncated)

    if looks_textual(payload):
        enc = detect_encoding(payload)
        return ExtractionResult(
            text=payload.decode(enc, errors="replace"), is_binary=False, encoding=enc,
            truncated=truncated,
        )

    # 二进制：先尝试直接解码（可能只是少量控制字符），失败则抽字符串
    if is_text_path(path):
        enc = detect_encoding(payload)
        return ExtractionResult(
            text=payload.decode(enc, errors="replace"), is_binary=True, encoding=enc,
            truncated=truncated,
        )
    return ExtractionResult(
        text=extract_strings(payload), is_binary=True, encoding="ascii-strings",
        truncated=truncated,
    )
