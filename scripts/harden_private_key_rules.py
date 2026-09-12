#!/usr/bin/env python
"""收紧私钥类规则：必须"私钥头 + 至少两行 Base64 密钥体"才算命中。

原因：只匹配 `-----BEGIN RSA PRIVATE KEY-----` 这一行会产生明显误报——
技术文档、教程、README 里经常成段引用这一行文字。
真正的私钥必然跟随大量 Base64 内容，据此可以把文档引用排除掉。

本脚本幂等，可重复执行。
"""

from __future__ import annotations

import re
from pathlib import Path

RULES_FILE = Path(__file__).resolve().parent.parent / "config" / "rules" / "crypto_keys.yaml"

# 密钥体：换行后至少两行、每行不少于 40 个 Base64 字符
BODY = r"[\r\n]+(?:[A-Za-z0-9+/=]{40,}[\r\n]+){2,}"

HEADERS: dict[str, str] = {
    "private-key-rsa-pem": "-----BEGIN RSA PRIVATE KEY-----",
    "private-key-pkcs8-pem": "-----BEGIN PRIVATE KEY-----",
    "private-key-encrypted-pem": "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "private-key-openssh": "-----BEGIN OPENSSH PRIVATE KEY-----",
    "private-key-ec": "-----BEGIN EC PRIVATE KEY-----",
    "private-key-dsa": "-----BEGIN DSA PRIVATE KEY-----",
    "private-key-pgp": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
}

ID_RE = re.compile(r"^  - id:\s*(\S+)")


def main() -> None:
    lines = RULES_FILE.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    current: str | None = None
    patched: list[str] = []

    for line in lines:
        m = ID_RE.match(line)
        if m:
            current = m.group(1)
        if current in HEADERS and line.startswith("    pattern:"):
            header = HEADERS[current]
            out.append(f"    pattern: '{header}{BODY}'")
            patched.append(current)
            current = None
            continue
        out.append(line)

    RULES_FILE.write_text("\n".join(out) + "\n", encoding="utf-8")
    missing = [k for k in HEADERS if k not in patched]
    print(f"已收紧 {len(patched)} 条私钥规则：{patched}")
    if missing:
        print(f"⚠ 未匹配到 pattern 行：{missing}")


if __name__ == "__main__":
    main()
