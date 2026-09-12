#!/usr/bin/env python
"""为连接串类规则标注正确的密钥捕获组（secret_group）。

背景：像 `mysql://user:password@host/db` 这类规则，正则的第 1 个捕获组
是用户名、第 2 个才是口令。如果不显式指定，规则引擎会把用户名当成凭据
上报——既报错了对象，也无法进行活性验证。

本脚本是幂等的：重复执行不会重复插入。
"""

from __future__ import annotations

import re
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent.parent / "config" / "rules"

# 规则 ID -> 密钥所在的捕获组序号
SECRET_GROUP_MAP: dict[str, int] = {
    # 数据库与中间件连接串（group1=用户名，group2=口令）
    "mysql-uri": 2,
    "postgresql-uri": 2,
    "mongodb-uri": 2,
    "redis-uri": 2,
    "elasticsearch-uri": 2,
    "clickhouse-uri": 2,
    "oracle-uri": 2,
    "gaussdb-uri": 2,
    "oceanbase-uri": 2,
    "rabbitmq-uri": 2,
    "zookeeper-uri": 2,
    "kafka-sasl-jaas": 2,
    # 通用规则
    "env-assignment-password": 2,   # group1=变量名，group2=值
    "docker-image-env-leak": 2,     # group1=键名，group2=值
    "ftp-credential": 2,
    "proxy-credential": 2,
    "basic-auth-url": 2,
    "shadow-hash": 2,               # group1=用户名，group2=口令哈希
}

ID_RE = re.compile(r"^  - id:\s*(\S+)")


def patch(path: Path) -> tuple[int, list[str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    current: str | None = None
    patched: list[str] = []

    for line in lines:
        out.append(line)
        m = ID_RE.match(line)
        if m:
            current = m.group(1)
            continue
        if (
            current
            and current in SECRET_GROUP_MAP
            and line.startswith("    pattern:")
        ):
            out.append(f"    secret_group: {SECRET_GROUP_MAP[current]}")
            patched.append(current)
            current = None

    if patched:
        path.write_text("\n".join(out) + "\n", encoding="utf-8")
    return len(patched), patched


def main() -> None:
    missing = set(SECRET_GROUP_MAP)
    for path in sorted(RULES_DIR.glob("*.y*ml")):
        count, patched = patch(path)
        for item in patched:
            missing.discard(item)
        print(f"{path.name}: 标注 {count} 条 {patched if patched else ''}")
    if missing:
        print(f"⚠ 以下规则未找到对应的 pattern 行：{sorted(missing)}")
    else:
        print("全部规则标注完成。")


if __name__ == "__main__":
    main()
