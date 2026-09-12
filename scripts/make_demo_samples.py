#!/usr/bin/env python
"""生成演示语料。

所有凭据均为**程序生成的伪造值**，格式合法但不对应任何真实账号，
仅用于离线演示与回归测试。

之所以用脚本生成而不是手工写死，是为了让"样本为什么长这样"可复现、
可审计——评审如果需要核对，直接重跑本脚本即可。
"""

from __future__ import annotations

import json
import random
import string
import struct
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "demo" / "samples"
RNG = random.Random(20260912)  # 固定种子，保证每次生成结果一致

UPPER_ALNUM = string.ascii_uppercase + string.digits
ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"


def _build_wxapkg(entries: list[tuple[str, bytes]]) -> bytes:
    """按 wxapkg 公开格式构造小程序包。

    头部：
        firstMark(0xBE) info1(4) indexInfoLength(4) bodyInfoLength(4) lastMark(0xED)
    索引区：
        infoCount(4) 之后每项 nameLen(4) name offset(4) size(4)
    数据区：
        紧随索引区之后
    """
    index_parts: list[bytes] = [struct.pack(">I", len(entries))]
    offset = 0
    body_parts: list[bytes] = []
    for name, data in entries:
        name_bytes = name.encode("utf-8")
        index_parts.append(struct.pack(">I", len(name_bytes)))
        index_parts.append(name_bytes)
        index_parts.append(struct.pack(">I", offset))
        index_parts.append(struct.pack(">I", len(data)))
        body_parts.append(data)
        offset += len(data)

    index_info = b"".join(index_parts)
    body = b"".join(body_parts)
    header = struct.pack(">B", 0xBE) + struct.pack(">I", 0)
    header += struct.pack(">I", len(index_info))
    header += struct.pack(">I", len(body))
    header += struct.pack(">B", 0xED)
    return header + index_info + body


def upper(n: int) -> str:
    return "".join(RNG.choice(UPPER_ALNUM) for _ in range(n))


def alnum(n: int) -> str:
    return "".join(RNG.choice(ALNUM) for _ in range(n))


def hexs(n: int) -> str:
    return "".join(RNG.choice(HEX) for _ in range(n))


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"  生成 {path.relative_to(ROOT.parent.parent)}")


def main() -> None:
    print("生成演示语料（全部为伪造凭据）…")

    # 伪造但格式合法的凭据
    aws_ak = "AKIA" + upper(16)
    aws_sk = alnum(40)
    aliyun_ak = "LTAI" + alnum(17)
    aliyun_sk = alnum(30)
    tencent_ak = "AKID" + alnum(20)
    tencent_sk = alnum(32)
    gitlab_pat = "glpat-" + alnum(20)
    github_pat = "ghp_" + alnum(36)
    npm_token = "npm_" + alnum(36)
    slack_bot = f"xoxb-{RNG.randint(10**11, 10**12 - 1)}-{RNG.randint(10**11, 10**12 - 1)}-{alnum(24)}"
    stripe_key = "sk_live_" + alnum(24)
    jwt_secret = alnum(48)
    db_password = "Pr0d_" + alnum(12)
    redis_password = alnum(20)

    # ------------------------------------------------------------ Web 应用
    write(
        ROOT / "webapp" / ".env",
        f"""# 生产环境配置（演示样本，凭据均为伪造值）
APP_ENV=production
APP_DEBUG=false

# 云存储
AWS_ACCESS_KEY_ID={aws_ak}
AWS_SECRET_ACCESS_KEY={aws_sk}
AWS_DEFAULT_REGION=cn-north-1

# 数据库
MYSQL_HOST=10.20.30.41
MYSQL_PORT=3306
MYSQL_USER=app_rw
MYSQL_PASSWORD={db_password}
DATABASE_URL=mysql://app_rw:{db_password}@10.20.30.41:3306/production

# 缓存
REDIS_HOST=10.20.30.42
REDIS_PASSWORD={redis_password}

# 会话与令牌
JWT_SECRET={jwt_secret}
SESSION_SECRET={alnum(32)}
""",
    )

    write(
        ROOT / "webapp" / "config" / "settings.py",
        f"""'''应用配置（演示样本，凭据均为伪造值）。'''

DEBUG = False
ALLOWED_HOSTS = ["api.internal-demo.example.com"]

# 硬编码的数据源与第三方密钥（典型的"不该出现"写法）
DATABASES = {{
    "default": {{
        "ENGINE": "django.db.backends.mysql",
        "NAME": "production",
        "USER": "app_rw",
        "PASSWORD": "{db_password}",
        "HOST": "10.20.30.41",
        "PORT": 3306,
    }}
}}

DJANGO_SECRET_KEY = "{alnum(50)}"

# 支付与消息推送
STRIPE_SECRET_KEY = "{stripe_key}"
SLACK_BOT_TOKEN = "{slack_bot}"
""",
    )
    write(
        ROOT / "webapp" / "docker-compose.yml",
        f"""# 演示样本，凭据均为伪造值
version: "3.9"
services:
  api:
    image: registry.internal-demo.example.com/api:2.4.1
    environment:
      - DATABASE_URL=postgresql://api_user:{db_password}@postgres:5432/app
      - REDIS_PASSWORD={redis_password}
    ports:
      - "8080:8080"

  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: api_user
      POSTGRES_PASSWORD: {db_password}
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7
    command: redis-server --requirepass {redis_password}

volumes:
  pgdata:
""",
    )

    write(
        ROOT / "webapp" / "deploy" / "Dockerfile",
        f"""# 演示样本：镜像构建 ENV 残留是镜像渠道的核心命中点
FROM python:3.12-slim

ARG PIP_INDEX_URL=https://pypi.org/simple
ENV APP_HOME=/opt/api
ENV SECRET_KEY={alnum(40)}
ENV ACCESS_TOKEN={alnum(32)}
ENV DB_PASSWORD={db_password}

WORKDIR $APP_HOME
COPY . $APP_HOME
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "-m", "api"]
""",
    )

    # ------------------------------------------------------------ 云厂商
    write(
        ROOT / "cloud" / "aws_credentials",
        f"""[default]
aws_access_key_id = {aws_ak}
aws_secret_access_key = {aws_sk}
region = cn-north-1

[backup-role]
aws_access_key_id = AIDA{upper(16)}
aws_secret_access_key = {alnum(40)}
""",
    )

    write(
        ROOT / "cloud" / "aliyun.env",
        f"""# 演示样本，凭据均为伪造值
ALIYUN_ACCESS_KEY_ID={aliyun_ak}
ALIYUN_ACCESS_KEY_SECRET={aliyun_sk}
ALIYUN_REGION=cn-hangzhou
""",
    )

    write(
        ROOT / "cloud" / "tencent.env",
        f"""# 演示样本，凭据均为伪造值
TENCENTCLOUD_SECRET_ID={tencent_ak}
TENCENTCLOUD_SECRET_KEY={tencent_sk}
TENCENTCLOUD_REGION=ap-guangzhou
""",
    )

    # ------------------------------------------------------------ 私钥
    pem_body = "\n".join(
        "MII" + alnum(60) for _ in range(6)
    )
    write(
        ROOT / "keys" / "server_rsa.pem",
        f"""-----BEGIN RSA PRIVATE KEY-----
{pem_body}
-----END RSA PRIVATE KEY-----
""",
    )

    # ------------------------------------------------------------ k8s Secret
    import base64

    def b64(value: str) -> str:
        return base64.b64encode(value.encode()).decode()

    write(
        ROOT / "k8s" / "secret.yaml",
        f"""# 演示样本，凭据均为伪造值
apiVersion: v1
kind: Secret
metadata:
  name: api-credentials
  namespace: production
type: Opaque
data:
  db-password: {b64(db_password)}
  redis-password: {b64(redis_password)}
  jwt-secret: {b64(jwt_secret)}
""",
    )

    # ------------------------------------------------------------ CI 配置
    write(
        ROOT / "ci" / ".gitlab-ci.yml",
        f"""# 演示样本，凭据均为伪造值
stages: [build, deploy]

build:
  stage: build
  script:
    - echo "building"
    - docker login -u ci-bot -p {gitlab_pat}

deploy:
  stage: deploy
  variables:
    GITLAB_TOKEN: {gitlab_pat}
    NPM_TOKEN: {npm_token}
    DB_PASSWORD: {db_password}
  script:
    - ./deploy.sh
""",
    )

    write(
        ROOT / "ci" / ".npmrc",
        f"""# 演示样本，凭据均为伪造值
registry=https://registry.npmjs.org/
//registry.npmjs.org/:_authToken={npm_token}
""",
    )

    # ------------------------------------------------------------ 包配置
    write(
        ROOT / "package" / "package.json",
        json.dumps(
            {
                "name": "internal-config-loader",
                "version": "1.2.3",
                "description": "演示样本，凭据均为伪造值",
                "main": "index.js",
                "dependencies": {"axios": "^1.6.0"},
                "config": {
                    "apiKey": alnum(32),
                    "accessToken": alnum(40),
                    "clientSecret": alnum(32),
                },
                "publishConfig": {"registry": "https://registry.npmjs.org/"},
                "//": f"npmpublish token: {npm_token}",
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
    )

    # ------------------------------------------------------------ 移动端产物
    write(
        ROOT / "mobile" / "strings.xml",
        f"""<?xml version="1.0" encoding="utf-8"?>
<!-- 演示样本：Android 资源文件中的硬编码密钥 -->
<resources>
    <string name="app_name">DemoApp</string>
    <string name="api_base_url">https://api.internal-demo.example.com/v2/</string>
    <string name="amap_api_key">{hexs(32)}</string>
    <string name="api_key">{alnum(32)}</string>
    <string name="client_secret">{alnum(40)}</string>
    <string name="github_token">{github_pat}</string>
</resources>
""",
    )

    # ------------------------------------------------------------ INI 配置
    write(
        ROOT / "ops" / "deploy.ini",
        f"""[credentials]
admin_user = deployer
admin_password = {db_password}
ssh_key_path = /home/deployer/.ssh/id_rsa

[target]
host = 10.20.30.50
port = 22
""",
    )

    # ------------------------------------------------------------ 归档
    archive_path = ROOT / "archive" / "backup-config.zip"
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "backup/.env",
            f"""# 演示样本，凭据均为伪造值
AWS_ACCESS_KEY_ID={aws_ak}
AWS_SECRET_ACCESS_KEY={aws_sk}
MYSQL_PASSWORD={db_password}
GLPAT={gitlab_pat}
""",
        )
        zf.writestr(
            "backup/docker-compose.yml",
            f"""services:
  db:
    image: mysql:8
    environment:
      MYSQL_ROOT_PASSWORD: {db_password}
""",
        )
        zf.writestr("backup/notes.txt", "备份于 2026-08-01，仅含配置样例。\n")
    print(f"  生成 {archive_path.relative_to(ROOT.parent.parent)}")

    # ------------------------------------------------------------ 移动端产物（渠道二：App）
    # 与仓库样本中出现的同一个令牌，用于演示"跨渠道扩散"关联能力
    apk_path = ROOT / "artifacts" / "demo-app.apk"
    apk_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(apk_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "AndroidManifest.xml",
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<manifest package="com.demo.internalapp" />\n',
        )
        zf.writestr(
            "res/values/strings.xml",
            f"""<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="api_base_url">https://api.internal-demo.example.com/v2/</string>
    <string name="github_token">{github_pat}</string>
    <string name="api_key">{alnum(32)}</string>
</resources>
""",
        )
        zf.writestr(
            "assets/config.json",
            json.dumps(
                {
                    "endpoint": "https://api.internal-demo.example.com/v2/",
                    "appSecret": alnum(32),
                    "amapKey": hexs(32),
                },
                ensure_ascii=False,
                indent=2,
            ),
        )
        # 伪造的 dex：仅含可见字符串，用于验证二进制字符串抽取能力
        zf.writestr(
            "classes.dex",
            b"\x64\x65\x78\x0a\x30\x33\x35\x00" + f"SECRET_TOKEN={alnum(32)}".encode() + b"\x00" * 16,
        )
    print(f"  生成 {apk_path.relative_to(ROOT.parent.parent)}")

    # --------------------------------------------------- 小程序包（渠道三：小程序）
    # 按 wxapkg 公开格式手工构造，同时用于验证解包器实现
    miniapp_path = ROOT / "artifacts" / "demo-miniapp.wxapkg"
    entries: list[tuple[str, bytes]] = [
        (
            "app.js",
            f"""// 演示样本，凭据均为伪造值
const config = {{
  apiBase: "https://api.internal-demo.example.com/v2/",
  appKey: "{alnum(32)}",
  accessToken: "{github_pat}",
}};
App({{ globalData: config }});
""".encode(),
        ),
        (
            "config.json",
            json.dumps(
                {"pages": ["pages/index/index"], "appSecret": alnum(40)},
                ensure_ascii=False,
                indent=2,
            ).encode(),
        ),
        (
            "pages/index/index.js",
            f"""Page({{
  data: {{}},
  onLoad() {{
    // 演示样本：小程序端硬编码后台地址与令牌
    const baseUrl = "https://api.internal-demo.example.com/v2/";
    const token = "{github_pat}";
    console.log(baseUrl, token);
  }},
}});
""".encode(),
        ),
    ]
    miniapp_path.write_bytes(_build_wxapkg(entries))
    print(f"  生成 {miniapp_path.relative_to(ROOT.parent.parent)}")

    # ------------------------------------------------------------ 反例（不应命中）
    write(
        ROOT / "README.md",
        """# 演示样本说明

本目录中的全部凭据均为**程序生成的伪造值**，不对应任何真实账号，
仅用于演示与回归测试。

## 反例：以下写法应当被判定为"非泄露"，不得报警

```bash
# 环境变量引用，不是明文
export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
API_KEY=os.environ["API_KEY"]
TOKEN=process.env.TOKEN

# 占位符
AWS_ACCESS_KEY_ID=your_access_key_here
SECRET_KEY=<YOUR_SECRET_KEY>
API_KEY=xxxxxxxxxxxxxxxx
```

## 正例：以下写法应当被判定为"真实泄露"

- `AKIA` 前缀的 20 位访问密钥 ID + 40 位 Secret
- `glpat-` / `ghp_` / `npm_` 等平台令牌
- 形如 `mysql://user:password@host/db` 的连接串
- `-----BEGIN RSA PRIVATE KEY-----` 私钥块
- Kubernetes Secret 中 Base64 编码的口令字段
- Dockerfile / 镜像构建历史中的 `ENV SECRET_KEY=...`

> 本文件自身包含大量"示例值"，是验证误报控制能力的重要反例语料。
""",
    )

    print("完成。所有凭据均为伪造值，可安全用于演示与测试。")


if __name__ == "__main__":
    main()
