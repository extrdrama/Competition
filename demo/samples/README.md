# 演示样本说明

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
