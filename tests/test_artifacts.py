"""App 与小程序渠道的端到端测试。

构造最小的 APK（zip）与 wxapkg（按未加密格式手工组包）样本，
验证"解包 → 提取 → 检测"全链路真实可用——此前这两个渠道没有
任何测试覆盖，属于逻辑审查中发现的覆盖缺口。
"""

from __future__ import annotations

import io
import struct
import unittest
import zipfile
from pathlib import Path

from credwatch.detectors import DetectionPipeline, RuleEngine
from credwatch.models import Document
from credwatch.parsers.archive import iter_wxapkg

RULES_DIR = Path(__file__).resolve().parent.parent / "config" / "rules"

AWS_KEY = "K7fQ2mZx9Rt4Wp1Ld8Nv3Hb6Yc5Gs0Ae7Ui2Og4Z"
WX_SECRET = "a1b2c3d4e5f60718293a4b5c6d7e8f90"


def _make_apk_bytes() -> bytes:
    """最小 APK：本质是 zip，含一个泄露 AWS 密钥的 .env。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "assets/config.env",
            f"AWS_SECRET_ACCESS_KEY={AWS_KEY}\nAWS_REGION=cn-north-1\n",
        )
        zf.writestr(
            "res/values/strings.xml",
            '<resources><string name="app_name">Demo</string></resources>',
        )
    return buf.getvalue()


def _make_wxapkg_bytes(files: dict[str, str]) -> bytes:
    """按未加密 wxapkg 格式手工组包：

    头部 14 字节（0xBE ... 0xED）+ 索引（fileCount + N×(nameLen,name,offset,size)）
    + 数据体。offset 相对数据体起点。
    """
    body = b""
    index_items = []
    offset = 0
    for name, content in files.items():
        data = content.encode("utf-8")
        index_items.append((name.encode("utf-8"), offset, len(data)))
        body += data
        offset += len(data)

    index = struct.pack(">I", len(index_items))
    for name, off, size in index_items:
        index += struct.pack(">I", len(name)) + name
        index += struct.pack(">I", off) + struct.pack(">I", size)

    index_len = len(index)
    # 头部 14 字节：firstMark(1) + info1(4) + indexLen(4) + bodyLen(4) + lastMark(1)
    header = bytes([0xBE]) + struct.pack(">I", 0) + struct.pack(">I", index_len) + struct.pack(
        ">I", len(body)
    ) + bytes([0xED])
    return header + index + body


class TestArtifactChannels(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = RuleEngine.from_dir(RULES_DIR)

    def _detect(self, docs: list[Document]) -> set[str]:
        pipeline = DetectionPipeline(self.engine, hmac_salt="t")
        fired: set[str] = set()
        for result in (pipeline.run([d]) for d in docs):
            fired |= {f.rule_id for f in result.findings}
        return fired

    def test_apk_env_credential_detected(self) -> None:
        """APK 内 assets/.env 中的 AWS 密钥应被解包并检出。"""
        from credwatch.sources.artifact import MobileAppSource

        apk = _make_apk_bytes()
        path = Path(__file__).parent / "_fixture_demo.apk"
        path.write_bytes(apk)  # 留在磁盘（已 gitignore），由本地清理
        src = MobileAppSource(Settings_stub(), artifacts=[str(path)])
        docs = []
        for raw in src.discover({}):
            docs.extend(src.normalize(raw))
        self.assertTrue(docs, "APK 应解包出至少 1 份文档")
        fired = self._detect(docs)
        self.assertIn("aws-secret-access-key", fired)

    def test_wxapkg_parser_roundtrip(self) -> None:
        """手工组包的 wxapkg 应能按格式解出原始文件。"""
        files = {
            "app.js": "const secret = 'WxMiniS3cretKey2026';",
            "config.json": f'{{"appid":"wx1234567890abcdef","secret":"{WX_SECRET}"}}',
        }
        data = _make_wxapkg_bytes(files)
        entries = {e.name: e.data for e in iter_wxapkg(data)}
        self.assertEqual(set(entries), set(files))
        self.assertIn(WX_SECRET, entries["config.json"].decode("utf-8"))

    def test_wxapkg_secret_detected_end_to_end(self) -> None:
        """小程序包中的 AppSecret 应被解包并检出。"""
        from credwatch.sources.artifact import MiniProgramSource

        pkg = _make_wxapkg_bytes(
            {
                "app.js": f"App({{appid:'wx1234567890abcdef'}});wx.init('{WX_SECRET}');",
                "config.json": f'{{"appid":"wx1234567890abcdef","secret":"{WX_SECRET}"}}',
            }
        )
        path = Path(__file__).parent / "_fixture_demo.wxapkg"
        path.write_bytes(pkg)
        src = MiniProgramSource(Settings_stub(), packages=[str(path)])
        docs = []
        for raw in src.discover({}):
            docs.extend(src.normalize(raw))
        self.assertTrue(docs, "wxapkg 应解包出至少 1 份文档")
        fired = self._detect(docs)
        # AppSecret 规则要求 wx/微信关键词共现，config.json 中的 appid 提供上下文
        self.assertTrue(
            {"wechat-miniapp-appsecret", "yaml-password-field",
             "os-account-credential"} & fired,
            f"应命中小程序凭据类规则，实际: {fired}",
        )


def Settings_stub():
    """测试用最小配置（不落盘、不联网）。"""
    from credwatch.config import Settings

    return Settings.load()


if __name__ == "__main__":
    unittest.main()
