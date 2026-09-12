"""上下文结构化提取（敏感信息对）测试。

这组能力对应赛题"关联上下文，输出关联的敏感信息对"的要求。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from credwatch.context_extract import (  # noqa: E402
    ContextExtractor,
    context_statistics,
)
from credwatch.models import Evidence, Finding  # noqa: E402


def make_finding(masked: str, line_no: int | None = None) -> Finding:
    return Finding(
        rule_id="test",
        rule_name="测试",
        category="database",
        severity="high",
        confidence=0.9,
        detector="rule",
        masked=masked,
        fingerprint="f" * 64,
        evidence=Evidence(url="file://a/.env", path_hint=".env", line_no=line_no),
    )


class TestDsnContext(unittest.TestCase):
    def setUp(self) -> None:
        self.extractor = ContextExtractor()

    def test_mysql_dsn_extracts_full_pair(self) -> None:
        text = 'DATABASE_URL=mysql://app_rw:S3cr3tPass@10.20.30.41:3306/production\n'
        finding = make_finding("S3****ass", 1)
        ctx = self.extractor.extract(finding, text)
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx.service, "MySQL")
        self.assertEqual(ctx.fields["host"], "10.20.30.41")
        self.assertEqual(ctx.fields["port"], "3306")
        self.assertEqual(ctx.fields["username"], "app_rw")
        self.assertEqual(ctx.fields["database"], "production")
        # 口令绝不落明文
        self.assertNotIn("S3cr3tPass", str(ctx.fields))
        self.assertNotEqual(ctx.fields["password"], "S3cr3tPass")
        self.assertTrue(ctx.fields["password"].startswith("S3"))

    def test_default_port_filled_when_missing(self) -> None:
        text = "REDIS_PASSWORD=x\nREDIS_URL=redis://:hunter2@cache.internal\n"
        finding = make_finding("hun****er2", 2)
        ctx = self.extractor.extract(finding, text)
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx.service, "Redis")
        self.assertEqual(ctx.fields.get("port"), "6379")

    def test_plain_https_url_is_not_a_dsn(self) -> None:
        """普通 URL 不应被拆成 DSN 字段（真实数据实测教训）。"""
        text = 'api_base_url = "https://api.example.com/v2/"\ntoken = "abcdefgh12345678"\n'
        finding = make_finding("abc****5678", 2)
        ctx = self.extractor.extract(finding, text)
        if ctx is not None:
            self.assertNotEqual(ctx.extraction, "dsn")
            self.assertNotIn("database", ctx.fields)

    def test_internal_ip_flagged(self) -> None:
        text = "MYSQL_HOST=10.20.30.41\nMYSQL_PASSWORD=Pr0d_aB3cD4eF\n"
        finding = make_finding("Pr0****4eF", 2)
        ctx = self.extractor.extract(finding, text)
        self.assertIsNotNone(ctx)
        self.assertTrue(ctx.is_internal, "内网 IP 应被标记")


class TestNearbyContext(unittest.TestCase):
    def setUp(self) -> None:
        self.extractor = ContextExtractor()

    def test_prefixed_variable_names_recognised(self) -> None:
        """MYSQL_USER / DB_HOST 这类带前缀的变量名也应被识别。"""
        text = (
            "MYSQL_HOST=10.20.30.41\n"
            "MYSQL_PORT=3306\n"
            "MYSQL_USER=app_rw\n"
            "MYSQL_PASSWORD=Pr0d_aB3cD4eF\n"
        )
        finding = make_finding("Pr0****4eF", 4)
        ctx = self.extractor.extract(finding, text)
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx.fields.get("username"), "app_rw")
        self.assertEqual(ctx.fields.get("host"), "10.20.30.41")
        self.assertEqual(ctx.fields.get("port"), "3306")

    def test_environment_references_not_extracted(self) -> None:
        """`${VAR}` / `os.environ` 引用不是明文，不应进入信息对。"""
        text = "DB_HOST=${DB_HOST}\nDB_USER=os.environ['DB_USER']\nDB_PASSWORD=Pr0d_aB3cD4eF\n"
        finding = make_finding("Pr0****4eF", 3)
        ctx = self.extractor.extract(finding, text)
        if ctx is not None:
            self.assertNotEqual(ctx.fields.get("host"), "${DB_HOST}")
            self.assertNotEqual(ctx.fields.get("username"), "os.environ['DB_USER']")


class TestContextStatistics(unittest.TestCase):
    def test_statistics_counts_coverage_and_hosts(self) -> None:
        from credwatch.context_extract import enrich_with_context
        from credwatch.models import Document
        from credwatch.detectors import DetectionPipeline, RuleEngine

        engine = RuleEngine.from_dir(PROJECT_ROOT / "config" / "rules")
        pipeline = DetectionPipeline(engine, hmac_salt="s")
        text = (
            "MYSQL_HOST=10.20.30.41\n"
            "MYSQL_PORT=3306\n"
            "MYSQL_USER=app_rw\n"
            "MYSQL_PASSWORD=Pr0d_aB3cD4eF\n"
        )
        doc = Document(
            doc_id="d", source="local_dir", url="file://a/.env", text=text,
            path_hint=".env", metadata={"source_category": "本地与企业内网"},
        )
        findings = pipeline.run([doc]).findings
        count = enrich_with_context(findings, {doc.url: text})
        stats = context_statistics(findings)
        self.assertGreater(count, 0)
        self.assertEqual(stats["findings"], len(findings))
        self.assertGreater(stats["with_context"], 0)
        self.assertGreater(stats["unique_hosts"], 0)
        self.assertTrue(stats["by_service"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
