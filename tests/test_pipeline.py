"""端到端测试：检测流水线、去重聚合、报表脱敏。

运行： python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from credwatch.dedup import Deduplicator  # noqa: E402
from credwatch.detectors import DetectionPipeline, RuleEngine  # noqa: E402
from credwatch.models import Document, utcnow  # noqa: E402
from credwatch.report import render_json  # noqa: E402

RULES_DIR = PROJECT_ROOT / "config" / "rules"
SECRET = "AKIA5F7KQ2Z8N3WLD9MX"


def make_doc(url: str, text: str, path_hint: str, source: str = "github") -> Document:
    return Document(
        doc_id=Document.new_id(source, url),
        source=source,
        url=url,
        text=text,
        path_hint=path_hint,
        metadata={"source_category": "代码托管平台"},
    )


class TestPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = RuleEngine.from_dir(RULES_DIR)

    def test_pipeline_flags_real_leak(self) -> None:
        pipeline = DetectionPipeline(self.engine, hmac_salt="test-salt")
        doc = make_doc(
            "https://github.com/acme/app/blob/main/.env",
            f"# production\nAWS_ACCESS_KEY_ID={SECRET}\nAWS_SECRET_ACCESS_KEY={'aB3dE6gH9jK2mN5pQ8sT1uV4wX7yZ0AbCdEf'}\n",
            ".env",
        )
        result = pipeline.run([doc])
        self.assertGreater(len(result.findings), 0, "应至少命中一条")
        self.assertTrue(any(f.masked.endswith("D9MX") for f in result.findings))

    def test_pipeline_ignores_placeholders(self) -> None:
        pipeline = DetectionPipeline(self.engine, hmac_salt="test-salt")
        doc = make_doc(
            "https://github.com/acme/app/blob/main/README.md",
            "Set `AWS_ACCESS_KEY_ID=your_access_key_here` before running.\n"
            "SECRET_KEY=<YOUR_SECRET>\n",
            "README.md",
        )
        result = pipeline.run([doc])
        self.assertEqual(len(result.findings), 0, "文档占位符不应产生发现")

    def test_same_secret_in_multiple_files_kept_as_separate_exposures(self) -> None:
        """同一凭据出现在不同文件时，必须分别保留暴露点，最终由去重层聚合。"""
        pipeline = DetectionPipeline(self.engine, hmac_salt="test-salt")
        docs = [
            make_doc(f"https://github.com/acme/app/blob/main/{name}", f"KEY={SECRET}\n", name)
            for name in (".env", "config.py", "deploy.sh")
        ]
        result = pipeline.run(docs)
        keys = [f.fingerprint for f in result.findings if f.masked.endswith("D9MX")]
        self.assertEqual(len(keys), 3, "三个文件应各产生一条暴露记录")
        self.assertEqual(len(set(keys)), 1, "指纹应一致，便于聚合为同一凭据")

    def test_statistics_recorded(self) -> None:
        pipeline = DetectionPipeline(self.engine, hmac_salt="test-salt")
        doc = make_doc("https://x/y", f"KEY={SECRET}\n", ".env")
        result = pipeline.run([doc])
        self.assertEqual(result.stats.documents_scanned, 1)
        self.assertGreater(result.stats.bytes_scanned, 0)
        self.assertIn("1_格式命中候选", result.stats.stage_counts)


class TestDeduplication(unittest.TestCase):
    def test_cross_channel_escalates_severity(self) -> None:
        engine = RuleEngine.from_dir(RULES_DIR)
        pipeline = DetectionPipeline(engine, hmac_salt="test-salt")

        doc_a = make_doc("https://github.com/acme/app/blob/main/.env", f"KEY={SECRET}\n", ".env")
        doc_b = make_doc(
            "https://hub.docker.com/r/acme/app",
            f"# 镜像构建历史\nENV SECRET_ACCESS_KEY={'aB3dE6gH9jK2mN5pQ8sT1uV4wX7yZ0Ab'}\nAPI_KEY={SECRET}\n",
            "layer0.tar",
            source="container_registry",
        )
        doc_b.metadata["source_category"] = "容器镜像"

        findings = pipeline.run([doc_a, doc_b]).findings
        target = [f for f in findings if f.masked.endswith("D9MX")]
        self.assertTrue(target, "应命中共享凭据")

        aggregator = Deduplicator()
        aggregator.add_many(target)
        clusters = aggregator.correlate()
        self.assertEqual(len(clusters), 1, "同一凭据应聚合为一条")
        self.assertTrue(clusters[0].multi_channel, "跨渠道出现应被标记")
        self.assertEqual(clusters[0].exposure_count, 2)


class TestReportRedaction(unittest.TestCase):
    def test_no_plaintext_in_json_output(self) -> None:
        """报告输出中绝不能出现明文凭据——这是本平台的合规底线。"""
        engine = RuleEngine.from_dir(RULES_DIR)
        pipeline = DetectionPipeline(engine, hmac_salt="test-salt")
        doc = make_doc("https://github.com/acme/app/blob/main/.env", f"KEY={SECRET}\n", ".env")
        result = pipeline.run([doc])
        aggregator = Deduplicator()
        aggregator.add_many(result.findings)
        clusters = aggregator.correlate()

        from credwatch.scheduler import ScanResult
        from credwatch.models import ScanStats

        scan_result = ScanResult(
            stats=result.stats,
            clusters=clusters,
            attributions={},
            credential_stats=aggregator.statistics(),
        )
        payload = render_json(scan_result)
        self.assertNotIn(SECRET, payload, "JSON 报告中不应出现明文凭据")
        parsed = json.loads(payload)
        self.assertEqual(len(parsed["clusters"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
