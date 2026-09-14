"""SARIF 2.1.0 输出测试：与 gitleaks/trufflehog 同级的 CI 平台集成能力。

验证三件事：结构合规、结果可溯源（指纹）、绝不含明文凭据。
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
from credwatch.models import Document  # noqa: E402
from credwatch.report import render_sarif  # noqa: E402

RULES_DIR = PROJECT_ROOT / "config" / "rules"
SECRET = "AKIA5F7KQ2Z8N3WLD9MX"


def _scan_result():
    engine = RuleEngine.from_dir(RULES_DIR)
    pipeline = DetectionPipeline(engine, hmac_salt="test-salt")
    doc = Document(
        doc_id=Document.new_id("github", "https://github.com/acme/app/blob/main/.env"),
        source="github",
        url="https://github.com/acme/app/blob/main/.env",
        text=f"KEY={SECRET}\n",
        path_hint=".env",
        metadata={"source_category": "代码托管平台"},
    )
    result = pipeline.run([doc])
    aggregator = Deduplicator()
    aggregator.add_many(result.findings)
    clusters = aggregator.correlate()

    from credwatch.models import ScanStats
    from credwatch.scheduler import ScanResult

    return ScanResult(
        stats=result.stats,
        clusters=clusters,
        attributions={},
        credential_stats=aggregator.statistics(),
    )


class TestSarifOutput(unittest.TestCase):
    def test_sarif_structure_and_levels(self) -> None:
        payload = render_sarif(_scan_result(), None)
        parsed = json.loads(payload)
        self.assertEqual(parsed["version"], "2.1.0")
        self.assertTrue(parsed["runs"], "应至少包含一个 run")
        run = parsed["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "CredWatch")
        self.assertTrue(run["results"], "应有至少一条 result")
        first = run["results"][0]
        self.assertIn(first["level"], {"error", "warning", "note"})
        self.assertIn("ruleId", first)
        self.assertIn("credwatchFingerprint/v1", first["partialFingerprints"])
        self.assertTrue(first["message"]["text"].strip())
        rules = run["tool"]["driver"]["rules"]
        self.assertTrue(any(r["id"] == first["ruleId"] for r in rules), "result 应有对应 rule 定义")

    def test_sarif_no_plaintext(self) -> None:
        payload = render_sarif(_scan_result(), None)
        self.assertNotIn(SECRET, payload, "SARIF 中不应出现明文凭据（掩码合规底线）")


if __name__ == "__main__":
    unittest.main(verbosity=2)
