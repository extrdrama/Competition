"""组合风险关联（凭据对）与规则库自检测试。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from credwatch.correlation import PairCorrelator, origin_key, pair_statistics  # noqa: E402
from credwatch.detectors import DetectionPipeline, RuleEngine  # noqa: E402
from credwatch.models import Document  # noqa: E402

RULES_DIR = PROJECT_ROOT / "config" / "rules"

AWS_AK = "AKIA5F7KQ2Z8N3WLD9MX"
AWS_SK = "K7fQ2mZx9Rt4Wp1Ld8Nv3Hb6Yc5Gs0Ae7Ui2Og4Z"


def make_doc(url: str, text: str, path_hint: str = ".env", source: str = "github") -> Document:
    return Document(
        doc_id=Document.new_id(source, url),
        source=source,
        url=url,
        text=text,
        path_hint=path_hint,
        metadata={"source_category": "代码托管平台"},
    )


class TestOriginKey(unittest.TestCase):
    def test_github_repo(self) -> None:
        self.assertEqual(
            origin_key("https://github.com/acme/app/blob/main/.env"), "acme/app"
        )

    def test_gitee_repo(self) -> None:
        self.assertEqual(origin_key("https://gitee.com/team/proj/blob/HEAD/a.env"), "team/proj")

    def test_docker_image(self) -> None:
        self.assertEqual(
            origin_key("https://hub.docker.com/r/acme/api"), "acme/api"
        )

    def test_local_engineering_dir(self) -> None:
        self.assertEqual(origin_key("file:///x/webapp/.env", "webapp/.env"), "webapp")


class TestPairCorrelation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = RuleEngine.from_dir(RULES_DIR)

    def _findings(self, docs):
        pipeline = DetectionPipeline(self.engine, hmac_salt="test-salt")
        return pipeline.run(docs).findings

    def test_same_document_pair_detected(self) -> None:
        doc = make_doc(
            "https://github.com/acme/app/blob/main/.env",
            f"AWS_ACCESS_KEY_ID={AWS_AK}\nAWS_SECRET_ACCESS_KEY={AWS_SK}\n",
        )
        findings = self._findings([doc])
        result = PairCorrelator().correlate(findings)
        self.assertEqual(len(result.pairs), 1)
        pair = result.pairs[0]
        self.assertEqual(pair.spec_key, "aws_access_pair")
        self.assertEqual(pair.scope, "document")
        self.assertEqual(pair.severity, "critical")
        self.assertEqual(len(pair.members), 2)

    def test_pair_upgrades_member_severity(self) -> None:
        """配对后成员风险等级必须被提升，并写入组合风险说明。"""
        doc = make_doc(
            "https://github.com/acme/app/blob/main/.env",
            f"AWS_ACCESS_KEY_ID={AWS_AK}\nAWS_SECRET_ACCESS_KEY={AWS_SK}\n",
        )
        findings = self._findings([doc])
        PairCorrelator().correlate(findings)
        for finding in findings:
            self.assertEqual(finding.severity, "critical")
            self.assertTrue(finding.metadata.get("credential_pairs"))

    def test_single_credential_produces_no_pair(self) -> None:
        """只有 Access Key ID 没有 Secret —— 不构成凭据对，不应误报组合风险。"""
        doc = make_doc(
            "https://github.com/acme/app/blob/main/.env",
            f"AWS_ACCESS_KEY_ID={AWS_AK}\n",
        )
        result = PairCorrelator().correlate(self._findings([doc]))
        self.assertEqual(result.pairs, [])

    def test_origin_scope_catches_cross_file_pair(self) -> None:
        """AK 与 SK 分别写在同仓库的两个文件里，同样构成完整凭据。"""
        base = "https://github.com/acme/app/blob/main/"
        docs = [
            make_doc(f"{base}.env", f"AWS_ACCESS_KEY_ID={AWS_AK}\n"),
            make_doc(f"{base}config/settings.py", f'AWS_SECRET_ACCESS_KEY = "{AWS_SK}"\n',
                     "config/settings.py"),
        ]
        result = PairCorrelator().correlate(self._findings(docs))
        self.assertTrue(result.pairs, "跨文件配对应当被识别")
        scopes = {p.scope for p in result.pairs}
        self.assertIn("origin", scopes)
        self.assertEqual(result.pairs[0].spec_key, "aws_access_pair")

    def test_different_repos_do_not_pair(self) -> None:
        """不同仓库中的两条凭据不应被关联（避免跨主体误关联）。"""
        docs = [
            make_doc("https://github.com/acme/app/blob/main/.env",
                     f"AWS_ACCESS_KEY_ID={AWS_AK}\n"),
            make_doc("https://github.com/other/repo/blob/main/.env",
                     f"AWS_SECRET_ACCESS_KEY={AWS_SK}\n"),
        ]
        result = PairCorrelator().correlate(self._findings(docs))
        self.assertEqual(result.pairs, [])

    def test_same_file_preferred_over_origin_scope(self) -> None:
        """同文件与同仓库都能匹配时，只保留更精确的同文件结论，不重复上报。"""
        docs = [
            make_doc("https://github.com/acme/app/blob/main/.env",
                     f"AWS_ACCESS_KEY_ID={AWS_AK}\nAWS_SECRET_ACCESS_KEY={AWS_SK}\n"),
        ]
        result = PairCorrelator().correlate(self._findings(docs))
        scopes = [p.scope for p in result.pairs if p.spec_key == "aws_access_pair"]
        self.assertEqual(scopes.count("origin"), 0)

    def test_statistics(self) -> None:
        doc = make_doc(
            "https://github.com/acme/app/blob/main/.env",
            f"AWS_ACCESS_KEY_ID={AWS_AK}\nAWS_SECRET_ACCESS_KEY={AWS_SK}\n",
        )
        result = PairCorrelator().correlate(self._findings([doc]))
        stats = pair_statistics(result.pairs)
        self.assertEqual(stats["pairs"], 1)
        self.assertEqual(stats["document_scope"], 1)


class TestRuleLint(unittest.TestCase):
    """规则库自检：规则文件是数据，数据也要有校验。"""

    def test_lint_reports_no_errors(self) -> None:
        from credwatch.rule_lint import lint_rules

        report = lint_rules(RULES_DIR)
        self.assertEqual(
            report.errors, [],
            "规则库存在错误：\n" + "\n".join(str(e) for e in report.errors),
        )

    def test_lint_detects_duplicate_id(self) -> None:
        import tempfile

        from credwatch.rule_lint import lint_rules

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dup.yaml"
            path.write_text(
                "category: t\nlabel: 测试\nrules:\n"
                "  - id: same\n    name: a\n    kind: k\n    severity: low\n"
                "    pattern: 'a'\n"
                "  - id: same\n    name: b\n    kind: k\n    severity: low\n"
                "    pattern: 'b'\n",
                encoding="utf-8",
            )
            report = lint_rules(Path(tmp))
            self.assertTrue(any("重复" in str(e) for e in report.errors))

    def test_lint_detects_secret_group_out_of_range(self) -> None:
        import tempfile

        from credwatch.rule_lint import lint_rules

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yaml"
            path.write_text(
                "category: t\nlabel: 测试\nrules:\n"
                "  - id: bad\n    name: a\n    kind: k\n    severity: low\n"
                "    pattern: 'x(y)'\n    secret_group: 5\n",
                encoding="utf-8",
            )
            report = lint_rules(Path(tmp))
            self.assertTrue(any("secret_group" in str(e) for e in report.errors))


class TestRuleInduction(unittest.TestCase):
    """规则自动归纳：从样本生成候选规则。"""

    def test_induce_common_prefix_rule(self) -> None:
        from credwatch.rule_induction import induce_rule

        samples = ["sk-AbC1234567890123456789012", "sk-ZxY9876543210987654321", "sk-MnB1111111111111111111111"]
        draft = induce_rule("induced-test", "测试归纳", samples)
        self.assertEqual(draft.prefix, "sk-")
        self.assertIn("[A-Za-z0-9", draft.pattern)
        # 归纳出的正则必须能命中全部样本（这是归纳正确性的硬标准）
        import re

        pattern = re.compile(draft.pattern)
        for sample in samples:
            self.assertTrue(pattern.search(sample), f"应命中样本 {sample}")

    def test_quality_note_flags_weak_prefix(self) -> None:
        from credwatch.rule_induction import induce_rule

        # 无公共前缀的随机样本应给出质量预警
        samples = ["a1B2c3D4e5F6g7H8i9J0", "x9Y8z7W6v5U4t3S2r1Q0", "m5N4o3P2q1R0s9T8u7V6"]
        draft = induce_rule("induced-weak", "弱前缀", samples)
        self.assertTrue(draft.quality_note, "应给出质量说明")
        self.assertIn("无公共前缀", draft.quality_note)

    def test_conflict_detection_finds_duplicate(self) -> None:
        from credwatch.rule_induction import detect_conflicts, induce_rule

        samples = ["sk-AbC1234567890123456789012", "sk-ZxY9876543210987654321"]
        draft = induce_rule("induced-dup", "重复", samples)
        conflicts = detect_conflicts(draft, {"existing": draft.pattern})
        self.assertTrue(conflicts, "与完全相同规则应检测出冲突")


if __name__ == "__main__":
    unittest.main(verbosity=2)
