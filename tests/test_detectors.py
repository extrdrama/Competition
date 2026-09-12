"""检测层单元测试。

运行： python -m unittest discover -s tests -v
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from credwatch.detectors import (  # noqa: E402
    DetectionPipeline,
    EntropyConfig,
    EntropyDetector,
    ProbabilityScorer,
    RuleEngine,
    StructuredParser,
    is_placeholder,
    shannon_entropy,
)
from credwatch.models import mask_secret  # noqa: E402

RULES_DIR = PROJECT_ROOT / "config" / "rules"


class TestPlaceholderFilter(unittest.TestCase):
    """占位符过滤是误报控制的第一道闸门。"""

    def test_common_placeholders_are_rejected(self) -> None:
        for value in [
            "your_api_key_here",
            "xxxxxxxxxxxx",
            "<YOUR_TOKEN>",
            "${ENV_SECRET}",
            "changeme",
            "placeholder",
            "aaaa",
            "1234",
        ]:
            with self.subTest(value=value):
                self.assertTrue(is_placeholder(value), f"{value} 应被判为占位符")

    def test_real_looking_values_pass(self) -> None:
        for value in ["AKIA5F7KQ2Z8N3WLD9MX", "Pr0d_aB3cD4eF5gH6", "glpat-Kx9mQ2Zr7Wp4Ld8Nv3Hb"]:
            with self.subTest(value=value):
                self.assertFalse(is_placeholder(value), f"{value} 不应被判为占位符")


class TestEntropy(unittest.TestCase):
    def test_shannon_entropy_bounds(self) -> None:
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertLess(shannon_entropy("aaaaaaaaaaaa"), 1.0)
        self.assertGreater(shannon_entropy("aB3dE6gH9jK2mN5pQ8sT"), 3.5)

    def test_high_entropy_token_detected(self) -> None:
        detector = EntropyDetector(EntropyConfig(threshold=3.5))
        text = 'token = "aB3dE6gH9jK2mN5pQ8sT1uV4wX7yZ0"'
        candidates = detector.scan(text)
        self.assertTrue(any("aB3dE6gH9jK2mN5pQ8sT1uV4wX7yZ0" == c.secret for c in candidates))

    def test_low_entropy_text_not_detected(self) -> None:
        detector = EntropyDetector()
        self.assertEqual(detector.scan("this is a normal english sentence with words"), [])


class TestRuleEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = RuleEngine.from_dir(RULES_DIR)

    def test_rules_loaded(self) -> None:
        stats = self.engine.stats()
        self.assertGreater(stats["total_rules"], 100, "规则库规模应超过 100 条")
        self.assertGreaterEqual(len(stats["categories"]), 5, "应覆盖至少 5 个凭据大类")
        self.assertIn("aws", stats["validators"])

    def test_detect_aws_access_key(self) -> None:
        findings = self.engine.scan("AWS_ACCESS_KEY_ID=AKIA5F7KQ2Z8N3WLD9MX")
        self.assertTrue(any(f.rule_id == "aws-access-key-id" for f in findings))

    def test_detect_gitlab_pat(self) -> None:
        findings = self.engine.scan("token: glpat-Kx9mQ2Zr7Wp4Ld8Nv3Hb")
        self.assertTrue(any(f.rule_id == "gitlab-pat" for f in findings))

    def test_dsn_uses_password_not_username(self) -> None:
        """连接串规则必须取到口令，而不是用户名。"""
        findings = self.engine.scan("DATABASE_URL=mysql://app_rw:Pr0d_aB3cD4eF@10.0.0.1:3306/db")
        mysql = [f for f in findings if f.rule_id == "mysql-uri"]
        self.assertTrue(mysql, "应命中 MySQL 连接串规则")
        self.assertEqual(mysql[0].secret, "Pr0d_aB3cD4eF", "取到的应是口令而非用户名")

    def test_doc_placeholder_dsn_rejected(self) -> None:
        """文档里的 user:password@host 示例必须被过滤。"""
        findings = self.engine.scan("形如 `mysql://user:password@host/db` 的连接串")
        self.assertFalse(
            any(f.rule_id == "mysql-uri" for f in findings),
            "示例 DSN 不应被上报",
        )

    def test_private_key_header_alone_rejected(self) -> None:
        """只提到私钥头（无密钥体）不应命中。"""
        findings = self.engine.scan("文档中提到 `-----BEGIN RSA PRIVATE KEY-----` 这一行")
        self.assertFalse(
            any(f.rule_id == "private-key-rsa-pem" for f in findings),
            "仅私钥头不应命中",
        )

    def test_private_key_with_body_detected(self) -> None:
        body = "\n".join("MII" + "aB3dE6gH9jK2mN5pQ8sT1uV4wX7yZ0AbCdEfGhIjKlMnOpQrStUvWxYz" for _ in range(3))
        text = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"
        findings = self.engine.scan(text)
        self.assertTrue(any(f.rule_id == "private-key-rsa-pem" for f in findings))


class TestStructuredParser(unittest.TestCase):
    """结构化解析返回 Candidate，键名放在 metadata['config_key']。"""

    def setUp(self) -> None:
        self.parser = StructuredParser()

    @staticmethod
    def _keys(hits) -> list[str]:
        return [str(h.metadata.get("config_key", "")) for h in hits]

    def test_dotenv_password_detected(self) -> None:
        hits = self.parser.parse("MYSQL_PASSWORD=Pr0d_aB3cD4eF\nAPP_ENV=production\n")
        keys = self._keys(hits)
        self.assertIn("MYSQL_PASSWORD", keys)
        self.assertNotIn("APP_ENV", keys, "非凭据变量不应命中")
        self.assertTrue(any(h.secret == "Pr0d_aB3cD4eF" for h in hits))

    def test_k8s_secret_base64_decoded(self) -> None:
        import base64

        encoded = base64.b64encode(b"Pr0d_aB3cD4eF").decode()
        text = f"apiVersion: v1\nkind: Secret\ndata:\n  db-password: {encoded}\n"
        hits = self.parser.parse(text)
        self.assertIn("db-password", self._keys(hits))
        self.assertTrue(
            any(h.secret == "Pr0d_aB3cD4eF" for h in hits),
            "Base64 值应被解码后再上报",
        )

    def test_ini_credentials_section(self) -> None:
        text = "[default]\naws_access_key_id = AKIA5F7KQ2Z8N3WLD9MX\nregion = cn-north-1\n"
        hits = self.parser.parse(text)
        keys = self._keys(hits)
        self.assertTrue(
            any("aws_access_key_id" in k for k in keys),
            f"应命中 INI 凭据字段，实际命中：{keys}",
        )

    def test_docker_env_leak(self) -> None:
        hits = self.parser.parse("ENV SECRET_KEY=aB3dE6gH9jK2mN5pQ8sT1uV4wX7yZ0")
        self.assertIn("SECRET_KEY", self._keys(hits))


class TestProbabilityScoring(unittest.TestCase):
    """可解释概率评分：既要判得准，也要能解释为什么。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = RuleEngine.from_dir(RULES_DIR)
        cls.scorer = ProbabilityScorer()

    def _candidate(self, rule_id: str, secret: str, span: tuple[int, int]):
        from credwatch.detectors import Candidate

        return Candidate(
            rule_id=rule_id,
            rule_name=rule_id,
            category="generic",
            kind="k",
            severity="high",
            secret=secret,
            span=span,
        )

    def test_sensitive_context_scores_higher_than_docs_context(self) -> None:
        text = "AWS_SECRET_ACCESS_KEY=AKIA5F7KQ2Z8N3WLD9MX"
        cand = self._candidate("aws-secret-access-key", "AKIA5F7KQ2Z8N3WLD9MX", (21, 41))
        sensitive, _ = self.scorer.score(cand, text, ".env")
        docs, _ = self.scorer.score(cand, text, "docs/readme.md")
        self.assertGreater(sensitive, docs, "敏感路径下的概率应显著更高")

    def test_explanation_lists_contributions(self) -> None:
        text = "AWS_SECRET_ACCESS_KEY=AKIA5F7KQ2Z8N3WLD9MX"
        cand = self._candidate("aws-secret-access-key", "AKIA5F7KQ2Z8N3WLD9MX", (21, 41))
        probability, explanation = self.scorer.score(cand, text, ".env")
        self.assertGreater(probability, 0.9)
        self.assertTrue(explanation.contributions, "应给出逐特征贡献")
        names = [name for name, _, _ in explanation.contributions]
        self.assertIn("sensitive_identifier", names)
        self.assertIn("known_prefix", names)
        self.assertTrue(explanation.summary())

    def test_doc_path_penalty_makes_entropy_candidate_rejected(self) -> None:
        """高熵串出现在文档里、又没有敏感标识符时，应当被判为噪声。"""
        text = "参考值： aB3dE6gH9jK2mN5pQ8sT1uV4wX7yZ0"
        cand = self._candidate("entropy-high-value", "aB3dE6gH9jK2mN5pQ8sT1uV4wX7yZ0", (5, 37))
        probability, explanation = self.scorer.score(cand, text, "docs/notes.md")
        self.assertLess(probability, 0.5, f"应低于阈值，实际 {probability}")
        self.assertIn("doc_path", [n for n, _, _ in explanation.contributions])

    def test_probability_is_bounded(self) -> None:
        for secret in ("a" * 4, "A" * 200, "AKIA5F7KQ2Z8N3WLD9MX"):
            cand = self._candidate("x", secret, (0, len(secret)))
            probability, _ = self.scorer.score(cand, f"key={secret}", ".env")
            self.assertGreaterEqual(probability, 0.0)
            self.assertLessEqual(probability, 1.0)


class TestRealDataHardening(unittest.TestCase):
    """这两组用例来自**真实 GitHub 公开数据实测**暴露的问题，用于锁死修复。

    背景：在真实数据上，"仅凭高熵"会产生大量误报（包名、构建标识、随机哈希），
    而单个文件里几百条同类命中会把报告淹没成噪声。
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = RuleEngine.from_dir(RULES_DIR)

    def test_entropy_without_corroboration_is_rejected(self) -> None:
        """高熵串若无任何佐证（变量名/已知前缀/敏感文件），必须拦截。

        真实案例：`com/example/lib_x86` 这类包名也能达到 0.83 的概率。
        """
        from credwatch.models import Document

        text = "build output: com/example/lib_x86 done\n"
        doc = Document(
            doc_id="d", source="github", url="https://x/y.log", text=text,
            path_hint="output_log.txt", metadata={"source_category": "代码托管平台"},
        )
        result = DetectionPipeline(self.engine, hmac_salt="s").run([doc])
        self.assertEqual(
            [f.rule_id for f in result.findings if f.detector == "entropy"], [],
            "无佐证的熵命中应被拦截",
        )

    def test_entropy_with_corroboration_is_kept(self) -> None:
        """同样的高熵串，位于 .env 中（有敏感路径佐证）就应保留。

        注意：选一个不触发任何规则键名的变量（避免被更优的规则命中，
        从而无法验证"熵通道本身"是否被保留）。
        """
        from credwatch.models import Document

        text = "xyz_config = aB3dE6gH9jK2mN5pQ8sT1uV4wX7yZ0\n"
        doc = Document(
            doc_id="d", source="local_dir", url="file://a/.env", text=text,
            path_hint=".env", metadata={"source_category": "本地与企业内网"},
        )
        result = DetectionPipeline(self.engine, hmac_salt="s").run([doc])
        self.assertTrue(
            any(f.detector == "entropy" for f in result.findings),
            "有佐证的熵命中应保留，不应被门控误杀",
        )

    def test_entropy_gate_does_not_block_rule_hits(self) -> None:
        """门控只针对熵通道；`password = xxx` 这种行应被规则正常命中。"""
        from credwatch.models import Document

        text = "password = aB3dE6gH9jK2mN5pQ8sT1uV4wX7yZ0\n"
        doc = Document(
            doc_id="d", source="local_dir", url="file://a/.env", text=text,
            path_hint=".env", metadata={"source_category": "本地与企业内网"},
        )
        result = DetectionPipeline(self.engine, hmac_salt="s").run([doc])
        self.assertTrue(result.findings, "该行应产生发现（由规则命中）")

    def test_flood_control_caps_per_rule_per_doc(self) -> None:
        """同一文档内同一条规则命中 100 条时，应只保留 50 条并标注抑制数。"""
        from credwatch.models import Document

        # 100 条互不相同、且都会命中 env-assignment-password 的值
        lines = [
            f"SECRET_{i}={('aB3dE6gH9jK2mN5pQ8sT1uV4wX7yZ0' + str(i).zfill(3))[:40]}"
            for i in range(100)
        ]
        text = "\n".join(lines) + "\n"
        doc = Document(
            doc_id="d", source="local_dir", url="file://a/dump.txt", text=text,
            path_hint="dump.txt", metadata={"source_category": "代码托管平台"},
        )
        result = DetectionPipeline(self.engine, hmac_salt="s").run([doc])
        for rule_id in {f.rule_id for f in result.findings}:
            count = sum(1 for f in result.findings if f.rule_id == rule_id)
            self.assertLessEqual(
                count, 50, f"规则 {rule_id} 超过单文档上限，命中风暴抑制未生效"
            )
        self.assertIn("命中风暴抑制", result.stats.stage_counts)
        suppressed = [f for f in result.findings if f.metadata.get("flood_suppressed")]
        self.assertTrue(suppressed, "应在保留的首条上标注被抑制的数量")


class TestRuleSpecificity(unittest.TestCase):
    """通用兜底规则不得盖掉具体格式规则。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = RuleEngine.from_dir(RULES_DIR)
        cls.pipeline = DetectionPipeline(cls.engine, hmac_salt="test-salt")

    def test_specific_rule_wins_over_generic_fallback(self) -> None:
        """同一行同时命中具体规则与兜底规则时，必须保留具体规则。"""
        from credwatch.models import Document

        text = "AWS_SECRET_ACCESS_KEY=K7fQ2mZx9Rt4Wp1Ld8Nv3Hb6Yc5Gs0Ae7Ui2Og4Z\n"
        doc = Document(
            doc_id="d", source="local_dir", url="file://a/.env", text=text,
            path_hint=".env", metadata={"source_category": "本地与企业内网"},
        )
        result = self.pipeline.run([doc])
        rules = {f.rule_id for f in result.findings}
        self.assertIn("aws-secret-access-key", rules)
        self.assertNotIn(
            "env-assignment-password", rules,
            "通用兜底规则不应盖掉具体格式规则",
        )

    def test_generic_rule_specificity_is_negative(self) -> None:
        from credwatch.detectors.rule_engine import rule_specificity

        self.assertLess(rule_specificity("env-assignment-password"), 0)
        self.assertEqual(rule_specificity("aws-access-key-id"), 0)
        self.assertLess(rule_specificity("datadog-api-key", ["datadog"]), 0)

    def test_detection_is_deterministic(self) -> None:
        """同样的输入必须得到同样的结果——可复现是被评审抽查的前提。"""
        from credwatch.models import Document

        text = (
            "AWS_ACCESS_KEY_ID=AKIA5F7KQ2Z8N3WLD9MX\n"
            "AWS_SECRET_ACCESS_KEY=K7fQ2mZx9Rt4Wp1Ld8Nv3Hb6Yc5Gs0Ae7Ui2Og4Z\n"
            "MYSQL_PASSWORD=Pr0d_aB3cD4eF\n"
            "JWT_SECRET=aB3dE6gH9jK2mN5pQ8sT1uV4wX7yZ0AbCdEfGhIjKl\n"
        )
        doc = Document(
            doc_id="d", source="local_dir", url="file://a/.env", text=text,
            path_hint=".env", metadata={"source_category": "本地与企业内网"},
        )
        runs = [
            sorted(f.rule_id for f in DetectionPipeline(self.engine, hmac_salt="s").run([doc]).findings)
            for _ in range(3)
        ]
        self.assertEqual(runs[0], runs[1])
        self.assertEqual(runs[1], runs[2])


class TestMasking(unittest.TestCase):
    def test_mask_hides_middle_and_fixes_length(self) -> None:
        masked = mask_secret("AKIA5F7KQ2Z8N3WLD9MX")
        self.assertEqual(masked, "AKIA****D9MX")
        self.assertNotIn("5F7KQ2Z8N3WL", masked)

    def test_mask_length_not_leaked(self) -> None:
        """不同长度的凭据，掩码长度应一致，避免泄露真实长度。"""
        self.assertEqual(len(mask_secret("a" * 20)), len(mask_secret("a" * 60)))

    def test_pem_masked_without_body(self) -> None:
        pem = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"
        masked = mask_secret(pem)
        self.assertIn("BEGIN RSA PRIVATE KEY", masked)
        self.assertNotIn("AAAA", masked)


if __name__ == "__main__":
    unittest.main(verbosity=2)
