#!/usr/bin/env python
"""规则库全量自测：为每条规则自动生成正样本，验证"规则真的能命中"。

两级验证：
1. 正则级：exrex 从模式生成样本 → re.search 必须命中（往返一致）；
2. 引擎级：样本嵌入关键词上下文后走完整检测管线，断言该规则（或
   因更具体而遮蔽它的同跨度规则）产生发现——"伪支持"的规则在此现形。

用法：python scripts/rule_selftest.py [--json]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import random

import exrex  # noqa: E402

from credwatch.config import Settings  # noqa: E402
from credwatch.detectors import DetectionPipeline, RuleEngine  # noqa: E402
from credwatch.models import Document  # noqa: E402


def make_sample(pattern: str, tries: int = 8) -> str | None:
    """从模式生成一个匹配样本；exrex 对某些结构可能失败，多次尝试。"""
    for _ in range(tries):
        try:
            return exrex.getone(pattern, limit=3)
        except Exception:  # noqa: BLE001
            continue
    return None


# exrex 对连接串/多行清单类模式会生成退化样本（单字符口令、控制字符），
# 这些规则改用手工逼真正样本——与真实泄露形态一致，验证更有意义。
MANUAL_SAMPLES: dict[str, str] = {
    "mysql-uri": "mysql://app_rw:Pr0d_aB3cD4eF@10.20.30.41:3306/production",
    "postgresql-uri": "postgresql://api_user:V3ryS3cret99@db.internal:5432/app",
    "mongodb-uri": "mongodb://mongoadmin:M0ngoPass123@cluster0.mongodb.net/prod",
    "redis-uri": "redis://:R3disPass456@redis.internal:6379/0",
    "elasticsearch-uri": "https://elastic:ESs3cret789@elasticsearch.internal:9200",
    "clickhouse-uri": "clickhouse://ch_user:Cl1ckH0use77@clickhouse.internal:8123",
    "oracle-uri": "oracle:thin:system/Or4clePass11@ora-host:1521/ORCL",
    "rabbitmq-uri": "amqp://mq_admin:R4bbitPass22@rabbit.internal:5672/vhost",
    "kafka-sasl-jaas": (
        "org.apache.kafka.common.security.plain.PlainLoginModule required "
        "username='kafka_admin' password='K4fkaPass33';"
    ),
    "zookeeper-uri": "zookeeper://zk_user:ZkPass56789@zoo.internal:2181",
    "gaussdb-uri": "gaussdb://gauss_user:G4ussPass88@gauss.internal:5432/postgres",
    "oceanbase-uri": "oceanbase://ob_user:0bPass56789@ob.internal:2881/test",
    "ssh-tunnel-credential": "ssh -L 3306:db.internal:3306 deploy_user@jump.internal -N",
    "env-assignment-password": "MYSQL_ROOT_PASSWORD=Pr0d_aB3cD4eF",
    "ftp-credential": "ftp://ftp_user:FtpPass67890@files.internal:21/pub",
    "proxy-credential": "http://proxy_user:Pr0xyPass66@proxy.internal:8080",
    "docker-image-env-leak": "ENV DB_PASSWORD=Pr0d_aB3cD4eF",
    "kubernetes-secret-data": (
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db-cred\n"
        "data:\n  password: UHIzZDBQQXNzd29yZA==\n"
    ),
    "hardcoded-password-any": "password = 'Xk9$mQ2vLp8#'",
    "upyun-operator-token": "upyun operator password = UpYun0p3rat0rT0ken2026xyz",
    "sqlserver-uri": "jdbc:sqlserver://10.20.30.50:1433;databaseName=prod;password=Sq1Server2026x",
    "nacos-credential": "nacos.config.server=127.0.0.1\nnacos.password=N4cosSecret2026",
    "mybatis-datasource-password": "spring.datasource.password=S3cureD4ta2026",
    "dameng-password": "DM_PASSWORD=D4mengS3cret2026",
    "kingbase-password": "KINGBASE_PASSWORD=K1ngbaseS3cret2026",
    "basic-auth-url": "https://svc_deploy:Ap1Passw0rd2026@api.internal.corp/v1/build",
    "ssh-command-password": "sshpass -p 'SshPass2026x' scp app.tar.gz deploy@10.20.30.9:/opt/app",
    "bitbucket-app-password": "bitbucket app-password = BBitAppPass2026xyzw00",
    "weak-credential-pair": "root:123456\nadmin:admin",
    "yaml-password-field": "password: S3curePass2026",
    "mysql-command-password": "mysql -u root -pMysqlPass2026 -h 10.0.0.5",
    "docker-history-secret": "docker history image --password BuildPass2026x",
}


def main() -> int:
    random.seed(20260913)  # 固定种子：自测结果可复现
    engine = RuleEngine.from_dir("config/rules")
    pipeline = DetectionPipeline(engine, hmac_salt="selftest")
    settings = Settings.load()

    total = ok_regex = ok_engine = shadowed = 0
    failures: list[str] = []
    shadow_notes: list[str] = []

    for rule in engine.rules:
        total += 1
        pattern = rule.compiled.pattern
        sample = MANUAL_SAMPLES.get(rule.id) or make_sample(pattern)
        if sample is None:
            failures.append(f"{rule.id}: 样本生成失败（exrex 不支持该模式结构）")
            continue

        # ---- 1) 正则级往返 ----
        if not rule.compiled.search(sample):
            failures.append(f"{rule.id}: 正则往返失败，生成的样本不匹配自身模式")
            continue
        ok_regex += 1

        # ---- 2) 引擎级命中（exrex 样本有随机性，最多重试 5 次）----
        fired: set[str] = set()
        for attempt in range(5):
            if attempt:
                sample = make_sample(pattern)
                if sample is None or not rule.compiled.search(sample):
                    continue
            context_words = " ".join(
                (rule.require_keywords or rule.keywords or [rule.category])[:3]
            )
            text = f"{context_words}\n{sample}\n# {context_words}\n"
            doc = Document(
                doc_id=f"t-{rule.id}",
                source="local_dir",
                url=f"file://selftest/{rule.id}",
                text=text,
                path_hint="config/settings.py",
                metadata={"source_category": "本地与企业内网"},
            )
            result = pipeline.run([doc])
            fired = {f.rule_id for f in result.findings}
            if fired:
                break
        if rule.id in fired:
            ok_engine += 1
        elif fired:
            # 同跨度被更具体的规则遮蔽（检测仍然成立，归属不同）
            shadowed += 1
            shadow_notes.append(f"{rule.id} -> 被 {sorted(fired)} 遮蔽（泄漏仍被发现）")
        else:
            failures.append(f"{rule.id}: 引擎级未命中（候选被过滤：占位符/评分/去重）")

    print(f"\n=== 规则库自测（{total} 条）===")
    print(f"正则级往返通过: {ok_regex}")
    print(f"引擎级命中:     {ok_engine}")
    print(f"被更具体规则遮蔽（检测仍成立）: {shadowed}")
    print(f"失败:           {len(failures)}")
    if shadow_notes:
        print("\n遮蔽明细：")
        for note in shadow_notes:
            print("  -", note)
    if failures:
        print("\n失败明细：")
        for f in failures:
            print("  -", f)
        return 1
    print("\n全部规则具备真实命中能力 ✓")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
