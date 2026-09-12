"""存储层：SQLite 落盘与增量游标管理。

两点设计约束：

1. **不存明文**。凭据仅以掩码（`AKIA****1234`）与 HMAC 指纹落盘。
   平台自身绝不能成为新的泄露源，这是防御性工具的底线。
2. **默认 SQLite**，零外部依赖，评审现场 `git clone` 后即可运行；
   生产环境可平滑切换到 PostgreSQL（SQL 兼容，仅需替换连接串）。
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from .models import utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    stats_json    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    fingerprint     TEXT PRIMARY KEY,
    masked          TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    rule_name       TEXT NOT NULL,
    category        TEXT,
    kind            TEXT,
    severity        TEXT,
    confidence      REAL,
    validated       INTEGER,
    validation_note TEXT,
    detector        TEXT,
    first_seen      TEXT,
    first_published TEXT,
    multi_channel   INTEGER DEFAULT 0,
    exposure_count  INTEGER DEFAULT 0,
    channel_count   INTEGER DEFAULT 0,
    sources_json    TEXT,
    feature_vector_json TEXT,
    updated_at      TEXT
);

CREATE TABLE IF NOT EXISTS exposures (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint   TEXT NOT NULL,
    source        TEXT,
    url           TEXT,
    path          TEXT,
    line          INTEGER,
    snippet       TEXT,
    severity      TEXT,
    detector      TEXT,
    published_at  TEXT,
    discovered_at TEXT,
    UNIQUE(fingerprint, url, path, line)
);

CREATE TABLE IF NOT EXISTS attributions (
    fingerprint     TEXT PRIMARY KEY,
    platform        TEXT,
    owner           TEXT,
    project         TEXT,
    org_name        TEXT,
    org_type        TEXT,
    domain          TEXT,
    confidence      REAL,
    disclosure_hint TEXT,
    notes_json      TEXT
);

CREATE TABLE IF NOT EXISTS credential_pairs (
    pair_type    TEXT NOT NULL,
    scope        TEXT NOT NULL,
    scope_key    TEXT NOT NULL,
    label        TEXT,
    severity     TEXT,
    members_json TEXT,
    masked_json  TEXT,
    location     TEXT,
    impact       TEXT,
    confidence   REAL,
    updated_at   TEXT,
    PRIMARY KEY (pair_type, scope, scope_key)
);

CREATE TABLE IF NOT EXISTS feedback (
    fingerprint         TEXT PRIMARY KEY,
    label               INTEGER NOT NULL,
    note                TEXT,
    rule_id             TEXT,
    kind                TEXT,
    feature_vector_json TEXT,
    labeled_at          TEXT
);

CREATE TABLE IF NOT EXISTS cursors (
    source     TEXT PRIMARY KEY,
    cursor_json TEXT NOT NULL,
    updated_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_credentials_severity ON credentials(severity);
CREATE INDEX IF NOT EXISTS idx_exposures_fp ON exposures(fingerprint);
CREATE INDEX IF NOT EXISTS idx_exposures_source ON exposures(source);
CREATE INDEX IF NOT EXISTS idx_pairs_type ON credential_pairs(pair_type);
"""


class Storage:
    """SQLite 存储。线程内复用连接，跨线程各自新建。"""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self.init_schema()

    def init_schema(self) -> None:
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """轻量迁移：为已存在的旧库补充新增列。

        用 ALTER TABLE 而不是要求用户删库重建——扫描数据积累不易，
        不能因为一次版本升级就全部作废。
        """
        migrations = (
            ("credentials", "feature_vector_json", "TEXT"),
        )
        for table, column, coltype in migrations:
            try:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
            except sqlite3.OperationalError:
                pass  # 列已存在

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def close(self) -> None:
        self._conn.close()

    # ------------------------------------------------------------------ 扫描

    def save_scan(self, stats: dict[str, Any]) -> int:
        with self.transaction() as conn:
            cur = conn.execute(
                "INSERT INTO scans (started_at, finished_at, stats_json) VALUES (?, ?, ?)",
                (
                    str(stats.get("started_at")),
                    str(stats.get("finished_at")),
                    json.dumps(stats, ensure_ascii=False),
                ),
            )
            return int(cur.lastrowid or 0)

    # ------------------------------------------------------------ 凭据与证据

    def upsert_clusters(
        self,
        clusters: Iterable[Any],
        attributions: dict[str, Any] | None = None,
        scan_id: int | None = None,
    ) -> int:
        attributions = attributions or {}
        count = 0
        now = utcnow().isoformat()
        with self.transaction() as conn:
            for cluster in clusters:
                record = cluster.to_record()
                conn.execute(
                    """
                    INSERT INTO credentials (
                        fingerprint, masked, rule_id, rule_name, category, kind,
                        severity, confidence, validated, validation_note, detector,
                        first_seen, first_published, multi_channel, exposure_count,
                        channel_count, sources_json, feature_vector_json, updated_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(fingerprint) DO UPDATE SET
                        severity=excluded.severity,
                        confidence=excluded.confidence,
                        validated=COALESCE(excluded.validated, credentials.validated),
                        validation_note=CASE WHEN excluded.validation_note != ''
                                             THEN excluded.validation_note
                                             ELSE credentials.validation_note END,
                        first_published=COALESCE(credentials.first_published,
                                                 excluded.first_published),
                        multi_channel=excluded.multi_channel,
                        exposure_count=credentials.exposure_count + excluded.exposure_count,
                        channel_count=MAX(credentials.channel_count, excluded.channel_count),
                        sources_json=excluded.sources_json,
                        updated_at=excluded.updated_at
                    """,
                    (
                        record["fingerprint"],
                        record["masked"],
                        record.get("rule_id") or record["rule_name"],
                        record["rule_name"],
                        record["category"],
                        record["kind"],
                        record["severity"],
                        record["confidence"],
                        None if record["validated"] is None else int(record["validated"]),
                        record["validation_note"] or "",
                        record["detector"],
                        record["first_seen"],
                        record["first_published"],
                        int(record["multi_channel"]),
                        record["exposure_count"],
                        record["channel_count"],
                        json.dumps(record["sources"], ensure_ascii=False),
                        json.dumps(record.get("feature_vector") or {}, ensure_ascii=False),
                        now,
                    ),
                )
                for exposure in record["exposures"]:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO exposures (
                            fingerprint, source, url, path, line, snippet,
                            severity, detector, published_at, discovered_at
                        ) VALUES (?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            record["fingerprint"],
                            exposure.get("source"),
                            exposure.get("url"),
                            exposure.get("path"),
                            exposure.get("line"),
                            exposure.get("snippet"),
                            exposure.get("severity"),
                            exposure.get("detector"),
                            exposure.get("published_at"),
                            exposure.get("discovered_at"),
                        ),
                    )
                attr = attributions.get(record["fingerprint"])
                if attr is not None:
                    conn.execute(
                        """
                        INSERT INTO attributions (
                            fingerprint, platform, owner, project, org_name, org_type,
                            domain, confidence, disclosure_hint, notes_json
                        ) VALUES (?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(fingerprint) DO UPDATE SET
                            platform=excluded.platform, owner=excluded.owner,
                            project=excluded.project, org_name=excluded.org_name,
                            org_type=excluded.org_type, domain=excluded.domain,
                            confidence=excluded.confidence,
                            disclosure_hint=excluded.disclosure_hint,
                            notes_json=excluded.notes_json
                        """,
                        (
                            record["fingerprint"],
                            attr.platform,
                            attr.owner,
                            attr.project,
                            attr.org_name,
                            attr.org_type,
                            attr.domain,
                            attr.confidence,
                            attr.disclosure_hint,
                            json.dumps(attr.notes, ensure_ascii=False),
                        ),
                    )
                count += 1
        return count

    # ------------------------------------------------------------------ 凭据对

    def upsert_pairs(self, pairs: Iterable[Any]) -> int:
        """写入凭据对关联结果（组合风险）。"""
        now = utcnow().isoformat()
        count = 0
        with self.transaction() as conn:
            for pair in pairs:
                conn.execute(
                    """
                    INSERT INTO credential_pairs (
                        pair_type, scope, scope_key, label, severity,
                        members_json, masked_json, location, impact, confidence, updated_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(pair_type, scope, scope_key) DO UPDATE SET
                        label=excluded.label, severity=excluded.severity,
                        members_json=excluded.members_json,
                        masked_json=excluded.masked_json,
                        location=excluded.location, impact=excluded.impact,
                        confidence=excluded.confidence, updated_at=excluded.updated_at
                    """,
                    (
                        pair.spec_key,
                        pair.scope,
                        pair.scope_key,
                        pair.label,
                        pair.severity,
                        json.dumps(pair.members, ensure_ascii=False),
                        json.dumps(pair.masked_values, ensure_ascii=False),
                        pair.location,
                        pair.impact,
                        pair.confidence,
                        now,
                    ),
                )
                count += 1
        return count

    def pairs(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM credential_pairs "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 ELSE 3 END, confidence DESC"
        ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            try:
                item["members"] = json.loads(item.pop("members_json") or "[]")
                item["masked_values"] = json.loads(item.pop("masked_json") or "[]")
            except (ValueError, TypeError):
                item["members"] = []
                item["masked_values"] = []
            out.append(item)
        return out

    # ------------------------------------------------------------------ 反馈

    def record_feedback(
        self,
        fingerprint: str,
        label: int,
        *,
        note: str = "",
        rule_id: str = "",
        kind: str = "",
        feature_vector: dict[str, float] | None = None,
    ) -> None:
        """记录人工标注：1 = 确认为真实泄露，0 = 误报。"""
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO feedback (
                    fingerprint, label, note, rule_id, kind,
                    feature_vector_json, labeled_at
                ) VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    label=excluded.label, note=excluded.note,
                    rule_id=excluded.rule_id, kind=excluded.kind,
                    feature_vector_json=excluded.feature_vector_json,
                    labeled_at=excluded.labeled_at
                """,
                (
                    fingerprint,
                    int(label),
                    note,
                    rule_id,
                    kind,
                    json.dumps(feature_vector or {}, ensure_ascii=False),
                    utcnow().isoformat(),
                ),
            )

    def feedback(self) -> list[dict]:
        return [
            dict(row)
            for row in self._conn.execute(
                "SELECT * FROM feedback ORDER BY labeled_at DESC"
            ).fetchall()
        ]

    def feedback_samples(self) -> list[tuple[dict[str, float], int]]:
        """返回 (特征向量, 标签) 列表，用于权重校准。"""
        samples: list[tuple[dict[str, float], int]] = []
        for row in self._conn.execute(
            "SELECT feature_vector_json, label FROM feedback WHERE feature_vector_json != '{}'"
        ).fetchall():
            try:
                vector = json.loads(row["feature_vector_json"] or "{}")
            except (ValueError, TypeError):
                continue
            if vector:
                samples.append((vector, int(row["label"])))
        return samples

    def false_positive_fingerprints(self) -> set[str]:
        """被标注为误报的指纹集合，用于后续扫描自动抑制。"""
        return {
            row["fingerprint"]
            for row in self._conn.execute(
                "SELECT fingerprint FROM feedback WHERE label = 0"
            ).fetchall()
        }

    def confirmed_fingerprints(self) -> set[str]:
        return {
            row["fingerprint"]
            for row in self._conn.execute(
                "SELECT fingerprint FROM feedback WHERE label = 1"
            ).fetchall()
        }

    def feedback_summary(self) -> dict[str, Any]:
        rows = self.feedback()
        return {
            "total": len(rows),
            "confirmed": sum(1 for r in rows if r["label"] == 1),
            "false_positives": sum(1 for r in rows if r["label"] == 0),
            "latest": rows[0]["labeled_at"] if rows else None,
        }

    # ------------------------------------------------------------------ 游标

    def get_cursor(self, source: str) -> dict[str, Any]:
        row = self._conn.execute(
            "SELECT cursor_json FROM cursors WHERE source = ?", (source,)
        ).fetchone()
        if not row:
            return {}
        try:
            return json.loads(row["cursor_json"])
        except (ValueError, TypeError):
            return {}

    def set_cursor(self, source: str, cursor: dict[str, Any]) -> None:
        merged = self.get_cursor(source)
        merged.update(cursor)
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO cursors (source, cursor_json, updated_at) VALUES (?,?,?)
                ON CONFLICT(source) DO UPDATE SET
                    cursor_json=excluded.cursor_json, updated_at=excluded.updated_at
                """,
                (source, json.dumps(merged, ensure_ascii=False), utcnow().isoformat()),
            )

    # ------------------------------------------------------------------ 查询

    def credentials(self, severity: str | None = None, limit: int | None = None) -> list[dict]:
        sql = "SELECT * FROM credentials"
        params: list[Any] = []
        if severity:
            sql += " WHERE severity = ?"
            params.append(severity)
        sql += (
            " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
            " WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,"
            " validated DESC, confidence DESC"
        )
        if limit:
            sql += f" LIMIT {int(limit)}"
        return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def exposures_for(self, fingerprint: str) -> list[dict]:
        return [
            dict(r)
            for r in self._conn.execute(
                "SELECT * FROM exposures WHERE fingerprint = ? ORDER BY discovered_at",
                (fingerprint,),
            ).fetchall()
        ]

    def attributions(self) -> dict[str, dict]:
        return {
            row["fingerprint"]: dict(row)
            for row in self._conn.execute("SELECT * FROM attributions").fetchall()
        }

    def summary(self) -> dict[str, Any]:
        conn = self._conn
        total = conn.execute("SELECT COUNT(*) AS n FROM credentials").fetchone()["n"]
        exposures = conn.execute("SELECT COUNT(*) AS n FROM exposures").fetchone()["n"]
        by_sev = {
            row["severity"]: row["n"]
            for row in conn.execute(
                "SELECT severity, COUNT(*) AS n FROM credentials GROUP BY severity"
            ).fetchall()
        }
        by_source = {
            row["source"]: row["n"]
            for row in conn.execute(
                "SELECT source, COUNT(*) AS n FROM exposures GROUP BY source ORDER BY n DESC"
            ).fetchall()
        }
        validated = conn.execute(
            "SELECT COUNT(*) AS n FROM credentials WHERE validated = 1"
        ).fetchone()["n"]
        multi = conn.execute(
            "SELECT COUNT(*) AS n FROM credentials WHERE multi_channel = 1"
        ).fetchone()["n"]
        scans = conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
        pairs = conn.execute("SELECT COUNT(*) AS n FROM credential_pairs").fetchone()["n"]
        return {
            "unique_credentials": total,
            "total_exposures": exposures,
            "validated": validated,
            "multi_channel": multi,
            "credential_pairs": pairs,
            "scans": scans,
            "by_severity": by_sev,
            "by_source": by_source,
        }

    def last_scan(self) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not row:
            return None
        try:
            data = json.loads(row["stats_json"])
        except (ValueError, TypeError):
            return None
        # 把记录编号一并带出，便于报告追溯
        data["scan_id"] = row["id"]
        return data

    def mttd_stats(self) -> dict[str, Any]:
        """计算发现延迟（MTTD）。"""
        rows = self._conn.execute(
            "SELECT first_published, first_seen FROM credentials "
            "WHERE first_published IS NOT NULL AND first_seen IS NOT NULL"
        ).fetchall()
        deltas: list[float] = []
        for row in rows:
            try:
                published = _parse(row["first_published"])
                seen = _parse(row["first_seen"])
            except ValueError:
                continue
            if published and seen:
                deltas.append(max((seen - published).total_seconds(), 0.0) / 3600.0)
        deltas.sort()
        if not deltas:
            return {"samples": 0}
        return {
            "samples": len(deltas),
            "min_hours": round(deltas[0], 4),
            "median_hours": round(deltas[len(deltas) // 2], 4),
            "max_hours": round(deltas[-1], 4),
            "mean_hours": round(sum(deltas) / len(deltas), 4),
        }


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
