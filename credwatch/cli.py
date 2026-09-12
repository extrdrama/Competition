"""命令行入口。

常用命令：
    python -m credwatch demo                  # 离线演示（扫描内置样本）
    python -m credwatch scan-local D:/code    # 扫描本地/内网目录
    python -m credwatch scan --source github  # 扫描指定在线渠道
    python -m credwatch scan --all            # 扫描全部已启用渠道
    python -m credwatch sources --health      # 查看渠道清单与可用性
    python -m credwatch rules                 # 查看规则库覆盖情况
    python -m credwatch report                # 用数据库现有数据出报告
    python -m credwatch watch --interval 600  # 常驻模式
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .config import PROJECT_ROOT, Settings, load_sources_config
from .detectors import RuleEngine
from .report import write_reports
from .scheduler import ScanEngine
from .sources import CATEGORY_ORDER, registry

try:  # rich 为可选依赖，缺失时降级为纯文本
    from rich.console import Console
    from rich.table import Table

    _console: "Console | None" = Console()
except Exception:  # noqa: BLE001
    _console = None


def _print(message: str = "") -> None:
    if _console is not None:
        _console.print(message)
    else:
        print(message)


def _table(title: str, columns: list[str], rows: list[list[str]]) -> None:
    if _console is not None:
        table = Table(title=title, show_lines=False, header_style="bold")
        for col in columns:
            table.add_column(col, overflow="fold")
        for row in rows:
            table.add_row(*[str(c) for c in row])
        _console.print(table)
        return
    print(f"\n== {title} ==")
    print(" | ".join(columns))
    for row in rows:
        print(" | ".join(str(c) for c in row))


# --------------------------------------------------------------------- 子命令


def cmd_sources(args: argparse.Namespace) -> int:
    settings = Settings.load()
    grouped = registry.by_category()
    order = [c for c in CATEGORY_ORDER if c in grouped] + [
        c for c in grouped if c not in CATEGORY_ORDER
    ]
    rows: list[list[str]] = []
    total = 0
    for category in order:
        for meta in grouped[category]:
            total += 1
            status = "-"
            if args.health:
                try:
                    adapter = registry.get(meta.name)(settings)
                    ok, detail = adapter.health_check()
                    adapter.close()
                    status = ("✅ " if ok else "⚠️ ") + detail
                except Exception as exc:  # noqa: BLE001
                    status = f"❌ {type(exc).__name__}"
            rows.append(
                [
                    meta.name,
                    meta.label,
                    category,
                    "需要令牌" if meta.requires_token else "无需令牌",
                    str(meta.rate_limit_per_minute),
                    status,
                ]
            )
    _table(
        f"支持的公开渠道（共 {total} 个）",
        ["渠道标识", "渠道名称", "类别", "令牌要求", "限速/分钟", "状态"],
        rows,
    )
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    settings = Settings.load()
    engine = RuleEngine.from_dir(settings.rules_dir)
    stats = engine.stats()
    _print(f"\n已加载检测规则：[bold]{stats['total_rules']}[/bold] 条")
    _table(
        "凭据大类覆盖",
        ["凭据大类", "规则数"],
        [[k, v] for k, v in stats["categories"].items()],
    )
    _table(
        "凭据类型覆盖",
        ["凭据类型", "规则数"],
        [[k, v] for k, v in stats["kinds"].items()],
    )
    _print(f"\n已注册只读验证器：{', '.join(stats['validators']) or '无'}")
    if args.verbose:
        _table(
            "规则明细",
            ["规则 ID", "名称", "类型", "风险", "验证器"],
            [
                [r.id, r.name, r.kind, r.severity, r.validator or "-"]
                for r in engine.rules
            ],
        )
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    settings = Settings.load()
    engine = ScanEngine(settings)
    names = args.source or None
    if args.all:
        names = None

    _print(f"\n开始扫描（渠道：{', '.join(names) if names else '全部已启用渠道'}）…")
    result = engine.run(
        names, full_rescan=args.full, max_documents=args.max_docs, workers=args.workers
    )
    _summarize(result)
    if not args.no_report:
        _emit_reports(engine, result, args.out)
    return 0


def cmd_scan_local(args: argparse.Namespace) -> int:
    settings = Settings.load()
    engine = ScanEngine(settings)
    paths = [str(Path(p).resolve()) for p in args.paths]
    for path in paths:
        if not Path(path).exists():
            _print(f"[yellow]路径不存在，已跳过：{path}[/yellow]")
    engine.sources_config = {
        "sources": {
            "local_dir": {
                "enabled": True,
                "paths": paths,
                "include_archives": not args.no_archives,
                "max_files": args.max_files,
            }
        }
    }
    _print(f"\n开始扫描本地目录：{', '.join(paths)}")
    result = engine.run(
        ["local_dir"], full_rescan=args.full, max_documents=args.max_docs, workers=1
    )
    _summarize(result)
    if not args.no_report:
        _emit_reports(engine, result, args.out)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """离线演示：三个渠道并行，验证跨渠道关联能力。

    样本目录里的凭据全部是伪造值；其中同一个令牌同时出现在
    代码样本与移动端产物中，用于演示"同一凭据跨渠道扩散"的关联效果。
    """
    settings = Settings.load()
    engine = ScanEngine(settings)
    demo_dir = PROJECT_ROOT / "demo" / "samples"
    artifacts_dir = demo_dir / "artifacts"
    if not demo_dir.exists():
        _print(f"[red]演示样本目录不存在：{demo_dir}[/red]")
        _print("请先执行：python scripts/make_demo_samples.py")
        return 1

    source_config: dict[str, dict] = {
        "local_dir": {
            "enabled": True,
            "paths": [str(demo_dir)],
            # 安装包与小程序包交由专用渠道处理，此处排除以免重复上报
            "exclude": ["artifacts/*"],
        },
    }
    enabled = ["local_dir"]
    apk = artifacts_dir / "demo-app.apk"
    if apk.exists():
        source_config["mobile_app"] = {"enabled": True, "artifacts": [str(apk)]}
        enabled.append("mobile_app")
    wxapkg = artifacts_dir / "demo-miniapp.wxapkg"
    if wxapkg.exists():
        source_config["mini_program"] = {"enabled": True, "packages": [str(wxapkg)]}
        enabled.append("mini_program")

    engine.sources_config = {"sources": source_config}
    _print(f"\n[bold]离线演示[/bold]：样本目录 {demo_dir}")
    _print(f"启用渠道：{', '.join(enabled)}")
    result = engine.run(enabled, full_rescan=True)
    _summarize(result)
    paths = _emit_reports(engine, result, args.out)
    _print("\n报告已生成：")
    for name, path in paths.items():
        _print(f"  - {name}: {path}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    settings = Settings.load()
    engine = ScanEngine(settings)
    summary = engine.storage.summary()
    if not summary.get("unique_credentials"):
        _print("数据库中暂无数据，请先执行 scan / demo 命令。")
        return 1
    from .dedup import CredentialCluster  # noqa: F401  仅用于类型说明

    result = _rebuild_result_from_storage(engine)
    paths = write_reports(result, engine.rule_engine, _out_dir(args.out))
    _print("报告已根据数据库现有数据重新生成：")
    for name, path in paths.items():
        _print(f"  - {name}: {path}")
    return 0


def cmd_lint_rules(args: argparse.Namespace) -> int:
    """规则库自检。"""
    from .rule_lint import format_report, lint_rules

    settings = Settings.load()
    report = lint_rules(settings.rules_dir)
    if args.json:
        import json

        _print(json.dumps(report.to_record(), ensure_ascii=False, indent=2))
    else:
        _print(format_report(report))
    return 0 if report.ok else 2


def cmd_new_source(args: argparse.Namespace) -> int:
    """生成新渠道骨架（扩展性的现场演示入口）。"""
    from .scaffold import create_source

    try:
        result = create_source(
            args.name,
            label=args.label or "",
            category=args.category,
            description=args.description or "（待补充）",
            requires_token=args.requires_token,
            rate_limit=args.rate_limit,
            homepage=args.homepage or "",
            force=args.force,
        )
    except (ValueError, FileExistsError) as exc:
        _print(f"[red]{exc}[/red]")
        return 1

    _print(f"[bold]已生成渠道骨架：{result.name}[/bold]")
    _table(
        "生成内容",
        ["项目", "结果"],
        [
            ["渠道模块", str(result.module_path)],
            ["渠道类名", f"{result.class_name}Source"],
            ["注册到 sources/__init__.py", "已更新" if result.init_updated else "已存在"],
            ["追加 config/sources.yaml", "已追加" if result.yaml_updated else "已存在"],
        ],
    )
    _print("\n后续步骤：")
    for step in result.next_steps():
        _print(f"  {step}")
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    """性能基准测试。"""
    from .benchmark import run_benchmark

    settings = Settings.load()
    engine = ScanEngine(settings)
    _print(f"\n[bold]性能基准测试[/bold]（语料 {args.documents} 份，固定随机种子，可复现）…")
    result = run_benchmark(
        engine.rule_engine,
        documents=args.documents,
        noise_ratio=args.noise_ratio,
        pipeline=engine._build_pipeline(),
    )
    _print("")
    if _console is not None:
        _console.print(result.render())
    else:
        print(result.render())

    if args.out:
        import json
        from pathlib import Path as _Path

        target = _Path(args.out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(result.to_record(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        _print(f"\n结果已写入：{target}")
    return 0


def cmd_feedback(args: argparse.Namespace) -> int:
    """标注发现的真伪（误报反馈闭环入口）。"""
    from .feedback import FeedbackLoop
    from .storage import Storage

    settings = Settings.load()
    storage = Storage(settings.db_path)
    loop = FeedbackLoop(settings, storage)

    if not args.fingerprint:
        stats = loop.stats()
        _table(
            "误报反馈现状",
            ["指标", "数值"],
            [
                ["已标注样本", stats["total"]],
                ["确认为真实泄露", stats["confirmed"]],
                ["标记为误报", stats["false_positives"]],
                ["已抑制指纹", stats["suppressed_fingerprints"]],
                ["权重是否已校准", "是" if stats["weights_calibrated"] else "否（仍用专家先验）"],
                ["校准使用样本数", stats["weights_samples"]],
            ],
        )
        _print("\n用法：")
        _print("  python -m credwatch feedback <指纹前缀> --false-positive   # 标记误报")
        _print("  python -m credwatch feedback <指纹前缀> --confirmed        # 确认真实泄露")
        _print("  python -m credwatch calibrate                             # 用标注样本校准权重")
        return 0

    outcome = loop.label(
        args.fingerprint,
        is_false_positive=not args.confirmed,
        note=args.note or "",
    )
    style = "green" if outcome.found else "yellow"
    _print(f"[{style}]{outcome.message}[/{style}]")
    if outcome.found:
        _print("\n提示：累计一定样本后可执行 `python -m credwatch calibrate` 校准评分权重。")
    return 0 if outcome.found else 1


def cmd_calibrate(args: argparse.Namespace) -> int:
    """用标注样本校准评分权重。"""
    from .feedback import FeedbackLoop
    from .storage import Storage

    settings = Settings.load()
    loop = FeedbackLoop(settings, Storage(settings.db_path))
    _print("\n正在用已标注样本校准评分权重…")
    report = loop.calibrate_weights(save=not args.dry_run)
    if report is None:
        stats = loop.stats()
        _print(
            f"[yellow]样本不足，保持专家先验。[/yellow]\n"
            f"  当前已标注 {stats['total']} 条（需要至少 8 条且有正负两类样本）。\n"
            "  可用 `python -m credwatch feedback <指纹> --false-positive` 补充标注。"
        )
        return 1

    _print(f"\n[bold]校准完成[/bold]：{report.summary()}")
    _table(
        "指标变化（先验 → 校准后）",
        ["指标", "先验", "校准后"],
        [
            ["准确率", f"{report.prior_accuracy:.3f}", f"{report.calibrated_accuracy:.3f}"],
            ["精确率", f"{report.prior_precision:.3f}", f"{report.calibrated_precision:.3f}"],
            ["召回率", f"{report.prior_recall:.3f}", f"{report.calibrated_recall:.3f}"],
        ],
    )
    _table(
        "变化最大的权重",
        ["特征", "先验", "校准后"],
        [[name, f"{a:+.3f}", f"{b:+.3f}"] for name, a, b in report.top_changes],
    )
    if args.dry_run:
        _print("[yellow]--dry-run：未写入权重文件[/yellow]")
    else:
        _print(f"\n权重已写入：{settings.scoring_weights_file}")
        _print("下次扫描将自动加载校准后的权重。")
    return 0


def cmd_induce_rule(args: argparse.Namespace) -> int:
    """从样本归纳候选规则。"""
    from .detectors import RuleEngine
    from .rule_induction import detect_conflicts, induce_from_file, induce_rule

    settings = Settings.load()
    samples: list[str] = []
    if args.from_file:
        from pathlib import Path as _P

        fp = _P(args.from_file)
        if not fp.exists():
            _print(f"[red]样本文件不存在：{fp}[/red]")
            return 1
        samples = [
            line.strip()
            for line in fp.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    else:
        samples = [s.strip() for s in (args.samples or "").split(",") if s.strip()]

    if len(samples) < 2:
        _print("[red]至少需要 2 个样本才能归纳规则[/red]")
        return 1

    draft = induce_rule(
        args.name or "induced",
        args.label or "自动归纳凭据",
        samples,
        kind=args.kind,
        severity=args.severity,
    )

    existing = {rule.id: rule.pattern for rule in RuleEngine.from_dir(settings.rules_dir).rules}
    draft.conflicts = detect_conflicts(draft, existing)

    _print("\n[bold]归纳结果[/bold]")
    _print(draft.to_yaml())
    _table(
        "归纳质量",
        ["项目", "结果"],
        [
            ["样本数", draft.sample_count],
            ["公共前缀", draft.prefix or "（无）"],
            ["长度区间", f"{draft.min_length} - {draft.max_length}"],
            ["字符集", draft.charset_label],
            ["熵区间", f"{draft.entropy_min:.2f} - {draft.entropy_max:.2f}"],
            ["质量评估", draft.quality_note],
        ],
    )
    if draft.conflicts:
        _print("\n[yellow]冲突检测：[/yellow]")
        for conflict in draft.conflicts:
            _print(f"  - {conflict}")
    else:
        _print("\n[green]冲突检测：与现有规则无明显重复[/green]")

    _print("\n提示：候选规则需人工审核后合并到 config/rules/ 目录，")
    _print("      审核通过后运行 `python -m credwatch lint-rules` 自检。")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """复核修复结果。"""
    from .feedback import FeedbackLoop
    from .storage import Storage

    settings = Settings.load()
    loop = FeedbackLoop(settings, Storage(settings.db_path))
    result = loop.verify_remediation(args.fingerprint or "")
    _print(f"\n[bold]修复复核[/bold]：{result['summary']}\n")
    if result["still_present"]:
        _table(
            "仍在暴露",
            ["指纹", "掩码值", "凭据类型", "暴露点"],
            [
                [r["fingerprint"], r["masked"], r["rule_name"], r["exposures"]]
                for r in result["still_present"][:20]
            ],
        )
    if result["resolved"]:
        _table(
            "已消除",
            ["指纹", "掩码值", "凭据类型"],
            [[r["fingerprint"], r["masked"], r["rule_name"]] for r in result["resolved"][:20]],
        )
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    settings = Settings.load()
    engine = ScanEngine(settings)
    _print(f"进入常驻扫描模式，间隔 {args.interval} 秒（Ctrl+C 退出）")
    engine.run_forever(interval_seconds=args.interval)
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    settings = Settings.load()
    settings.ensure_dirs()
    engine = ScanEngine(settings)
    stats = engine.rule_engine.stats()
    _print("[bold]凭迹 CredWatch 初始化完成[/bold]")
    _print(f"  数据库：{settings.db_path}")
    _print(f"  规则数：{stats['total_rules']}")
    _print(f"  渠道数：{len(registry.names())}")
    _print(f"  活性验证：{'已启用' if settings.enable_validation else '未启用（默认）'}")
    _print(f"  指纹盐值：{'已配置' if settings.hmac_salt else '未配置（使用内置默认值，建议修改）'}")
    sources_cfg = load_sources_config(settings.sources_file)
    _print(f"  渠道配置文件：{settings.sources_file}（{len(sources_cfg.get('sources', {}))} 项配置）")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    dashboard = PROJECT_ROOT / "credwatch" / "dashboard.py"
    if not dashboard.exists():
        _print("看板脚本不存在")
        return 1
    try:
        import streamlit  # noqa: F401
    except ImportError:
        _print("未安装 streamlit，请先执行：pip install streamlit")
        return 1
    import subprocess

    return subprocess.call(
        [sys.executable, "-m", "streamlit", "run", str(dashboard), "--server.port", str(args.port)]
    )


# --------------------------------------------------------------------- 工具


def _out_dir(value: str | None) -> Path:
    return Path(value).resolve() if value else PROJECT_ROOT / "output"


def _emit_reports(engine: ScanEngine, result, out: str | None) -> dict[str, Path]:
    paths = write_reports(result, engine.rule_engine, _out_dir(out))
    _print(f"\n报告已生成：{paths['markdown']}")
    return paths


def _summarize(result) -> None:
    stats = result.stats
    cred = result.credential_stats or {}
    pairs = list(getattr(getattr(result, "correlation", None), "pairs", []) or [])
    _print("")
    _table(
        "扫描概览",
        ["指标", "数值"],
        [
            ["文档数", stats.documents_scanned],
            ["扫描字节", f"{stats.bytes_scanned / 1024 / 1024:.2f} MB"],
            ["耗时", f"{stats.elapsed_seconds():.1f} s"],
            ["去重后唯一凭据", cred.get("unique_credentials", 0)],
            ["暴露位置总数", cred.get("total_exposures", 0)],
            ["跨渠道扩散", cred.get("multi_channel", 0)],
            ["组合风险（凭据对）", len(pairs)],
            ["活性验证通过", cred.get("validated", 0)],
        ],
    )
    if stats.stage_counts:
        _table(
            "收敛漏斗",
            ["阶段", "数量"],
            [[k, v] for k, v in sorted(stats.stage_counts.items())],
        )
    if pairs:
        _table(
            "组合风险：可拼出完整凭据的配对（危害高于任意单条）",
            ["风险", "凭据对类型", "范围", "涉及凭据（已脱敏）"],
            [
                [p.severity, p.label, p.scope, " + ".join(p.masked_values[:4])]
                for p in pairs[:10]
            ],
        )
    if result.clusters:
        rows = []
        for cluster in result.clusters[:15]:
            attr = result.attributions.get(cluster.fingerprint)
            rows.append(
                [
                    cluster.masked,
                    cluster.rule_name,
                    cluster.severity,
                    f"{cluster.confidence:.2f}",
                    "有效" if cluster.validated is True else "—",
                    "是" if getattr(cluster, "pairs", None) else "—",
                    cluster.exposure_count,
                    attr.display if attr else "-",
                ]
            )
        _table(
            "高优先级发现（Top 15，凭据已脱敏）",
            ["掩码值", "类型", "风险", "概率", "验活", "成对", "暴露点", "归属主体"],
            rows,
        )
    if result.sources:
        _table(
            "渠道执行情况",
            ["渠道", "文档数", "命中数", "耗时(s)", "状态"],
            [
                [
                    p.name,
                    p.documents,
                    p.findings,
                    f"{p.duration_seconds:.1f}",
                    "正常" if not p.error else f"失败：{p.error[:40]}",
                ]
                for p in result.sources
            ],
        )


def _rebuild_result_from_storage(engine: ScanEngine):
    """从数据库重建一个轻量结果对象，供 `report` 子命令使用。"""
    from .dedup import CredentialCluster
    from .models import ScanStats, utcnow
    from .scheduler import ScanResult

    clusters: list[CredentialCluster] = []
    for row in engine.storage.credentials():
        cluster = CredentialCluster(
            fingerprint=row["fingerprint"],
            masked=row["masked"],
            rule_id=row.get("rule_id") or "",
            rule_name=row["rule_name"],
            category=row["category"] or "",
            kind=row["kind"] or "",
            severity=row["severity"] or "medium",
            confidence=row["confidence"] or 0.0,
            validated=None if row["validated"] is None else bool(row["validated"]),
            validation_note=row["validation_note"] or "",
            detector=row["detector"] or "",
            exposures=engine.storage.exposures_for(row["fingerprint"]),
            sources=set(__import__("json").loads(row["sources_json"] or "[]")),
            multi_channel=bool(row["multi_channel"]),
        )
        cluster.first_published = _parse_dt(row["first_published"])
        cluster.first_seen = _parse_dt(row["first_seen"])
        clusters.append(cluster)

    stats_record = engine.storage.last_scan() or {}
    stats = ScanStats()
    stats.documents_scanned = stats_record.get("documents_scanned", 0)
    stats.bytes_scanned = stats_record.get("bytes_scanned", 0)
    stats.stage_counts = stats_record.get("stage_counts", {})
    # 时间字段要一并还原，否则报告头部会显示为空
    stats.started_at = _parse_dt(stats_record.get("started_at")) or stats.started_at
    stats.finished_at = _parse_dt(stats_record.get("finished_at"))
    latest_scan_id = stats_record.get("scan_id")

    attributions = {}
    from .attribution import Attribution

    for fp, row in engine.storage.attributions().items():
        import json

        attributions[fp] = Attribution(
            platform=row.get("platform") or "",
            owner=row.get("owner") or "",
            project=row.get("project") or "",
            org_name=row.get("org_name") or "",
            org_type=row.get("org_type") or "",
            domain=row.get("domain") or "",
            confidence=row.get("confidence") or 0.0,
            disclosure_hint=row.get("disclosure_hint") or "",
            notes=json.loads(row.get("notes_json") or "[]"),
        )

    return ScanResult(
        stats=stats,
        sources=[],
        clusters=clusters,
        attributions=attributions,
        credential_stats=_recompute_stats(clusters),
        mttd=engine.storage.mttd_stats(),
        storage_summary=engine.storage.summary(),
        scan_id=latest_scan_id,
    )


def _recompute_stats(clusters) -> dict:
    from collections import defaultdict

    by_severity: dict[str, int] = defaultdict(int)
    by_category: dict[str, int] = defaultdict(int)
    by_kind: dict[str, int] = defaultdict(int)
    by_source: dict[str, int] = defaultdict(int)
    for cluster in clusters:
        by_severity[cluster.severity] += 1
        by_category[cluster.category] += 1
        by_kind[cluster.kind or "未分类"] += 1
        for source in cluster.sources:
            by_source[source] += 1
    return {
        "unique_credentials": len(clusters),
        "total_exposures": sum(c.exposure_count for c in clusters),
        "multi_channel": sum(1 for c in clusters if c.multi_channel),
        "validated": sum(1 for c in clusters if c.validated is True),
        "by_severity": dict(by_severity),
        "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
        "by_kind": dict(sorted(by_kind.items(), key=lambda kv: -kv[1])),
        "by_source": dict(sorted(by_source.items(), key=lambda kv: -kv[1])),
    }


def _parse_dt(value):
    from datetime import datetime, timezone

    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------- 解析器


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="credwatch",
        description="凭迹 CredWatch —— 云上凭据泄露自动化检测平台（防御性安全研究工具）",
    )
    parser.add_argument("--version", action="version", version=f"CredWatch {__version__}")
    parser.add_argument("--verbose", action="store_true", help="输出调试日志")
    sub = parser.add_subparsers(dest="command", required=True)

    p_sources = sub.add_parser("sources", help="列出支持的公开渠道")
    p_sources.add_argument("--health", action="store_true", help="执行可用性自检")
    p_sources.set_defaults(func=cmd_sources)

    p_rules = sub.add_parser("rules", help="查看检测规则库覆盖情况")
    p_rules.add_argument("-v", "--verbose", action="store_true", help="列出全部规则明细")
    p_rules.set_defaults(func=cmd_rules)

    p_scan = sub.add_parser("scan", help="扫描在线渠道")
    p_scan.add_argument("--source", action="append", help="指定渠道，可重复指定")
    p_scan.add_argument("--all", action="store_true", help="扫描全部已启用渠道（默认行为）")
    p_scan.add_argument("--full", action="store_true", help="忽略游标做全量重扫")
    p_scan.add_argument("--max-docs", type=int, default=None, help="单渠道最多处理文档数")
    p_scan.add_argument("--out", default=None, help="报告输出目录")
    p_scan.add_argument("--no-report", action="store_true", help="只扫描不出报告")
    p_scan.add_argument("--workers", type=int, default=1, help="渠道并发数（默认 1，顺序执行以保证可复现）")
    p_scan.set_defaults(func=cmd_scan)

    p_local = sub.add_parser("scan-local", help="扫描本地/内网目录")
    p_local.add_argument("paths", nargs="+", help="一个或多个目录")
    p_local.add_argument("--full", action="store_true", help="忽略游标做全量重扫")
    p_local.add_argument("--max-docs", type=int, default=None)
    p_local.add_argument("--max-files", type=int, default=20000)
    p_local.add_argument("--no-archives", action="store_true", help="不展开 zip/tar 等归档")
    p_local.add_argument("--out", default=None)
    p_local.add_argument("--no-report", action="store_true")
    p_local.add_argument("--workers", type=int, default=1, help="渠道并发数")
    p_local.set_defaults(func=cmd_scan_local)

    p_demo = sub.add_parser("demo", help="离线演示：扫描内置样本并生成报告")
    p_demo.add_argument("--out", default=None)
    p_demo.set_defaults(func=cmd_demo)

    p_report = sub.add_parser("report", help="用数据库现有数据重新生成报告")
    p_report.add_argument("--out", default=None)
    p_report.set_defaults(func=cmd_report)

    p_watch = sub.add_parser("watch", help="常驻扫描模式")
    p_watch.add_argument("--interval", type=int, default=600, help="扫描间隔（秒）")
    p_watch.set_defaults(func=cmd_watch)

    p_init = sub.add_parser("init", help="初始化数据库并检查配置")
    p_init.set_defaults(func=cmd_init)

    p_serve = sub.add_parser("serve", help="启动可视化看板")
    p_serve.add_argument("--port", type=int, default=8501)
    p_serve.set_defaults(func=cmd_serve)

    p_lint = sub.add_parser("lint-rules", help="规则库自检（正则、ID、验证器、特异性）")
    p_lint.add_argument("--json", action="store_true", help="以 JSON 输出")
    p_lint.set_defaults(func=cmd_lint_rules)

    p_new = sub.add_parser("new-source", help="生成新渠道骨架（扩展性演示）")
    p_new.add_argument("name", help="渠道标识，如 mysite")
    p_new.add_argument("--label", default="", help="渠道中文名称")
    p_new.add_argument("--category", default="内容共享平台", help="渠道类别")
    p_new.add_argument("--description", default="", help="渠道说明")
    p_new.add_argument("--requires-token", action="store_true", help="该渠道是否需要令牌")
    p_new.add_argument("--rate-limit", type=int, default=20, help="每分钟调用上限")
    p_new.add_argument("--homepage", default="", help="平台主页")
    p_new.add_argument("--force", action="store_true", help="覆盖已存在的模块")
    p_new.set_defaults(func=cmd_new_source)

    p_bench = sub.add_parser("bench", help="性能基准测试（吞吐量 / 阶段耗时 / 规则热点）")
    p_bench.add_argument("--documents", type=int, default=500, help="合成语料文档数")
    p_bench.add_argument("--noise-ratio", type=float, default=0.25, help="无凭据文档占比")
    p_bench.add_argument("--out", default=None, help="结果输出 JSON 路径")
    p_bench.set_defaults(func=cmd_bench)

    p_fb = sub.add_parser("feedback", help="标注发现为误报/确认（误报反馈闭环）")
    p_fb.add_argument("fingerprint", nargs="?", default="", help="凭据指纹前缀（报告中的前 16 位）")
    p_fb.add_argument("--false-positive", action="store_true", help="标记为误报")
    p_fb.add_argument("--confirmed", action="store_true", help="确认为真实泄露")
    p_fb.add_argument("--note", default="", help="备注")
    p_fb.set_defaults(func=cmd_feedback)

    p_cal = sub.add_parser("calibrate", help="用标注样本校准评分权重")
    p_cal.add_argument("--dry-run", action="store_true", help="只计算不写入")
    p_cal.set_defaults(func=cmd_calibrate)

    p_verify = sub.add_parser("verify", help="复核修复结果（重扫后确认是否已消除）")
    p_verify.add_argument("fingerprint", nargs="?", default="", help="留空则复核全部已确认凭据")
    p_verify.set_defaults(func=cmd_verify)

    p_induce = sub.add_parser("induce-rule", help="从样本归纳候选规则（应对新平台格式变化）")
    p_induce.add_argument("--from-file", default="", help="样本文件路径（每行一个样本）")
    p_induce.add_argument("--samples", default="", help="逗号分隔的样本，如 sk-xxx,sk-yyy")
    p_induce.add_argument("--name", default="", help="规则 ID，如 induced-mysite")
    p_induce.add_argument("--label", default="", help="规则中文名")
    p_induce.add_argument("--kind", default="自动归纳凭据", help="凭据类型")
    p_induce.add_argument("--severity", default="high", help="风险等级")
    p_induce.set_defaults(func=cmd_induce_rule)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        _print("\n已中断。")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
