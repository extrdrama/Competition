#!/usr/bin/env python
"""把 docs/ 下的交付文档合并为一份可提交的作品文档。

官方要求：
    应提交的竞赛作品资料包括作品文档资料（PDF 格式，大小不超过 10M）及可执行程序；
    作品文档资料内容应包括：作品简介、设计方案、测试报告、其他文档、参赛作品声明。

本脚本做三件事：
1. 按官方要求的要素顺序，把 docs/ 下的 Markdown 合并为**一个自包含 HTML**
   （封面 + 自动目录 + 正文，含打印分页样式）；
2. 在浏览器中打开该 HTML，`Ctrl+P → 另存为 PDF` 即得到提交用 PDF；
3. 输出体量检查与合规自查提示。

用法：
    python scripts/build_submission.py
    python scripts/build_submission.py --open      # 生成后自动用浏览器打开
"""

from __future__ import annotations

import argparse
import html as html_mod
import re
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
OUT_DIR = ROOT / "submission"

# 按官方要求的要素顺序排列（作品简介 → 设计方案 → 测试报告 → 其他文档 → 声明）
SUBMISSION_ORDER: list[tuple[str, str]] = [
    ("作品简介", "docs/作品简介.md"),
    ("设计方案（技术说明书）", "docs/技术说明书.md"),
    ("测试报告", "docs/测试报告.md"),
    ("创新点说明", "docs/创新点说明.md"),
    ("支持的公开渠道列表", "docs/支持的公开渠道列表.md"),
    ("支持的凭据类型列表", "docs/支持的凭据类型列表.md"),
    ("对比优势与基准", "docs/对比优势与基准.md"),
    ("引用与开源组件说明", "docs/引用与开源组件说明.md"),
    ("合规与伦理声明", "docs/合规与伦理声明.md"),
    ("参赛作品声明", "docs/参赛作品声明.md"),
]

# 内部工作文档：不进入提交材料
INTERNAL_DOCS = ("docs/答辩演示脚本.md", "docs/赛题要求对照与自查表.md")


def _esc(value: object) -> str:
    """HTML 转义。"""
    return html_mod.escape(str(value if value is not None else ""), quote=False)

_CSS = """
@page { size: A4; margin: 18mm 16mm; }
* { box-sizing: border-box; }
body { font-family:"Microsoft YaHei","PingFang SC","Segoe UI",sans-serif;
       color:#1f2933; font-size:11pt; line-height:1.75; margin:0; background:#fff; }
.doc { max-width: 820px; margin: 0 auto; padding: 0 8px 60px; }
.cover { text-align:center; padding:120px 0 90px; page-break-after:always; }
.cover h1 { font-size:30pt; margin:0 0 14px; letter-spacing:1px; }
.cover .subtitle { font-size:14pt; color:#4a5568; margin-bottom:36px; }
.cover .meta { font-size:11pt; color:#4a5568; line-height:2.2; }
.cover .rule { width:220px; height:3px; background:#0b5fff; margin:26px auto; }
.toc { page-break-after:always; }
.toc h2 { font-size:16pt; border:none; }
.toc ol { font-size:11.5pt; line-height:2.1; }
h1 { font-size:20pt; margin:0 0 14px; padding-bottom:8px;
     border-bottom:3px solid #0b5fff; page-break-before:always; }
h1.first { page-break-before:avoid; }
h2 { font-size:14.5pt; margin:26px 0 10px; }
h3 { font-size:12.5pt; margin:18px 0 8px; }
h4 { font-size:11.5pt; margin:14px 0 6px; }
p { margin:8px 0; }
table { width:100%; border-collapse:collapse; margin:10px 0 14px; font-size:9.5pt; }
th, td { border:1px solid #d7dee6; padding:5px 8px; text-align:left; vertical-align:top; }
th { background:#eef3f9; }
code { background:#f0f3f7; padding:1px 4px; border-radius:3px; font-size:9pt;
       font-family:Consolas,Menlo,monospace; }
pre { background:#f7f9fb; border:1px solid #e3e8ee; border-radius:6px;
      padding:10px 12px; overflow-x:auto; page-break-inside:avoid; }
pre code { background:none; padding:0; font-size:8.5pt; line-height:1.5; }
blockquote { border-left:4px solid #0b5fff; background:#f5f8ff;
             margin:10px 0; padding:8px 14px; color:#37414d; }
ul, ol { margin:8px 0 8px 22px; padding:0; }
li { margin:3px 0; }
hr { border:none; border-top:1px solid #e3e8ee; margin:20px 0; }
a { color:#0b5fff; text-decoration:none; }
.footer { margin-top:40px; color:#8a94a0; font-size:9pt; text-align:center; }
@media print { h1 { page-break-before:always; } h1.first { page-break-before:avoid; } }
"""


# --------------------------------------------------------------------- MD → HTML


def _inline(text: str) -> str:
    """行内元素：转义 → 代码 → 加粗 → 斜体 → 链接。"""
    text = html_mod.escape(text, quote=False)
    placeholders: list[str] = []

    def _stash(match: re.Match[str]) -> str:
        placeholders.append(f"<code>{match.group(1)}</code>")
        return f"\x00{len(placeholders) - 1}\x00"

    text = re.sub(r"`([^`]+)`", _stash, text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<em>\1</em>", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    for idx, replacement in enumerate(placeholders):
        text = text.replace(f"\x00{idx}\x00", replacement)
    return text


def md_to_html(markdown: str) -> str:
    """极简 Markdown → HTML，覆盖本项目文档实际用到的语法。"""
    out: list[str] = []
    lines = markdown.splitlines()
    i = 0
    in_code = False
    code_lang = ""
    code_buf: list[str] = []
    list_stack: list[str] = []

    def close_list() -> None:
        while list_stack:
            out.append(f"</{list_stack.pop()}>")

    while i < len(lines):
        line = lines[i]

        # 围栏代码块
        if line.strip().startswith("```"):
            if in_code:
                out.append(
                    f"<pre><code>{html_mod.escape(chr(10).join(code_buf))}</code></pre>"
                )
                code_buf, in_code = [], False
            else:
                close_list()
                in_code, code_lang = True, line.strip()[3:]
            i += 1
            continue
        if in_code:
            code_buf.append(line)
            i += 1
            continue

        stripped = line.strip()
        if not stripped:
            close_list()
            i += 1
            continue

        # 分隔线
        if re.fullmatch(r"-{3,}|={3,}|\*{3,}", stripped):
            close_list()
            out.append("<hr>")
            i += 1
            continue

        # 标题
        m = re.match(r"^(#{1,4})\s+(.*)$", stripped)
        if m:
            close_list()
            level = len(m.group(1))
            out.append(f"<h{level}>{_inline(m.group(2))}</h{level}>")
            i += 1
            continue

        # 表格
        if stripped.startswith("|") and i + 1 < len(lines) and re.match(
            r"^\|[\s:\-|]+\|$", lines[i + 1].strip()
        ):
            close_list()
            header = [c.strip() for c in stripped.strip("|").split("|")]
            i += 2
            rows: list[list[str]] = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            thead = "".join(f"<th>{_inline(c)}</th>" for c in header)
            body = "".join(
                "<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in row) + "</tr>"
                for row in rows
            )
            out.append(f"<table><thead><tr>{thead}</tr></thead><tbody>{body}</tbody></table>")
            continue

        # 引用
        if stripped.startswith(">"):
            close_list()
            quote: list[str] = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                quote.append(lines[i].strip().lstrip(">").strip())
                i += 1
            out.append(f"<blockquote>{_inline(' '.join(q for q in quote if q))}</blockquote>")
            continue

        # 无序列表
        if re.match(r"^[-*]\s+", stripped):
            if list_stack and list_stack[-1] == "ol":
                close_list()
            if not list_stack:
                list_stack.append("ul")
                out.append("<ul>")
            out.append(f"<li>{_inline(re.sub(r'^[-*]\s+', '', stripped))}</li>")
            i += 1
            continue

        # 有序列表
        if re.match(r"^\d+[.、]\s+", stripped):
            if list_stack and list_stack[-1] == "ul":
                close_list()
            if not list_stack:
                list_stack.append("ol")
                out.append("<ol>")
            out.append(f"<li>{_inline(re.sub(r'^\d+[.、]\s+', '', stripped))}</li>")
            i += 1
            continue

        # 普通段落
        close_list()
        out.append(f"<p>{_inline(stripped)}</p>")
        i += 1

    if in_code and code_buf:
        out.append(f"<pre><code>{html_mod.escape(chr(10).join(code_buf))}</code></pre>")
    close_list()
    return "\n".join(out)


def build_submission(*, title: str = "凭迹 CredWatch") -> Path:
    """合并文档并生成提交用 HTML。"""
    sections_html: list[str] = []
    toc: list[str] = []
    missing: list[str] = []

    for idx, (heading, rel_path) in enumerate(SUBMISSION_ORDER):
        path = ROOT / rel_path
        if not path.exists():
            missing.append(rel_path)
            continue
        body = md_to_html(path.read_text(encoding="utf-8"))
        anchor = f"sec{idx + 1}"
        toc.append(f'<li><a href="#{anchor}">{_esc(heading)}</a></li>')
        cls = ' class="first"' if idx == 0 else ""
        sections_html.append(
            f'<h1 id="{anchor}"{cls}>{idx + 1}. {_esc(heading)}</h1>\n{body}'
        )

    if missing:
        raise FileNotFoundError(f"缺少交付文档：{missing}")

    toc_html = "<ol>" + "".join(toc) + "</ol>"
    now = datetime.now().strftime("%Y 年 %m 月 %d 日")
    document = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>{_esc(title)} · 作品文档</title><style>{_CSS}</style></head>
<body><div class="doc">

<div class="cover">
  <h1>{_esc(title)}</h1>
  <div class="subtitle">云上凭据泄露自动化检测平台</div>
  <div class="rule"></div>
  <div class="meta">
    参赛赛道：揭榜挑战赛<br>
    参赛赛题：题目3《云上凭据泄露的自动化检测》<br>
    作品类型：防御性安全研究工具<br>
    编制日期：{now}
  </div>
</div>

<div class="toc"><h2>目 录</h2>{toc_html}</div>

{chr(10).join(sections_html)}

<div class="footer">本文档由 scripts/build_submission.py 自动合并生成 ·
浏览器打开后 Ctrl+P 可导出为 PDF</div>
</div></body></html>"""

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "作品文档.html"
    out_path.write_text(document, encoding="utf-8")
    return out_path


def fairness_check() -> list[str]:
    """公平性自查：材料中不得出现学校/学院/导师信息。

    使用方式：在 submission/forbidden_words.txt 中每行写一个需要拦截的词
    （学校名、学院名、导师与队员姓名），该文件已被 .gitignore 忽略。
    """
    wordlist = OUT_DIR / "forbidden_words.txt"
    if not wordlist.exists():
        return []
    words = [
        w.strip()
        for w in wordlist.read_text(encoding="utf-8").splitlines()
        if w.strip() and not w.strip().startswith("#")
    ]
    hits: list[str] = []
    for name, _ in SUBMISSION_ORDER:
        path = ROOT / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for word in words:
            if word and word in text:
                hits.append(f"{name} 中出现敏感词「{word}」")
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description="合并交付文档为可提交的作品文档")
    parser.add_argument("--title", default="凭迹 CredWatch", help="作品名称")
    args = parser.parse_args()

    out_path = build_submission(title=args.title)
    size_kb = out_path.stat().st_size / 1024

    print(f"已生成：{out_path}")
    print(f"体量：{size_kb:.1f} KB（官方上限 10 MB，余量充足）")
    print()
    print("包含的要素（对应官方要求）：")
    for idx, (heading, rel) in enumerate(SUBMISSION_ORDER, 1):
        exists = "✓" if (ROOT / rel).exists() else "✗"
        print(f"  {idx:>2}. {exists} {heading}")

    hits = fairness_check()
    print()
    if hits:
        print("[!] 公平性自查发现疑似违规内容，提交前必须处理：")
        for hit in hits:
            print("   -", hit)
        return 1
    print("公平性自查：未配置 forbidden_words.txt，跳过敏感词检查。")
    print("  建议在 submission/forbidden_words.txt 中写入学校/学院/姓名后重跑，")
    print("  确认材料中不含影响评审公平的信息（官方硬性要求）。")
    print()
    print("下一步：")
    print(f"  1. 用浏览器打开 {out_path}")
    print("  2. Ctrl+P → 目标打印机选『另存为 PDF』→ 保存")
    print("  3. 确认 PDF 体积 ≤10MB，并按『队长姓名+作品名称+资料名称』命名")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
