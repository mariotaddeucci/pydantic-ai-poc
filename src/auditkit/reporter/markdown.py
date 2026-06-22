from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from itertools import groupby
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from auditkit.models import ContextBlock, ScanReport


def build_markdown_report(
    blocks: list[ContextBlock],
    directory: str,
    tools_used: list[str],
    agent_name: str = "credential",
) -> str:
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    files_flagged = len({b.file_path for b in blocks})
    total_findings = sum(len(b.findings) for b in blocks)

    lines = [
        f"# {agent_name.title()} Scan Report",
        "",
        f"**Directory:** `{directory}`  ",
        f"**Generated:** {now}  ",
        f"**Tools:** {', '.join(tools_used)}  ",
        f"**Files flagged:** {files_flagged}  ",
        f"**Findings:** {total_findings}  ",
        "",
        "---",
        "",
    ]

    blocks_sorted = sorted(blocks, key=lambda b: (b.file_path, b.start_line))
    for file_path, _group in groupby(blocks_sorted, key=lambda b: b.file_path):
        file_blocks = list(_group)
        name = Path(file_path).name
        lines.append(f"## {name}")
        lines.append("")
        lines.append(f"*`{file_path}`*")
        lines.append("")

        for b in file_blocks:
            flagged_lines = ", ".join(str(ln) for ln in sorted(b.finding_lines))
            lines.append(f"### Linha(s) {flagged_lines}")
            lines.append("")
            lines.extend(f"- **`[{f.rule_id}]` ({f.tool_name})**: {f.description}" for f in b.findings)
            lines.append("")
            lines.extend(["```", b.snippet, "```", ""])

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


async def append_analysis_to_markdown(md_path: str, report: ScanReport) -> None:
    lines = [
        "## Análise do Agente",
        "",
        "| Classificação | Quantidade |",
        "|---------------|------------|",
        f"| 🔴 Exposto     | {report.exposed} |",
        f"| 🟡 Incerto     | {report.uncertain} |",
        f"| 🟢 Falso positivo | {report.false_positives} |",
        f"| **Total**      | **{report.total_findings}** |",
        "",
        "---",
        "",
    ]

    for f in report.findings:
        emoji = {"exposed": "🔴", "uncertain": "🟡", "false_positive": "🟢"}.get(f.assessment, "⚪")
        lines.extend(
            [
                f"### {emoji} `{f.file_path}`:{f.line_number} `[{f.rule_id}]`",
                "",
                f"**Classificação:** {f.assessment.replace('_', ' ').title()}",
                "",
                f"**Justificativa:** {f.reasoning}",
                "",
                "**Trecho:**",
                "```",
                f.context,
                "```",
                "",
            ]
        )

    content = "\n".join(lines) + "\n"
    await asyncio.to_thread(_append_to_file, md_path, content)


def _append_to_file(path: str, content: str) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(content)
