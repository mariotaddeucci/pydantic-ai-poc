"""Pre-context phase and markdown report generation.

Receives RawFinding[] from producers, builds merged ContextBlocks
with code snippets, and generates a markdown report for first-level
human review.
"""

import asyncio
from datetime import UTC, datetime
from itertools import groupby
from pathlib import Path

from auditkit.models import ContextBlock, RawFinding, ScanReport

CONTEXT_LINES = 3
MERGE_GAP = 2


# ── Context building ──────────────────────────────────────────────────


def _non_blank_window(lines: list[str], center: int, radius: int) -> tuple[int, int]:
    """Return (start, end) indices around center, skipping blank lines."""
    start = center
    found = 0
    while start > 0 and found < radius:
        start -= 1
        if lines[start].strip():
            found += 1

    end = center
    found = 0
    while end < len(lines) - 1 and found < radius:
        end += 1
        if lines[end].strip():
            found += 1

    return start, end + 1


def _format_snippet(lines: list[str], start: int, end: int, flagged: set[int]) -> str:
    parts: list[str] = []
    for i in range(start, end):
        prefix = ">>> " if (i + 1) in flagged else "    "
        parts.append(f"{prefix}{i + 1:4d}: {lines[i].rstrip()}")
    return "\n".join(parts)


async def _read_file_lines(file_path: str) -> list[str] | None:
    """Async read file lines. Returns None if file does not exist."""
    p = Path(file_path)
    exists = await asyncio.to_thread(p.exists)
    if not exists:
        return None
    content = await asyncio.to_thread(p.read_text, encoding="utf-8", errors="replace")
    return content.split("\n")


async def build_context_blocks(findings: list[RawFinding]) -> list[ContextBlock]:
    """Pre-context phase: one ContextBlock per finding, no merging.

    Each finding gets its own ±3 non-blank-line window. Blocks are
    ordered by file path, then line number.
    """
    findings_sorted = sorted(findings, key=lambda f: (f.file_path, f.line_number))
    blocks: list[ContextBlock] = []

    for file_path, group in groupby(findings_sorted, key=lambda f: f.file_path):
        lines = await _read_file_lines(file_path)
        if lines is None:
            continue

        for f in list(group):
            center = f.line_number - 1
            s, e = _non_blank_window(lines, center, CONTEXT_LINES)
            snippet = _format_snippet(lines, s, e, {f.line_number})
            blocks.append(
                ContextBlock(
                    file_path=file_path,
                    start_line=s + 1,
                    end_line=e,
                    finding_lines=[f.line_number],
                    findings=[f],
                    snippet=snippet,
                )
            )

    return blocks


def _rebuild_snippet(block: ContextBlock, file_lines: list[str]) -> ContextBlock:
    """Rebuild snippet from file lines using the block's range and finding_lines."""
    flagged = set(block.finding_lines)
    parts: list[str] = []
    for i in range(block.start_line - 1, block.end_line):
        if i >= len(file_lines):
            break
        prefix = ">>> " if (i + 1) in flagged else "    "
        parts.append(f"{prefix}{i + 1:4d}: {file_lines[i].rstrip()}")
    block.snippet = "\n".join(parts)
    return block


async def merge_context_blocks(blocks: list[ContextBlock]) -> list[ContextBlock]:
    """Merge overlapping or adjacent context blocks within the same file.

    When multiple tools flag the same or nearby lines, their context
    windows may overlap. Consolidates them into expanded blocks with
    combined finding lists and re-extracted snippets.
    """
    merged: list[ContextBlock] = []

    blocks_sorted = sorted(blocks, key=lambda b: (b.file_path, b.start_line))
    for file_path, file_group in groupby(blocks_sorted, key=lambda b: b.file_path):
        file_blocks = list(file_group)
        file_lines = await _read_file_lines(file_path)
        if file_lines is None:
            continue

        if not file_blocks:
            continue

        current = file_blocks[0]
        for nb in file_blocks[1:]:
            if nb.start_line <= current.end_line + MERGE_GAP:
                current = ContextBlock(
                    file_path=current.file_path,
                    start_line=min(current.start_line, nb.start_line),
                    end_line=max(current.end_line, nb.end_line),
                    finding_lines=sorted(set(current.finding_lines + nb.finding_lines)),
                    findings=current.findings + nb.findings,
                    snippet="",
                )
            else:
                current = _rebuild_snippet(current, file_lines)
                merged.append(current)
                current = nb

        current = _rebuild_snippet(current, file_lines)
        merged.append(current)

    return merged


# ── Markdown report ───────────────────────────────────────────────────


def build_markdown_report(
    blocks: list[ContextBlock],
    directory: str,
    tools_used: list[str],
    agent_name: str = "credential",
) -> str:
    """Generate a per-file markdown report — one section per file, one block per merged context."""
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
            lines.extend(
                [
                    "```",
                    b.snippet,
                    "```",
                    "",
                ]
            )

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


_RULE_LABELS: dict[str, str] = {
    "S105": "hardcoded-password-string",
    "S106": "hardcoded-password-func-arg",
    "S107": "hardcoded-password-default",
    "B105": "hardcoded_password_string",
    "B106": "hardcoded_password_funcarg",
    "B107": "hardcoded_password_default",
}


def _rule_label(rule_id: str) -> str:
    return _RULE_LABELS.get(rule_id, rule_id)


async def append_analysis_to_markdown(md_path: str, report: ScanReport) -> None:
    """Append the agent's classification to the markdown report."""
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
    """Synchronous file append helper (called via asyncio.to_thread)."""
    with open(path, "a", encoding="utf-8") as f:
        f.write(content)
