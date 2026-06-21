"""Pre-context phase and markdown report generation.

Receives RawFinding[] from producers, builds merged ContextBlocks
with code snippets, and generates a markdown report for first-level
human review.
"""

from datetime import datetime, timezone
from itertools import groupby
from pathlib import Path

from credential_scanner.models import ContextBlock, RawFinding, ScanReport

CONTEXT_LINES = 3


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


def build_context_blocks(findings: list[RawFinding]) -> list[ContextBlock]:
    """Pre-context phase: one ContextBlock per finding, no merging.

    Each finding gets its own ±3 non-blank-line window. Blocks are
    ordered by file path, then line number.
    """
    findings_sorted = sorted(findings, key=lambda f: (f.file_path, f.line_number))
    blocks: list[ContextBlock] = []

    for file_path, group in groupby(findings_sorted, key=lambda f: f.file_path):
        p = Path(file_path)
        if not p.exists():
            continue
        lines = p.read_text(encoding="utf-8", errors="replace").split("\n")

        for f in list(group):
            center = f.line_number - 1
            s, e = _non_blank_window(lines, center, CONTEXT_LINES)
            snippet = _format_snippet(lines, s, e, {f.line_number})
            blocks.append(ContextBlock(
                file_path=str(p),
                start_line=s + 1,
                end_line=e,
                finding_lines=[f.line_number],
                findings=[f],
                snippet=snippet,
            ))

    return blocks


# ── Markdown report ───────────────────────────────────────────────────


def build_markdown_report(
    blocks: list[ContextBlock],
    directory: str,
    tools_used: list[str],
) -> str:
    """Generate a per-file markdown report — one section per file, one block per finding."""
    from itertools import groupby as _groupby

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    files_flagged = len({b.file_path for b in blocks})

    lines = [
        f"# Credential Scan Report",
        f"",
        f"**Directory:** `{directory}`  ",
        f"**Generated:** {now}  ",
        f"**Tools:** {', '.join(tools_used)}  ",
        f"**Files flagged:** {files_flagged}  ",
        f"**Findings:** {len(blocks)}  ",
        f"",
        f"---",
        f"",
    ]

    blocks_sorted = sorted(blocks, key=lambda b: (b.file_path, b.start_line))
    for file_path, group in _groupby(blocks_sorted, key=lambda b: b.file_path):
        file_blocks = list(group)
        name = Path(file_path).name
        lines.append(f"## {name}")
        lines.append(f"")
        lines.append(f"*`{file_path}`*")
        lines.append(f"")

        for b in file_blocks:
            f = b.findings[0]  # one finding per block
            lines.extend([
                f"### Linha {f.line_number} — `[{f.rule_id}]` {_rule_label(f.rule_id)}",
                f"",
                f"**{f.description}**",
                f"",
                f"```",
                b.snippet,
                f"```",
                f"",
            ])

        lines.append(f"---")
        lines.append(f"")

    return "\n".join(lines)


_RULE_LABELS: dict[str, str] = {
    "S105": "hardcoded-password-string",
    "S106": "hardcoded-password-func-arg",
    "S107": "hardcoded-password-default",
}


def _rule_label(rule_id: str) -> str:
    return _RULE_LABELS.get(rule_id, rule_id)


def append_analysis_to_markdown(md_path: str, report: ScanReport) -> None:
    """Append the agent's classification to the markdown report."""
    lines = [
        f"## Análise do Agente (DeepSeek V4 Flash)",
        f"",
        f"| Classificação | Quantidade |",
        f"|---------------|------------|",
        f"| 🔴 Exposto     | {report.exposed} |",
        f"| 🟡 Incerto     | {report.uncertain} |",
        f"| 🟢 Falso positivo | {report.false_positives} |",
        f"| **Total**      | **{report.total_findings}** |",
        f"",
        f"---",
        f"",
    ]

    for f in report.findings:
        emoji = {"exposed": "🔴", "uncertain": "🟡", "false_positive": "🟢"}.get(
            f.assessment, "⚪"
        )
        lines.extend([
            f"### {emoji} `{f.file_path}`:{f.line_number} `[{f.rule_id}]`",
            f"",
            f"**Classificação:** {f.assessment.replace('_', ' ').title()}",
            f"",
            f"**Justificativa:** {f.reasoning}",
            f"",
            f"**Trecho:**",
            f"```",
            f.context,
            f"```",
            f"",
        ])

    with open(md_path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines))
