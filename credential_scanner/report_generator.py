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
    """Pre-context phase: read files, expand windows, merge overlapping blocks."""
    findings_sorted = sorted(findings, key=lambda f: (f.file_path, f.line_number))
    blocks: list[ContextBlock] = []

    for file_path, group in groupby(findings_sorted, key=lambda f: f.file_path):
        p = Path(file_path)
        if not p.exists():
            continue
        lines = p.read_text(encoding="utf-8", errors="replace").split("\n")

        file_findings = list(group)
        windows: list[tuple[int, int, set[int], list[RawFinding]]] = []
        for f in file_findings:
            center = f.line_number - 1
            s, e = _non_blank_window(lines, center, CONTEXT_LINES)
            windows.append((s, e, {f.line_number}, [f]))

        windows.sort(key=lambda w: w[0])
        merged: list[tuple[int, int, set[int], list[RawFinding]]] = []
        for s, e, fl, fg in windows:
            if merged and s <= merged[-1][1]:
                prev_s, prev_e, prev_fl, prev_fg = merged.pop()
                merged.append((prev_s, max(prev_e, e), prev_fl | fl, prev_fg + fg))
            else:
                merged.append((s, e, fl, fg))

        for s, e, fl, fg in merged:
            snippet = _format_snippet(lines, s, e, fl)
            blocks.append(ContextBlock(
                file_path=str(p),
                start_line=s + 1,
                end_line=e,
                finding_lines=sorted(fl),
                findings=fg,
                snippet=snippet,
            ))

    return blocks


# ── Markdown report ───────────────────────────────────────────────────


def build_markdown_report(
    blocks: list[ContextBlock],
    directory: str,
    tools_used: list[str],
) -> str:
    """Generate a self-contained markdown report for first-level human review."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = sum(len(b.findings) for b in blocks)
    files_flagged = len({b.file_path for b in blocks})

    lines = [
        f"# Credential Scan Report",
        f"",
        f"**Directory:** `{directory}`  ",
        f"**Generated:** {now}  ",
        f"**Tools:** {', '.join(tools_used)}  ",
        f"**Files flagged:** {files_flagged}  ",
        f"**Findings:** {total}  ",
        f"",
        f"---",
        f"",
    ]

    for i, b in enumerate(blocks, 1):
        rules = {f.rule_id for f in b.findings}
        flagged = ", ".join(str(ln) for ln in b.finding_lines)
        lines.extend([
            f"### {i}. `{b.file_path}`",
            f"",
            f"| Campo | Valor |",
            f"|-------|-------|",
            f"| **Linhas do bloco** | {b.start_line}–{b.end_line} |",
            f"| **Linhas flagadas** | {flagged} |",
            f"| **Regras** | {', '.join(sorted(rules))} |",
            f"",
            f"**Ocorrências:**",
            f"",
        ])
        for f in b.findings:
            lines.append(f"- `[{f.rule_id}]` linha **{f.line_number}** — {f.description}")
        lines.extend([
            f"",
            f"```",
            b.snippet,
            f"```",
            f"",
            f"---",
            f"",
        ])

    return "\n".join(lines)


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
