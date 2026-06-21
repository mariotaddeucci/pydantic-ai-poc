"""Shared prompt formatting helpers for security agents.

The default formatter is implemented directly in SecurityAgent.format_prompt.
This module exists so specialized agents can compose or reuse common pieces
without duplicating code.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from auditkit.models import ContextBlock


def format_block_header(index: int, block: ContextBlock) -> str:
    """Return the markdown header for a single context block."""
    tools = {finding.tool_name for finding in block.findings}
    rules = {finding.rule_id for finding in block.findings}
    flagged = ", ".join(str(ln) for ln in block.finding_lines)
    return (
        f"## Block {index}\n"
        f"**File:** `{block.file_path}` | "
        f"**Lines:** {block.start_line}-{block.end_line} | "
        f"**Flagged:** {flagged}\n"
        f"**Tools:** {', '.join(sorted(tools))} | "
        f"**Rules:** {', '.join(sorted(rules))}\n"
    )


def format_findings_list(block: ContextBlock) -> str:
    """Return the markdown list of findings inside a block."""
    return "\n".join(f"- [{f.rule_id}] line {f.line_number}: {f.description}" for f in block.findings)
