import asyncio
from itertools import groupby
from pathlib import Path

from auditkit.models import ContextBlock, RawFinding

CONTEXT_LINES = 3
MERGE_GAP = 2


def _non_blank_window(lines: list[str], center: int, radius: int) -> tuple[int, int]:
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
    p = Path(file_path)
    exists = await asyncio.to_thread(p.exists)
    if not exists:
        return None
    content = await asyncio.to_thread(p.read_text, encoding="utf-8", errors="replace")
    return content.split("\n")


async def build_context_blocks(findings: list[RawFinding]) -> list[ContextBlock]:
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
