import json
import subprocess
from dataclasses import dataclass
from enum import Enum
from itertools import groupby
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIChatModelSettings
from pydantic_ai.providers.openai import OpenAIProvider

from config import settings

CONTEXT_LINES = 5

RUFF_CREDENTIAL_RULES = [
    "S105",  # hardcoded-password-string
    "S106",  # hardcoded-password-func-arg
    "S107",  # hardcoded-password-default
]


# ── Generic tool models ───────────────────────────────────────────────


class RawFinding(BaseModel):
    """Generic finding produced by any scanning tool."""
    file_path: str
    line_number: int
    rule_id: str
    description: str
    tool_name: str
    extra: dict[str, Any] = Field(default_factory=dict)


class ContextBlock(BaseModel):
    """Pre-assembled context for one or more merged findings."""
    file_path: str
    start_line: int
    end_line: int
    finding_lines: list[int]
    findings: list[RawFinding]
    snippet: str


# ── Agent output models ───────────────────────────────────────────────


class Assessment(str, Enum):
    FALSE_POSITIVE = "false_positive"
    EXPOSED = "exposed"
    UNCERTAIN = "uncertain"


class AnalyzedFinding(BaseModel):
    file_path: str
    line_number: int
    rule_id: str
    assessment: Assessment
    context: str
    reasoning: str


class ScanReport(BaseModel):
    directory: str
    total_findings: int = 0
    false_positives: int = 0
    exposed: int = 0
    uncertain: int = 0
    findings: list[AnalyzedFinding] = Field(default_factory=list)


# ── Tool adapters (each toolname -> RawFinding list) ──────────────────

IGNORED_PARTS = {".venv", "venv", ".git", "node_modules", "__pycache__", ".tox", "dist", "build"}


def _is_ignored(file_path: str) -> bool:
    path = Path(file_path)
    return any(p in IGNORED_PARTS or p.endswith(".egg-info") for p in path.parts)


# ── Ruff adapter ─────────────────────────────────────────────────────


class _RuffLocation(BaseModel):
    column: int
    row: int


class _RuffFinding(BaseModel):
    code: str
    filename: str
    location: _RuffLocation
    message: str
    url: str | None = None


def run_ruff(dir_path: str) -> list[RawFinding]:
    rules = ",".join(RUFF_CREDENTIAL_RULES)
    result = subprocess.run(
        ["uv", "run", "ruff", "check", "--output-format", "json", "--select", rules, dir_path],
        capture_output=True,
        text=True,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"ruff failed: {result.stderr.strip()}")
    if not result.stdout.strip():
        return []

    findings: list[RawFinding] = []
    for item in json.loads(result.stdout):
        try:
            f = _RuffFinding.model_validate(item)
        except Exception:
            continue
        if _is_ignored(f.filename):
            continue
        findings.append(RawFinding(
            file_path=f.filename,
            line_number=f.location.row,
            rule_id=f.code,
            description=f.message,
            tool_name="ruff",
            extra={"url": f.url} if f.url else {},
        ))
    return findings


# ── Pre-context phase ─────────────────────────────────────────────────


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

    return start, end + 1  # +1 because end is inclusive


def _format_snippet(lines: list[str], start: int, end: int, flagged: set[int]) -> str:
    parts: list[str] = []
    for i in range(start, end):
        prefix = ">>> " if (i + 1) in flagged else "    "
        parts.append(f"{prefix}{i + 1:4d}: {lines[i].rstrip()}")
    return "\n".join(parts)


def build_context_blocks(findings: list[RawFinding]) -> list[ContextBlock]:
    """Pre-context phase: read files, expand windows, merge overlapping blocks."""
    # Group by file_path
    findings_sorted = sorted(findings, key=lambda f: (f.file_path, f.line_number))
    blocks: list[ContextBlock] = []

    for file_path, group in groupby(findings_sorted, key=lambda f: f.file_path):
        p = Path(file_path)
        if not p.exists():
            continue
        lines = p.read_text(encoding="utf-8", errors="replace").split("\n")

        file_findings = list(group)
        # Build expanded windows for each finding
        windows: list[tuple[int, int, set[int], list[RawFinding]]] = []
        for f in file_findings:
            center = f.line_number - 1
            s, e = _non_blank_window(lines, center, CONTEXT_LINES)
            windows.append((s, e, {f.line_number}, [f]))

        # Merge overlapping windows
        windows.sort(key=lambda w: w[0])
        merged: list[tuple[int, int, set[int], list[RawFinding]]] = []
        for s, e, fl, fg in windows:
            if merged and s <= merged[-1][1]:
                # Merge with previous
                prev_s, prev_e, prev_fl, prev_fg = merged.pop()
                merged.append((
                    prev_s, max(prev_e, e),
                    prev_fl | fl,
                    prev_fg + fg,
                ))
            else:
                merged.append((s, e, fl, fg))

        # Build ContextBlock for each merged window
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


# ── Agent ─────────────────────────────────────────────────────────────


@dataclass
class ScanDeps:
    directory: str
    blocks: list[ContextBlock]


agent = Agent(
    deps_type=ScanDeps,
    output_type=ScanReport,
    system_prompt=(
        "You are a senior security auditor specializing in credential leak detection. "
        "Your task is to analyse code blocks flagged by static analysis tools and "
        "classify each finding.\n\n"
        "Each block you receive already contains the surrounding code context. "
        "Review the snippet, identify the flagged lines (marked with '>>>'), and "
        "determine whether each finding is a false_positive, exposed, or uncertain.\n\n"
        "Classification criteria:\n"
        "- **false_positive**: The value is clearly a test mock, placeholder, "
        "example from documentation, empty string, or references an env var / settings "
        "(e.g. `os.environ.get(...)`, `getenv(...)`, `Settings()`, `config()`).\n"
        "- **exposed**: A real credential or secret is hardcoded in source code "
        "with actual values that look like real tokens, passwords, or API keys.\n"
        "- **uncertain**: The context is ambiguous — it could be a real secret or a "
        "test/mock but you cannot determine with confidence.\n\n"
        "For each finding, provide your assessment and reasoning."
    ),
    defer_model_check=True,
)


@agent.tool
async def list_blocks(ctx: RunContext[ScanDeps]) -> str:
    """List all code blocks to be analysed with their pre-assembled context."""
    if not ctx.deps.blocks:
        return "No code blocks to analyse."
    parts = []
    for i, b in enumerate(ctx.deps.blocks, 1):
        tools = {f.tool_name for f in b.findings}
        rules = {f.rule_id for f in b.findings}
        flagged = ", ".join(str(ln) for ln in b.finding_lines)
        parts.append(
            f"--- Block {i} ---\n"
            f"File: {b.file_path}\n"
            f"Lines: {b.start_line}-{b.end_line} (flagged: {flagged})\n"
            f"Tools: {', '.join(sorted(tools))}\n"
            f"Rules: {', '.join(sorted(rules))}\n"
            f"Descriptions:\n" +
            "\n".join(f"  [{f.rule_id}] line {f.line_number}: {f.description}" for f in b.findings) +
            f"\n\nSnippet:\n{b.snippet}\n"
        )
    return "\n".join(parts)


# ── Main ──────────────────────────────────────────────────────────────

# Registry of tool adapters — add new tools here
TOOL_RUNNERS: list[tuple[str, Any]] = [
    ("ruff", run_ruff),
]


async def main():
    import sys

    if not settings.opencode_api_key:
        print("Erro: OPENCODE_API_KEY nao definida.")
        print("Copie .env.example para .env e preencha sua chave do OpenCode Go.")
        return

    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"Scanning directory: {directory}")

    all_findings: list[RawFinding] = []
    for tool_name, runner in TOOL_RUNNERS:
        print(f"  Running {tool_name}...")
        try:
            findings = runner(directory)
            print(f"    {len(findings)} finding(s)")
            all_findings.extend(findings)
        except Exception as e:
            print(f"    Skipped: {e}")

    print(f"\nTotal raw findings: {len(all_findings)}")
    if not all_findings:
        print("No security issues found.")
        return

    # Pre-context phase
    print("Building context blocks...")
    blocks = build_context_blocks(all_findings)
    print(f"  Merged into {len(blocks)} block(s)")

    # Build prompt
    blocks_text = []
    for i, b in enumerate(blocks, 1):
        tools = {f.tool_name for f in b.findings}
        rules = {f.rule_id for f in b.findings}
        flagged = ", ".join(str(ln) for ln in b.finding_lines)
        blocks_text.append(
            f"## Block {i}\n"
            f"**File:** `{b.file_path}` | **Lines:** {b.start_line}-{b.end_line} | "
            f"**Flagged:** {flagged}\n"
            f"**Tools:** {', '.join(sorted(tools))} | **Rules:** {', '.join(sorted(rules))}\n\n"
            f"**Findings:**\n" +
            "\n".join(f"- [{f.rule_id}] line {f.line_number}: {f.description}" for f in b.findings) +
            f"\n\n```\n{b.snippet}\n```\n"
        )

    prompt = (
        f"Analyse the following security scan results from directory `{directory}`.\n\n"
        + "\n".join(blocks_text) +
        "\n\nFor each finding, classify it as false_positive, exposed, or uncertain. "
        "Include your reasoning for each classification."
    )

    provider = OpenAIProvider(
        base_url=settings.opencode_base_url,
        api_key=settings.opencode_api_key,
    )
    model = OpenAIChatModel(settings.opencode_model, provider=provider)
    deps = ScanDeps(directory=directory, blocks=blocks)

    result = await agent.run(
        prompt,
        deps=deps,
        model=model,
        model_settings=OpenAIChatModelSettings(
            extra_body={"thinking": {"type": "disabled"}}
        ),
    )

    report = result.output
    print(f"\n=== SCAN REPORT ===")
    print(f"Directory: {report.directory}")
    print(f"Total: {report.total_findings}")
    print(f"False positives: {report.false_positives}")
    print(f"Exposed: {report.exposed}")
    print(f"Uncertain: {report.uncertain}")
    print(f"\n--- Findings ---")
    for f in report.findings:
        print(f"\n[{f.assessment.upper()}] {f.file_path}:{f.line_number} [{f.rule_id}]")
        print(f"  Reasoning: {f.reasoning}")
        print(f"  Context:\n{f.context}")

    print(f"\nUsage: {result.usage}")


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
