import json
import subprocess
from dataclasses import dataclass
from enum import Enum
from itertools import groupby
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIChatModelSettings
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.usage import UsageLimits

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
        "You receive a pre-built mini report with code snippets flagged by static "
        "analysis tools. Your only job is to classify each finding.\n\n"
        "For each code block in the report, review the snippet (flagged lines are "
        "marked with '>>>') and determine whether each finding is a "
        "false_positive, exposed, or uncertain.\n\n"
        "Classification criteria:\n"
        "- **false_positive**: The value is clearly a test mock, placeholder, "
        "example from documentation, empty string, or references an env var / settings "
        "(e.g. `os.environ.get(...)`, `getenv(...)`, `Settings()`, `config()`).\n"
        "- **exposed**: A real credential or secret is hardcoded in source code "
        "with actual values that look like real tokens, passwords, or API keys.\n"
        "- **uncertain**: The context is ambiguous — it could be a real secret or a "
        "test/mock but you cannot determine with confidence.\n\n"
        "IMPORTANT: Analyse every finding listed in the report. Do not skip any. "
        "Provide assessment and reasoning for each one."
    ),
    defer_model_check=True,
)


# ── Main ──────────────────────────────────────────────────────────────

BATCH_SIZE = 5  # files per agent run

# Registry of tool adapters — add new tools here
TOOL_RUNNERS: list[tuple[str, Any]] = [
    ("ruff", run_ruff),
]


def _merge_reports(reports: list[ScanReport], directory: str) -> ScanReport:
    merged = ScanReport(directory=directory)
    for r in reports:
        merged.total_findings += r.total_findings
        merged.false_positives += r.false_positives
        merged.exposed += r.exposed
        merged.uncertain += r.uncertain
        merged.findings.extend(r.findings)
    return merged


def _format_prompt_from_blocks(blocks: list[ContextBlock], directory: str) -> str:
    blocks_text: list[str] = []
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
    return (
        f"Analyse the following security scan results from directory `{directory}`.\n\n"
        + "\n".join(blocks_text) +
        "\n\nFor each finding, classify it as false_positive, exposed, or uncertain. "
        "Include your reasoning for each classification."
    )


async def _analyse_batch(
    batch_files: list[str],
    all_findings: list[RawFinding],
    model: OpenAIChatModel,
    directory: str,
) -> ScanReport:
    """Run the agent on a single batch of files (5 or fewer)."""
    batch_set = set(batch_files)
    batch_findings = [f for f in all_findings if f.file_path in batch_set]

    blocks = build_context_blocks(batch_findings)
    prompt = _format_prompt_from_blocks(blocks, directory)
    deps = ScanDeps(directory=directory, blocks=blocks)

    result = await agent.run(
        prompt,
        deps=deps,
        model=model,
        model_settings=OpenAIChatModelSettings(
            extra_body={"thinking": {"type": "disabled"}}
        ),
        usage_limits=UsageLimits(request_limit=200),
    )
    return result.output


async def main():
    import sys

    if not settings.opencode_api_key:
        print("Erro: OPENCODE_API_KEY nao definida.")
        print("Copie .env.example para .env e preencha sua chave do OpenCode Go.")
        return

    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"Scanning directory: {directory}")

    # Phase 1: run external tools
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

    # Phase 2: group by file and split into batches
    files_flagged = list(dict.fromkeys(f.file_path for f in all_findings))
    batches = [files_flagged[i:i + BATCH_SIZE] for i in range(0, len(files_flagged), BATCH_SIZE)]

    provider = OpenAIProvider(
        base_url=settings.opencode_base_url,
        api_key=settings.opencode_api_key,
    )
    model = OpenAIChatModel(settings.opencode_model_light, provider=provider)

    print(f"\nFiles flagged: {len(files_flagged)}")
    print(f"Batches: {len(batches)} ({BATCH_SIZE} files each)")

    # Phase 3: process each batch through the agent
    reports: list[ScanReport] = []
    for i, batch in enumerate(batches, 1):
        print(f"\n  Batch {i}/{len(batches)} — {len(batch)} file(s)")
        for f in batch:
            print(f"    {f}")
        report = await _analyse_batch(batch, all_findings, model, directory)
        reports.append(report)
        print(f"    → {report.total_findings} analysed, "
              f"exposed={report.exposed}, uncertain={report.uncertain}, "
              f"false_positives={report.false_positives}")

    # Phase 4: merge and print
    final = _merge_reports(reports, directory)
    print(f"\n{'=' * 60}")
    print(f"FINAL SCAN REPORT — {final.directory}")
    print(f"{'=' * 60}")
    print(f"Total findings: {final.total_findings}")
    print(f"  Exposed:         {final.exposed}")
    print(f"  Uncertain:       {final.uncertain}")
    print(f"  False positives: {final.false_positives}")
    print(f"\n--- Detailed findings ---")
    for f in final.findings:
        print(f"\n[{f.assessment.upper()}] {f.file_path}:{f.line_number} [{f.rule_id}]")
        print(f"  Reasoning: {f.reasoning}")
        print(f"  Context:\n{f.context}")


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
