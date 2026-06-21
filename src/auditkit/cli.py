"""CLI for credential scanner — multi-step pipeline with JSONL interchange.

Commands:
  scan     Run scanning tools, merge context blocks, write JSONL.
  report   Read JSONL, build context, write markdown report.
  analyze  Read JSONL, run AI agent, dump ScanReport as JSON to stdout.
  validate Read JSONL + analyze JSON, run validators, dump results as JSON.

All I/O and subprocess calls are async under the hood.  Sync Typer commands
wrap async helpers with asyncio.run().  Settings are created freshly per
command (no global singleton).  Errors are logged as structured JSON to
stderr.
"""

import asyncio
import json
import sys
import traceback
from pathlib import Path

import typer

from auditkit.agents import classify_batch as agent_classify_batch
from auditkit.agents import get_agent, list_agents, merge_reports
from auditkit.config import Settings
from auditkit.models import RawFinding, ScanEntry, ScanReport
from auditkit.providers import AGENT_PROFILES, create_providers
from auditkit.report_generator import (
    build_context_blocks,
    build_markdown_report,
    merge_context_blocks,
)
from auditkit.validator import (
    validate_counts,
    validate_cross_reference,
    validate_markdown,
    validate_paths,
)

app = typer.Typer(no_args_is_help=True)


def _stderr_json(**kwargs: object) -> None:
    sys.stderr.write(json.dumps(kwargs, ensure_ascii=False) + "\n")


def _filter_provider_names(select: str | None, exclude: str | None, agent: str) -> list[str]:
    available = set(AGENT_PROFILES.get(agent, {}))
    selected = {s.strip() for s in select.split(",")} if select else None
    excluded = {s.strip() for s in exclude.split(",")} if exclude else set()
    if selected is not None and excluded:
        _stderr_json(error="--select and --exclude are mutually exclusive")
        raise typer.Exit(2)
    if selected is not None:
        invalid = selected - available
        if invalid:
            _stderr_json(error=f"Unknown tool(s): {', '.join(sorted(invalid))}", agent=agent)
            raise typer.Exit(2)
        return [n for n in available if n in selected]
    return [n for n in available if n not in excluded]


async def _read_jsonl(path: str | None) -> list[ScanEntry]:
    def _read(lines):
        return [ScanEntry.model_validate_json(line) for line in lines if line.strip()]

    if path:
        p = Path(path)
        if not await asyncio.to_thread(p.exists):
            _stderr_json(error=f"File not found: {path}")
            raise typer.Exit(1)

        def _from_file() -> list[ScanEntry]:
            with open(p, encoding="utf-8") as f:
                return _read(f)

        return await asyncio.to_thread(_from_file)

    stdin = await asyncio.to_thread(sys.stdin.read)
    return _read(stdin.split("\n"))


def _wrap_async(coro):
    try:
        asyncio.run(coro)
    except typer.Exit:
        raise
    except Exception:
        _stderr_json(error=traceback.format_exc())
        raise typer.Exit(1) from None


# ── Scan ──────────────────────────────────────────────────────────────────


async def _scan(
    directory: str,
    output: str | None,
    select: str | None,
    exclude: str | None,
    agent: str,
) -> None:
    if agent not in AGENT_PROFILES:
        _stderr_json(error=f"Unknown agent '{agent}'", available=sorted(AGENT_PROFILES))
        raise typer.Exit(2)

    names = _filter_provider_names(select, exclude, agent)
    if not names:
        return

    all_findings: list[RawFinding] = []
    for name in names:
        try:
            provider = create_providers(directory, agent=agent, select=[name])[0]
            async for finding in provider.generate_audit_records():
                all_findings.append(finding)  # noqa: PERF401
        except Exception as e:
            _stderr_json(warning=f"{name} skipped", reason=str(e))

    if not all_findings:
        return

    blocks = await build_context_blocks(all_findings)
    merged = await merge_context_blocks(blocks)

    entries = [ScanEntry(finding=f, snippet=b.snippet) for b in merged for f in b.findings]
    lines = "\n".join(e.model_dump_json() for e in entries) + "\n"
    out_path = await asyncio.to_thread(lambda: output or str(Path(directory).resolve() / "scan_results.jsonl"))
    await asyncio.to_thread(Path(out_path).write_text, lines, encoding="utf-8")


@app.command()
def scan(
    directory: str = typer.Argument(".", help="Directory to scan"),
    output: str | None = typer.Option(None, "--output", "-o", help="JSONL output path"),
    select: str | None = typer.Option(None, "--select", help="Comma-separated tools to run"),
    exclude: str | None = typer.Option(None, "--exclude", help="Comma-separated tools to skip"),
    agent: str = typer.Option(
        "credential", "--agent", "-a", help=f"Agent profile. Available: {', '.join(sorted(AGENT_PROFILES))}"
    ),
):
    _wrap_async(_scan(directory, output, select, exclude, agent))


# ── Report ─────────────────────────────────────────────────────────────────


async def _report(jsonl_file: str | None, output: str | None, directory: str | None, agent: str) -> None:
    entries = await _read_jsonl(jsonl_file)
    findings = [e.finding for e in entries]
    if not findings:
        return

    label = directory or (str(Path(jsonl_file).parent) if jsonl_file else ".")
    blocks = await build_context_blocks(findings)
    merged = await merge_context_blocks(blocks)
    tools = sorted({f.tool_name for f in findings})
    md = build_markdown_report(merged, label, tools, agent_name=agent)

    out = Path(output) if output else Path(label) / f"{agent}_scan_report.md"
    await asyncio.to_thread(out.write_text, md, encoding="utf-8")


@app.command()
def report(
    jsonl_file: str | None = typer.Argument(None, help="JSONL input (or stdin)"),
    output: str | None = typer.Option(None, "--output", "-o", help="Markdown output path"),
    directory: str | None = typer.Option(None, "--directory", "-d", help="Directory label"),
    agent: str = typer.Option("credential", "--agent", "-a", help="Agent context for report title"),
):
    _wrap_async(_report(jsonl_file, output, directory, agent))


# ── Analyze ────────────────────────────────────────────────────────────────


async def _analyze(
    jsonl_file: str | None,
    directory: str | None,
    agent: str | None,
) -> None:
    settings = Settings()
    if not settings.openai_api_key:
        _stderr_json(error="OPENAI_API_KEY not set")
        raise typer.Exit(1)

    agent_name = agent or settings.openai_default_agent
    try:
        instance = get_agent(agent_name).create()
    except ValueError as e:
        _stderr_json(error=str(e))
        raise typer.Exit(2) from None

    entries = await _read_jsonl(jsonl_file)
    findings = [e.finding for e in entries]
    label = directory or (str(Path(jsonl_file).parent) if jsonl_file else ".")

    files = list(dict.fromkeys(f.file_path for f in findings))
    batches = [files[i : i + instance.batch_size] for i in range(0, len(files), instance.batch_size)]

    reports: list[ScanReport] = []
    for batch in batches:
        batch_set = set(batch)
        batch_findings = [f for f in findings if f.file_path in batch_set]
        blocks = await build_context_blocks(batch_findings)
        blocks = await merge_context_blocks(blocks)
        report = await agent_classify_batch(instance, blocks, label, settings)
        reports.append(report)

    final = merge_reports(reports, label)
    sys.stdout.write(final.model_dump_json(indent=2, ensure_ascii=False) + "\n")


@app.command()
def analyze(
    jsonl_file: str | None = typer.Argument(None, help="JSONL input (or stdin)"),
    directory: str | None = typer.Option(None, "--directory", "-d", help="Directory label"),
    agent: str | None = typer.Option(None, "--agent", "-a", help=f"Agent. Available: {', '.join(list_agents())}"),
):
    _wrap_async(_analyze(jsonl_file, directory, agent))


# ── Validate ──────────────────────────────────────────────────────────────


async def _validate(jsonl_file: str | None, analyze_path: str | None, report_md: str | None, agent: str) -> None:
    entries = await _read_jsonl(jsonl_file)
    base = Path(jsonl_file).parent if jsonl_file else Path.cwd()

    if analyze_path:
        content = await asyncio.to_thread(Path(analyze_path).read_text, encoding="utf-8")
        report = ScanReport.model_validate_json(content)
    else:
        stdin_data = await asyncio.to_thread(sys.stdin.read)
        if not stdin_data.strip():
            _stderr_json(error="Provide --analyze or pipe analyze JSON via stdin")
            raise typer.Exit(1)
        report = ScanReport.model_validate_json(stdin_data)

    md_path = Path(report_md) if report_md else base / f"{agent}_scan_report.md"

    errors: dict[str, list[str]] = {
        "counts": validate_counts(report),
        "cross_reference": validate_cross_reference(entries, report),
        "markdown": await validate_markdown(md_path, report),
        "paths": await validate_paths(entries),
    }

    sys.stdout.write(json.dumps(errors, indent=2, ensure_ascii=False) + "\n")
    if any(v for v in errors.values()):
        raise typer.Exit(1)


@app.command()
def validate(
    jsonl_file: str | None = typer.Argument(None, help="JSONL input (or stdin)"),
    analyze_json: str | None = typer.Option(None, "--analyze", "-a", help="Analyze JSON path (or stdin)"),
    report_md: str | None = typer.Option(None, "--report", "-r", help="Markdown report path"),
    agent: str = typer.Option("credential", "--agent", help="Agent context for report filename"),
):
    _wrap_async(_validate(jsonl_file, analyze_json, report_md, agent))


if __name__ == "__main__":
    app()
