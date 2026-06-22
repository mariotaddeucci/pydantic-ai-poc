"""Central orchestrator — scan → report → classify → validate.

Usage:
  uv run python -m auditkit.pipeline <directory>
  uv run python -m auditkit.pipeline <directory> --agent injection
"""

import asyncio
import json
import sys
from pathlib import Path

import typer

from auditkit.classifier import get_agent, merge_reports
from auditkit.classifier.runner import classify_batch
from auditkit.config import Settings
from auditkit.models import RawFinding, ScanEntry, ScanReport
from auditkit.reporter.context import build_context_blocks, merge_context_blocks
from auditkit.reporter.markdown import append_analysis_to_markdown, build_markdown_report
from auditkit.scanner import (
    AGENT_PROFILES,
    ProviderNotInstalledError,
    create_providers,
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


async def run(
    directory: str,
    settings: Settings,
    agent_name: str = "credential",
) -> str | None:
    """Run the full pipeline. Returns path to markdown report or None if clean."""
    dir_path = Path(directory).resolve()

    if agent_name not in AGENT_PROFILES:
        _stderr_json(error=f"Unknown agent '{agent_name}'", available=sorted(AGENT_PROFILES))
        raise typer.Exit(2)

    try:
        agent = get_agent(agent_name)
    except ValueError as e:
        _stderr_json(error=str(e))
        raise typer.Exit(2) from e

    # ── Phase 1: scan ──────────────────────────────────────────────
    names = list(AGENT_PROFILES.get(agent_name, {}))
    if not names:
        _stderr_json(warning="No tools configured for this agent")
        return None

    all_findings: list[RawFinding] = []
    for name in names:
        try:
            providers = await create_providers(directory, agent=agent_name, select=[name])
            provider = providers[0]
            all_findings.extend([finding async for finding in provider.generate_audit_records()])
        except ProviderNotInstalledError as e:
            _stderr_json(warning=f"{name} not installed", detail=str(e))
        except Exception as e:
            _stderr_json(warning=f"{name} skipped", detail=str(e))

    if not all_findings:
        return None

    # ── Save JSONL ─────────────────────────────────────────────────
    tools_used = sorted({f.tool_name for f in all_findings})
    blocks = await build_context_blocks(all_findings)
    merged_blocks = await merge_context_blocks(blocks)
    entries = [ScanEntry(finding=f, snippet=b.snippet) for b in merged_blocks for f in b.findings]
    jsonl_path = dir_path / "scan_results.jsonl"
    await asyncio.to_thread(
        jsonl_path.write_text,
        "\n".join(e.model_dump_json() for e in entries) + "\n",
        encoding="utf-8",
    )

    # ── Phase 2: report ────────────────────────────────────────────
    md_path = dir_path / f"{agent_name}_scan_report.md"
    md_content = build_markdown_report(merged_blocks, str(directory), tools_used, agent_name=agent_name)
    await asyncio.to_thread(md_path.write_text, md_content, encoding="utf-8")

    # ── Phase 3: classify (batched) ────────────────────────────────
    files_flagged = list(dict.fromkeys(f.file_path for f in all_findings))
    batch_size = agent.batch_size
    batches = [files_flagged[i : i + batch_size] for i in range(0, len(files_flagged), batch_size)]

    reports: list[ScanReport] = []
    for batch_files in batches:
        batch_set = set(batch_files)
        batch_findings = [f for f in all_findings if f.file_path in batch_set]
        batch_blocks = await build_context_blocks(batch_findings)
        batch_blocks = await merge_context_blocks(batch_blocks)
        report = await classify_batch(agent, batch_blocks, str(directory), settings)
        reports.append(report)

    # ── Phase 4: merge + save ──────────────────────────────────────
    final = merge_reports(reports, str(directory))
    await append_analysis_to_markdown(str(md_path), final)

    analyze_path = dir_path / "analyze_results.json"
    await asyncio.to_thread(
        analyze_path.write_text,
        json.dumps(final.model_dump(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # ── Phase 5: validate ──────────────────────────────────────────
    val_errors: dict[str, list[str]] = {
        "counts": validate_counts(final),
        "cross_reference": validate_cross_reference(entries, final),
        "markdown": await validate_markdown(md_path, final, agent_name),
        "paths": await validate_paths(entries),
    }

    summary = {
        "directory": str(directory),
        "report": str(md_path),
        "analyze": str(analyze_path),
        "total_findings": final.total_findings,
        "exposed": final.exposed,
        "uncertain": final.uncertain,
        "false_positives": final.false_positives,
        "validation": val_errors,
    }
    sys.stdout.write(json.dumps(summary, ensure_ascii=False) + "\n")
    if any(v for v in val_errors.values()):
        raise typer.Exit(1)

    return str(md_path)


@app.command()
def main(
    directory: str = typer.Argument(".", help="Directory to scan"),
    agent: str | None = typer.Option(
        None,
        "--agent",
        "-a",
        help=f"Agent context. Available: {', '.join(sorted(AGENT_PROFILES))}",
    ),
) -> None:
    """Run the full security scan pipeline."""
    settings = Settings()

    if not settings.openai_api_key:
        _stderr_json(
            error="OPENAI_API_KEY not set",
            hint="Copie .env.example para .env e preencha sua chave da OpenAI.",
        )
        raise typer.Exit(1)

    agent_name = agent or settings.openai_default_agent
    asyncio.run(run(directory, settings, agent_name=agent_name))


if __name__ == "__main__":
    app()
