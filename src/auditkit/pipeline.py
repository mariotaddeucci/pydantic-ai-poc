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
from auditkit.scanner import AGENT_PROFILES, create_providers, filter_provider_names
from auditkit.validator import (
    validate_counts,
    validate_cross_reference,
    validate_markdown,
    validate_paths,
)

app = typer.Typer(no_args_is_help=True)


async def run(
    directory: str,
    settings: Settings,
    agent_name: str = "credential",
    select: str | None = None,
    exclude: str | None = None,
) -> str | None:
    """Run the full pipeline. Returns path to markdown report or None if clean."""
    dir_path = Path(directory).resolve()

    if agent_name not in AGENT_PROFILES:
        print(
            f"Unknown agent: {agent_name}. Available: {', '.join(sorted(AGENT_PROFILES))}",
            file=sys.stderr,
        )
        raise typer.Exit(2)

    try:
        agent = get_agent(agent_name)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        raise typer.Exit(2) from e

    # ── Phase 1: scan ──────────────────────────────────────────────
    names = filter_provider_names(select, exclude, agent_name)
    if not names:
        print("No tools selected — nothing to run.", file=sys.stderr)
        return None

    all_findings: list[RawFinding] = []
    for name in names:
        print(f"  Running {name}...")
        try:
            provider = create_providers(directory, agent=agent_name, select=[name])[0]
            count = 0
            async for finding in provider.generate_audit_records():
                all_findings.append(finding)
                count += 1
            print(f"    {count} finding(s)")
        except Exception as e:
            print(f"    Skipped: {e}")

    print(f"\nTotal raw findings: {len(all_findings)}")
    if not all_findings:
        print("No security issues found.")
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
    print(f"JSONL saved: {jsonl_path} ({len(entries)} entries)")

    # ── Phase 2: report ────────────────────────────────────────────
    md_path = dir_path / f"{agent_name}_scan_report.md"
    md_content = build_markdown_report(merged_blocks, str(directory), tools_used, agent_name=agent_name)
    await asyncio.to_thread(md_path.write_text, md_content, encoding="utf-8")
    print(f"\nPre-context report saved: {md_path}")
    print(f"  Files flagged: {len({b.file_path for b in merged_blocks})}")
    print(f"  Context blocks (merged): {len(merged_blocks)}")
    print(f"  Total findings: {len(entries)}")

    # ── Phase 3: classify (batched) ────────────────────────────────
    files_flagged = list(dict.fromkeys(f.file_path for f in all_findings))
    batch_size = agent.batch_size
    batches = [files_flagged[i : i + batch_size] for i in range(0, len(files_flagged), batch_size)]
    print(f"\nAgent: {agent.name} — {agent.description}")
    print(f"Batches: {len(batches)} ({batch_size} files each)")

    reports: list[ScanReport] = []
    for i, batch_files in enumerate(batches, 1):
        batch_set = set(batch_files)
        batch_findings = [f for f in all_findings if f.file_path in batch_set]
        batch_blocks = await build_context_blocks(batch_findings)
        batch_blocks = await merge_context_blocks(batch_blocks)

        print(f"\n  Batch {i}/{len(batches)} — {len(batch_files)} file(s)")
        for f in batch_files:
            print(f"    {f}")

        report = await classify_batch(agent, batch_blocks, str(directory), settings)
        reports.append(report)
        print(
            f"    → {report.total_findings} analysed, "
            f"exposed={report.exposed}, uncertain={report.uncertain}, "
            f"false_positives={report.false_positives}"
        )

    # ── Phase 4: merge + save ──────────────────────────────────────
    final = merge_reports(reports, str(directory))
    await append_analysis_to_markdown(str(md_path), final)
    print(f"\nAgent analysis appended to: {md_path}")

    analyze_path = dir_path / "analyze_results.json"
    await asyncio.to_thread(
        analyze_path.write_text,
        json.dumps(final.model_dump(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Analyze JSON saved: {analyze_path}")

    print(f"\n{'=' * 60}")
    print(f"FINAL SCAN REPORT — {final.directory}")
    print(f"{'=' * 60}")
    print(f"Total findings: {final.total_findings}")
    print(f"  Exposed:         {final.exposed}")
    print(f"  Uncertain:       {final.uncertain}")
    print(f"  False positives: {final.false_positives}")
    print(f"\nFull report: {md_path}")

    # ── Phase 5: validate ──────────────────────────────────────────
    print(f"\n{'─' * 60}")
    print("VALIDATION")
    print(f"{'─' * 60}")
    await _run_validation(entries, final, md_path, agent_name)

    return str(md_path)


async def _run_validation(entries: list[ScanEntry], report: ScanReport, md_path: Path, agent_name: str) -> None:
    all_errors: list[str] = []

    def check(name: str, errors: list[str]) -> bool:
        ok = len(errors) == 0
        status = "✓" if ok else "✗"
        print(f"  {status} {name}")
        if not ok:
            for e in errors:
                all_errors.append(f"[{name}] {e}")
                print(f"      {e}")
        return ok

    all_ok = True
    all_ok &= check("Internal counts", validate_counts(report))
    all_ok &= check("Cross-reference (scan ↔ analyze)", validate_cross_reference(entries, report))
    all_ok &= check("Markdown structure", await validate_markdown(md_path, report, agent_name))
    all_ok &= check("File paths existence", await validate_paths(entries))

    if all_ok:
        print("  All validations passed.")
    else:
        print(f"  {len(all_errors)} validation error(s) found.")


@app.command()
def main(
    directory: str = typer.Argument(".", help="Directory to scan"),
    agent: str | None = typer.Option(
        None,
        "--agent",
        "-a",
        help=f"Agent context. Available: {', '.join(sorted(AGENT_PROFILES))}",
    ),
    select: str | None = typer.Option(None, "--select", help="Comma-separated tool names to run (default: all)"),
    exclude: str | None = typer.Option(None, "--exclude", help="Comma-separated tool names to skip (default: none)"),
) -> None:
    """Run the full security scan pipeline."""
    settings = Settings()

    if not settings.openai_api_key:
        print("Erro: OPENAI_API_KEY nao definida.", file=sys.stderr)
        print("Copie .env.example para .env e preencha sua chave da OpenAI.", file=sys.stderr)
        raise typer.Exit(1)

    agent_name = agent or settings.openai_default_agent
    print(f"Scanning directory: {directory}")
    asyncio.run(run(directory, settings, agent_name=agent_name, select=select, exclude=exclude))


if __name__ == "__main__":
    app()
