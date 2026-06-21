"""CLI for credential scanner — multi-step pipeline with JSONL interchange.

Commands:
  scan     Run producers, build context, merge overlapping blocks, output JSONL.
  report   Read JSONL, generate a markdown report with findings and code context.
  analyze  Read JSONL, run the AI agent classifier in batches, output JSON report.
  validate Validate the final scan report for consistency and completeness.
"""

import asyncio
import json
import sys
from pathlib import Path

import typer

from auditkit.agents import classify_batch as agent_classify_batch
from auditkit.agents import get_agent, list_agents, merge_reports
from auditkit.config import settings
from auditkit.models import RawFinding, ScanEntry, ScanReport
from auditkit.providers import AVAILABLE_PROVIDERS, PROFILE_RULES
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


def _err(msg: str = "") -> None:
    """Print to stderr."""
    typer.echo(msg, err=True)


def _filter_provider_names(select: str | None, exclude: str | None) -> list[str]:
    """Apply --select / --exclude filters to provider names."""
    selected = {s.strip() for s in select.split(",")} if select else None
    excluded = {s.strip() for s in exclude.split(",")} if exclude else set()

    if selected is not None and excluded:
        _err("Error: --select and --exclude are mutually exclusive.")
        raise typer.Exit(2)

    if selected is not None:
        return [n for n in AVAILABLE_PROVIDERS if n in selected]
    return [n for n in AVAILABLE_PROVIDERS if n not in excluded]


@app.command()
def scan(
    directory: str = typer.Argument(".", help="Directory to scan for credentials"),
    output: str | None = typer.Option(
        None, "--output", "-o", help="JSONL output file (default: <directory>/scan_results.jsonl)"
    ),
    select: str | None = typer.Option(None, "--select", help="Comma-separated tool names to run (default: all)"),
    exclude: str | None = typer.Option(None, "--exclude", help="Comma-separated tool names to skip (default: none)"),
    profile: str = typer.Option("secret-scan", "--profile", "-p", help="Scan profile with pre-configured rules"),
):
    """Scan a directory for hardcoded credentials.

    Runs all registered providers (ruff, bandit, detect-secrets) by default.
    Use --select to run only specific tools or --exclude to skip some.
    Use --profile to pick a pre-configured rule set (default: secret-scan).
    Merges overlapping context blocks from different tools into consolidated snippets.
    Outputs one JSONL line per finding.
    """
    if profile not in PROFILE_RULES:
        _err(f"Unknown profile: {profile}. Available: {', '.join(sorted(PROFILE_RULES))}")
        raise typer.Exit(2)

    _err(f"Scanning: {directory} (profile: {profile})")

    names = _filter_provider_names(select, exclude)
    if not names:
        _err("No tools selected — nothing to run.")
        return

    profile_rules = PROFILE_RULES[profile]
    all_findings: list[RawFinding] = []
    for name in names:
        _err(f"  Running {name}...")
        try:
            provider_cls = AVAILABLE_PROVIDERS[name]
            rules = profile_rules.get(name, [])
            provider = provider_cls(directory, rules=rules)
            count = 0
            for finding in provider.generate_audit_records():
                all_findings.append(finding)
                count += 1
            _err(f"    {count} finding(s)")
        except Exception as e:
            _err(f"    Skipped: {e}")

    _err(f"Total raw findings: {len(all_findings)}")
    if not all_findings:
        _err("No security issues found.")
        return

    blocks = build_context_blocks(all_findings)
    _err(f"Context blocks (pre-merge): {len(blocks)}")

    merged = merge_context_blocks(blocks)
    _err(f"Context blocks (post-merge): {len(merged)}")

    entries = [ScanEntry(finding=f, snippet=b.snippet) for b in merged for f in b.findings]

    lines = "\n".join(e.model_dump_json() for e in entries) + "\n"
    out_file = output or str(Path(directory).resolve() / "scan_results.jsonl")
    Path(out_file).write_text(lines, encoding="utf-8")
    _err(f"JSONL saved: {out_file} ({len(entries)} entries)")


def _read_jsonl(jsonl_file: str | None) -> list[ScanEntry]:
    """Read ScanEntry items from a JSONL file or stdin."""
    entries: list[ScanEntry] = []
    if jsonl_file:
        p = Path(jsonl_file)
        if not p.exists():
            _err(f"File not found: {jsonl_file}")
            raise typer.Exit(1)
        source = open(p, encoding="utf-8")
    else:
        source = sys.stdin
    with source:
        for raw_line in source:
            line = raw_line.strip()
            if not line:
                continue
            entries.append(ScanEntry.model_validate_json(line))
    return entries


@app.command()
def report(
    jsonl_file: str | None = typer.Argument(None, help="JSONL file from the scan command (or stdin)"),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Markdown output file (default: <jsonl_dir>/credential_scan_report.md)"
    ),
    directory: str | None = typer.Option(None, "--directory", "-d", help="Directory label in the report header"),
):
    """Generate a markdown report from JSONL scan results.

    Reads findings from a JSONL file (or stdin), rebuilds context blocks,
    merges them, and exports a markdown report with code snippets for each
    finding. No AI agent is invoked — this is the first-level human review report.
    """
    entries = _read_jsonl(jsonl_file)
    all_findings = [e.finding for e in entries]
    dir_label = directory or (str(Path(jsonl_file).parent) if jsonl_file else ".")

    if not all_findings:
        _err("No findings to report.")
        return

    blocks = build_context_blocks(all_findings)
    merged = merge_context_blocks(blocks)
    tools = sorted({f.tool_name for f in all_findings})
    md_content = build_markdown_report(merged, dir_label, tools)

    out_path = Path(output) if output else Path(dir_label) / "credential_scan_report.md"
    out_path.write_text(md_content, encoding="utf-8")
    _err(f"Report saved: {out_path}")
    _err(f"  Files flagged: {len({b.file_path for b in merged})}")
    _err(f"  Context blocks: {len(merged)}")
    _err(f"  Findings: {len(all_findings)}")


@app.command()
def analyze(
    jsonl_file: str | None = typer.Argument(None, help="JSONL file from the scan command (or stdin)"),
    directory: str | None = typer.Option(None, "--directory", "-d", help="Override report directory label"),
    agent: str = typer.Option(
        settings.openai_default_agent,
        "--agent",
        "-a",
        help=f"Agent context to use. Available: {', '.join(list_agents())}",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress status output, print only JSON"),
):
    """Analyze JSONL scan results with the selected AI security agent.

    Reads findings from a JSONL file (or stdin), groups by file, runs the
    chosen agent in batches, and prints the final ScanReport as JSON to stdout.
    """
    if not settings.openai_api_key:
        _err("Erro: OPENAI_API_KEY nao definida.")
        _err("Copie .env.example para .env e preencha sua chave da OpenAI.")
        raise typer.Exit(1)

    try:
        agent_instance = get_agent(agent).create()
    except ValueError as e:
        _err(f"Error: {e}")
        raise typer.Exit(2) from e

    entries = _read_jsonl(jsonl_file)
    all_findings = [e.finding for e in entries]
    dir_label = directory or (str(Path(jsonl_file).parent) if jsonl_file else ".")

    if not quiet:
        _err(f"Loaded {len(all_findings)} findings")
        _err(f"Agent: {agent_instance.name} — {agent_instance.description}")

    files_flagged = list(dict.fromkeys(f.file_path for f in all_findings))
    batch_size = agent_instance.batch_size
    batches = [files_flagged[i : i + batch_size] for i in range(0, len(files_flagged), batch_size)]
    if not quiet:
        _err(f"Files flagged: {len(files_flagged)}")
        _err(f"Batches: {len(batches)} ({batch_size} files each)")

    async def _run():
        reports: list[ScanReport] = []
        for i, batch_files in enumerate(batches, 1):
            batch_set = set(batch_files)
            batch_findings = [f for f in all_findings if f.file_path in batch_set]
            batch_blocks = build_context_blocks(batch_findings)
            batch_blocks = merge_context_blocks(batch_blocks)

            if not quiet:
                _err(f"  Batch {i}/{len(batches)} — {len(batch_files)} file(s)")
                for bf in batch_files:
                    _err(f"    {bf}")

            report = await agent_classify_batch(agent_instance, batch_blocks, dir_label)
            reports.append(report)
            if not quiet:
                _err(
                    f"    → {report.total_findings} analysed, "
                    f"exposed={report.exposed}, uncertain={report.uncertain}, "
                    f"false_positives={report.false_positives}"
                )

        final = merge_reports(reports, dir_label)
        sys.stdout.write(json.dumps(final.model_dump(), indent=2, ensure_ascii=False) + "\n")

    asyncio.run(_run())


# ── Validate command ────────────────────────────────────────────────────


@app.command()
def validate(
    jsonl_file: str | None = typer.Argument(None, help="JSONL file from the scan command (or stdin)"),
    analyze_json: str | None = typer.Option(
        None, "--analyze", "-a", help="JSON output from the analyze command (or stdin)"
    ),
    report_md: str | None = typer.Option(
        None, "--report", "-r", help="Markdown report file (default: <jsonl_dir>/credential_scan_report.md)"
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only print errors (no OK lines)"),
):
    """Validate the final scan report for consistency and completeness.

    Cross-references the JSONL scan results with the AI analyze output and the
    markdown report. Checks internal count consistency, missing/orphan findings,
    markdown structure, and file path existence on disk.

    Exit code 0 if all validations pass, 1 if any fail.
    """
    entries = _read_jsonl(jsonl_file)
    if not entries:
        _err("No scan entries to validate.")
        raise typer.Exit(0)

    # Determine base directory from jsonl_file location
    base_dir = Path(jsonl_file).parent if jsonl_file else Path.cwd()

    # Read analyze JSON
    if analyze_json:
        analyze_path = Path(analyze_json)
        if not analyze_path.exists():
            _err(f"Analyze JSON file not found: {analyze_json}")
            raise typer.Exit(1)
        report = ScanReport.model_validate_json(analyze_path.read_text(encoding="utf-8"))
    else:
        # Try reading from stdin
        if sys.stdin.isatty():
            _err("No analyze JSON provided (use --analyze or pipe via stdin).")
            raise typer.Exit(1)
        report = ScanReport.model_validate_json(sys.stdin.read())

    # Determine markdown path
    md_path = Path(report_md) if report_md else base_dir / "credential_scan_report.md"

    all_errors: list[str] = []

    def check(name: str, errors: list[str]) -> bool:
        ok = len(errors) == 0
        if not quiet:
            status = "✓" if ok else "✗"
            _err(f"  {status} {name}")
        if not ok:
            for e in errors:
                all_errors.append(f"[{name}] {e}")
                _err(f"      {e}")
        return ok

    all_ok = True

    all_ok &= check("Internal counts", validate_counts(report))
    all_ok &= check("Cross-reference (scan ↔ analyze)", validate_cross_reference(entries, report))
    all_ok &= check("Markdown structure", validate_markdown(md_path, report))
    all_ok &= check("File paths existence", validate_paths(entries))

    if not quiet:
        _err("")
        if all_ok:
            _err("All validations passed.")
        else:
            _err(f"{len(all_errors)} validation error(s) found.")

    if not all_ok:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
