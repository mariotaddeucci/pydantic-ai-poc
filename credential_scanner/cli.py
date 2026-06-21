"""CLI for credential scanner — three-step pipeline with JSONL interchange.

Commands:
  scan     Run producers, build context, output one JSONL line per finding.
  report   Read JSONL, generate a markdown report with findings and code context.
  analyze  Read JSONL, run the AI agent classifier in batches, output JSON report.
"""

import asyncio
import json
import sys
from pathlib import Path

import typer

# Ensure project root is importable when running as script
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from config import settings
from credential_scanner.agent_classifier import BATCH_SIZE, classify_batch, merge_reports
from credential_scanner.models import RawFinding, ScanEntry, ScanReport
from credential_scanner.producers import TOOL_RUNNERS
from credential_scanner.report_generator import build_context_blocks, build_markdown_report

app = typer.Typer(no_args_is_help=True)


def _err(msg: str = "") -> None:
    """Print to stderr."""
    typer.echo(msg, err=True)


@app.command()
def scan(
    directory: str = typer.Argument(".", help="Directory to scan for credentials"),
    output: str | None = typer.Option(None, "--output", "-o", help="JSONL output file (default: stdout)"),
):
    """Scan a directory for hardcoded credentials.

    Runs all registered producers (ruff S105/S106/S107), builds
    context blocks (±3 non-blank lines around each finding), and
    outputs one JSONL line per finding.
    """
    _err(f"Scanning: {directory}")

    all_findings: list[RawFinding] = []
    for tool_name, runner in TOOL_RUNNERS:
        _err(f"  Running {tool_name}...")
        try:
            findings = runner(directory)
            _err(f"    {len(findings)} finding(s)")
            all_findings.extend(findings)
        except Exception as e:
            _err(f"    Skipped: {e}")

    _err(f"Total raw findings: {len(all_findings)}")
    if not all_findings:
        _err("No security issues found.")
        return

    # Build context blocks (one per file group, merged)
    blocks = build_context_blocks(all_findings)

    # Flatten blocks back into per-finding ScanEntry (one per line)
    entries: list[ScanEntry] = []
    for b in blocks:
        for f in b.findings:
            entries.append(ScanEntry(finding=f, snippet=b.snippet))

    # Write JSONL — to file or stdout
    lines = "\n".join(e.model_dump_json() for e in entries) + "\n"
    if output:
        Path(output).write_text(lines, encoding="utf-8")
        _err(f"JSONL saved: {output} ({len(entries)} entries)")
    else:
        sys.stdout.write(lines)
        _err(f"JSONL written to stdout ({len(entries)} entries)")


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
        for line in source:
            line = line.strip()
            if not line:
                continue
            entries.append(ScanEntry.model_validate_json(line))
    return entries


@app.command()
def report(
    jsonl_file: str | None = typer.Argument(None, help="JSONL file from the scan command (or stdin)"),
    output: str | None = typer.Option(None, "--output", "-o", help="Markdown output file (default: <jsonl_dir>/credential_scan_report.md)"),
    directory: str | None = typer.Option(None, "--directory", "-d", help="Directory label in the report header"),
):
    """Generate a markdown report from JSONL scan results.

    Reads findings from a JSONL file (or stdin), rebuilds context blocks,
    and exports a markdown report with code snippets for each finding.
    No AI agent is invoked — this is the first-level human review report.
    """
    entries = _read_jsonl(jsonl_file)
    all_findings = [e.finding for e in entries]
    dir_label = directory or (str(Path(jsonl_file).parent) if jsonl_file else ".")

    if not all_findings:
        _err("No findings to report.")
        return

    # Rebuild context blocks from findings
    blocks = build_context_blocks(all_findings)
    tools = sorted({f.tool_name for f in all_findings})
    md_content = build_markdown_report(blocks, dir_label, tools)

    out_path = Path(output) if output else Path(dir_label) / "credential_scan_report.md"
    out_path.write_text(md_content, encoding="utf-8")
    _err(f"Report saved: {out_path}")
    _err(f"  Files flagged: {len({b.file_path for b in blocks})}")
    _err(f"  Context blocks: {len(blocks)}")
    _err(f"  Findings: {len(all_findings)}")


@app.command()
def analyze(
    jsonl_file: str | None = typer.Argument(None, help="JSONL file from the scan command (or stdin)"),
    directory: str | None = typer.Option(None, "--directory", "-d", help="Override report directory label"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress status output, print only JSON"),
):
    """Analyze JSONL scan results with the AI agent.

    Reads findings from a JSONL file (or stdin), groups by file, runs the
    DeepSeek V4 Flash agent in batches of 5 files, and prints the final
    ScanReport as JSON to stdout.
    """
    if not settings.opencode_api_key:
        _err("Erro: OPENCODE_API_KEY nao definida.")
        _err("Copie .env.example para .env e preencha sua chave do OpenCode Go.")
        raise typer.Exit(1)

    entries = _read_jsonl(jsonl_file)
    all_findings = [e.finding for e in entries]
    dir_label = directory or (str(Path(jsonl_file).parent) if jsonl_file else ".")

    if not quiet:
        _err(f"Loaded {len(all_findings)} findings")

    # Group by file and split into batches
    files_flagged = list(dict.fromkeys(f.file_path for f in all_findings))
    batches = [files_flagged[i : i + BATCH_SIZE] for i in range(0, len(files_flagged), BATCH_SIZE)]
    if not quiet:
        _err(f"Files flagged: {len(files_flagged)}")
        _err(f"Batches: {len(batches)} ({BATCH_SIZE} files each)")

    async def _run():
        reports: list[ScanReport] = []
        for i, batch_files in enumerate(batches, 1):
            batch_set = set(batch_files)
            batch_findings = [f for f in all_findings if f.file_path in batch_set]
            batch_blocks = build_context_blocks(batch_findings)

            if not quiet:
                _err(f"  Batch {i}/{len(batches)} — {len(batch_files)} file(s)")
                for bf in batch_files:
                    _err(f"    {bf}")

            report = await classify_batch(batch_blocks, dir_label)
            reports.append(report)
            if not quiet:
                _err(f"    → {report.total_findings} analysed, "
                      f"exposed={report.exposed}, uncertain={report.uncertain}, "
                      f"false_positives={report.false_positives}")

        final = merge_reports(reports, dir_label)
        # Output JSON to stdout
        sys.stdout.write(json.dumps(final.model_dump(), indent=2, ensure_ascii=False) + "\n")

    asyncio.run(_run())


if __name__ == "__main__":
    app()
