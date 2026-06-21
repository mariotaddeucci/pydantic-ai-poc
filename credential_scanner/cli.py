"""CLI for credential scanner — two-step pipeline with JSONL interchange.

Commands:
  scan     Run producers, build context, output one JSONL line per finding.
  analyze  Read JSONL, run the AI agent classifier in batches, output report.
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
from credential_scanner.report_generator import build_context_blocks

app = typer.Typer(no_args_is_help=True)


@app.command()
def scan(
    directory: str = typer.Argument(".", help="Directory to scan for credentials"),
    output: str | None = typer.Option(None, "--output", "-o", help="JSONL output file (default: <dir>/scan_results.jsonl)"),
):
    """Scan a directory for hardcoded credentials.

    Runs all registered producers (ruff S105/S106/S107), builds
    context blocks (±3 non-blank lines around each finding), and
    outputs one JSONL line per finding.
    """
    print(f"Scanning: {directory}")

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

    # Build context blocks (one per file group, merged)
    blocks = build_context_blocks(all_findings)

    # Flatten blocks back into per-finding ScanEntry (one per line)
    entries: list[ScanEntry] = []
    for b in blocks:
        for f in b.findings:
            entries.append(ScanEntry(finding=f, snippet=b.snippet))

    out_path = Path(output) if output else Path(directory) / "scan_results.jsonl"
    with open(out_path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(entry.model_dump_json() + "\n")

    print(f"\nJSONL saved: {out_path} ({len(entries)} entries)")


@app.command()
def analyze(
    jsonl_file: str = typer.Argument(..., help="JSONL file from the scan command"),
    directory: str | None = typer.Option(None, "--directory", "-d", help="Override report directory label"),
):
    """Analyze JSONL scan results with the AI agent.

    Reads findings from a JSONL file, groups by file, runs the
    DeepSeek V4 Flash agent in batches of 5 files, and prints
    the final ScanReport as JSON.
    """
    if not settings.opencode_api_key:
        print("Erro: OPENCODE_API_KEY nao definida.")
        print("Copie .env.example para .env e preencha sua chave do OpenCode Go.")
        raise typer.Exit(1)

    p = Path(jsonl_file)
    if not p.exists():
        print(f"File not found: {jsonl_file}")
        raise typer.Exit(1)

    # Read JSONL
    entries: list[ScanEntry] = []
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entries.append(ScanEntry.model_validate_json(line))

    all_findings = [e.finding for e in entries]
    dir_label = directory or str(p.parent)

    print(f"Loaded {len(all_findings)} findings from {jsonl_file}")

    # Group by file and split into batches
    files_flagged = list(dict.fromkeys(f.file_path for f in all_findings))
    batches = [files_flagged[i : i + BATCH_SIZE] for i in range(0, len(files_flagged), BATCH_SIZE)]
    print(f"Files flagged: {len(files_flagged)}")
    print(f"Batches: {len(batches)} ({BATCH_SIZE} files each)")

    async def _run():
        reports: list[ScanReport] = []
        for i, batch_files in enumerate(batches, 1):
            batch_set = set(batch_files)
            batch_findings = [f for f in all_findings if f.file_path in batch_set]
            batch_blocks = build_context_blocks(batch_findings)

            print(f"\n  Batch {i}/{len(batches)} — {len(batch_files)} file(s)")
            for bf in batch_files:
                print(f"    {bf}")

            report = await classify_batch(batch_blocks, dir_label)
            reports.append(report)
            print(f"    → {report.total_findings} analysed, "
                  f"exposed={report.exposed}, uncertain={report.uncertain}, "
                  f"false_positives={report.false_positives}")

        final = merge_reports(reports, dir_label)

        # Output as JSON
        print(f"\n{'=' * 60}")
        print(json.dumps(final.model_dump(), indent=2, ensure_ascii=False))

    asyncio.run(_run())


if __name__ == "__main__":
    app()
