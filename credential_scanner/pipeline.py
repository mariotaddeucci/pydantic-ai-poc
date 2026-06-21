"""Central orchestrator for the credential scanner pipeline.

Phases:
  1. producers    → RawFinding[] (scan directory with CLI tools)
  2. report_gen   → ContextBlock[] → markdown report saved to disk
  3. agent        → classify ContextBlocks in batches → ScanReport[]
  4. merge + save → append agent analysis to markdown

Usage:
  uv run python -m credential_scanner.pipeline <directory>
  uv run python credential_scanner/pipeline.py <directory>
"""

import asyncio
import sys
from pathlib import Path

# Ensure project root is importable when running as script
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from credential_scanner.report_generator import (
    append_analysis_to_markdown,
    build_context_blocks,
    build_markdown_report,
)
from credential_scanner.producers import TOOL_RUNNERS
from credential_scanner.models import RawFinding, ScanReport
from credential_scanner.agent_classifier import (
    BATCH_SIZE,
    classify_batch,
    merge_reports,
)


async def run(directory: str) -> str | None:
    """Run the full pipeline. Returns path to markdown report or None if clean."""

    # ── Phase 1: producers (scan) ──────────────────────────────────
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
        return None

    # ── Phase 2: report generator ─────────────────────────────────
    tools_used = [t[0] for t in TOOL_RUNNERS]
    global_blocks = build_context_blocks(all_findings)
    md_path = Path(directory) / "credential_scan_report.md"
    md_content = build_markdown_report(global_blocks, directory, tools_used)
    md_path.write_text(md_content, encoding="utf-8")
    print(f"\nPre-context report saved: {md_path}")
    print(f"  Files flagged: {len({b.file_path for b in global_blocks})}")
    print(f"  Context blocks: {len(global_blocks)}")

    # ── Phase 3: agent classifier (batched) ───────────────────────
    files_flagged = list(dict.fromkeys(f.file_path for f in all_findings))
    batches = [files_flagged[i : i + BATCH_SIZE] for i in range(0, len(files_flagged), BATCH_SIZE)]
    print(f"\nBatches: {len(batches)} ({BATCH_SIZE} files each)")

    reports: list[ScanReport] = []
    for i, batch_files in enumerate(batches, 1):
        batch_set = set(batch_files)
        batch_findings = [f for f in all_findings if f.file_path in batch_set]
        batch_blocks = build_context_blocks(batch_findings)

        print(f"\n  Batch {i}/{len(batches)} — {len(batch_files)} file(s)")
        for f in batch_files:
            print(f"    {f}")

        report = await classify_batch(batch_blocks, directory)
        reports.append(report)
        print(f"    → {report.total_findings} analysed, "
              f"exposed={report.exposed}, uncertain={report.uncertain}, "
              f"false_positives={report.false_positives}")

    # ── Phase 4: merge + save ─────────────────────────────────────
    final = merge_reports(reports, directory)
    append_analysis_to_markdown(str(md_path), final)
    print(f"\nAgent analysis appended to: {md_path}")

    print(f"\n{'=' * 60}")
    print(f"FINAL SCAN REPORT — {final.directory}")
    print(f"{'=' * 60}")
    print(f"Total findings: {final.total_findings}")
    print(f"  Exposed:         {final.exposed}")
    print(f"  Uncertain:       {final.uncertain}")
    print(f"  False positives: {final.false_positives}")
    print(f"\nFull report: {md_path}")

    return str(md_path)


async def main():
    import sys as _sys

    from config import settings

    if not settings.opencode_api_key:
        print("Erro: OPENCODE_API_KEY nao definida.")
        print("Copie .env.example para .env e preencha sua chave do OpenCode Go.")
        return

    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"Scanning directory: {directory}")
    await run(directory)


if __name__ == "__main__":
    asyncio.run(main())
