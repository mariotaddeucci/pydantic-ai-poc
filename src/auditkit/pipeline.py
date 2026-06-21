"""Central orchestrator for the credential scanner pipeline.

Phases:
  1. producers    → RawFinding[] (scan directory with CLI tools)
  2. report_gen   → ContextBlock[] → merge → markdown report saved to disk
  3. agent        → classify ContextBlocks in batches → ScanReport[]
  4. merge + save → append agent analysis to markdown + validate

Usage:
  uv run python -m auditkit.pipeline <directory>
  uv run python auditkit/pipeline.py <directory>
"""

import asyncio
import json
import sys
from pathlib import Path

from auditkit.agent_classifier import (
    BATCH_SIZE,
    classify_batch,
    merge_reports,
)
from auditkit.models import RawFinding, ScanEntry, ScanReport
from auditkit.providers import create_providers
from auditkit.report_generator import (
    append_analysis_to_markdown,
    build_context_blocks,
    build_markdown_report,
    merge_context_blocks,
)


async def run(directory: str) -> str | None:
    """Run the full pipeline. Returns path to markdown report or None if clean."""

    # ── Phase 1: producers (scan) ──────────────────────────────────
    dir_path = Path(directory).resolve()
    providers = create_providers(directory)
    all_findings: list[RawFinding] = []
    for provider in providers:
        tool_name = type(provider).__name__.replace("Provider", "").lower()
        print(f"  Running {tool_name}...")
        try:
            count = 0
            for finding in provider.generate_audit_records():
                all_findings.append(finding)
                count += 1
            print(f"    {count} finding(s)")
        except Exception as e:
            print(f"    Skipped: {e}")

    print(f"\nTotal raw findings: {len(all_findings)}")
    if not all_findings:
        print("No security issues found.")
        return None

    # ── Phase 1b: persist JSONL for validation ────────────────────
    tools_used = sorted({f.tool_name for f in all_findings})
    blocks = build_context_blocks(all_findings)
    merged_blocks = merge_context_blocks(blocks)
    entries = [ScanEntry(finding=f, snippet=b.snippet) for b in merged_blocks for f in b.findings]
    jsonl_path = dir_path / "scan_results.jsonl"
    jsonl_path.write_text(
        "\n".join(e.model_dump_json() for e in entries) + "\n",
        encoding="utf-8",
    )
    print(f"JSONL saved: {jsonl_path} ({len(entries)} entries)")

    # ── Phase 2: report generator ─────────────────────────────────
    md_path = dir_path / "credential_scan_report.md"
    md_content = build_markdown_report(merged_blocks, str(directory), tools_used)
    md_path.write_text(md_content, encoding="utf-8")
    print(f"\nPre-context report saved: {md_path}")
    print(f"  Files flagged: {len({b.file_path for b in merged_blocks})}")
    print(f"  Context blocks (merged): {len(merged_blocks)}")
    print(f"  Total findings: {len(entries)}")

    # ── Phase 3: agent classifier (batched) ───────────────────────
    files_flagged = list(dict.fromkeys(f.file_path for f in all_findings))
    batches = [files_flagged[i : i + BATCH_SIZE] for i in range(0, len(files_flagged), BATCH_SIZE)]
    print(f"\nBatches: {len(batches)} ({BATCH_SIZE} files each)")

    reports: list[ScanReport] = []
    for i, batch_files in enumerate(batches, 1):
        batch_set = set(batch_files)
        batch_findings = [f for f in all_findings if f.file_path in batch_set]
        batch_blocks = build_context_blocks(batch_findings)
        batch_blocks = merge_context_blocks(batch_blocks)

        print(f"\n  Batch {i}/{len(batches)} — {len(batch_files)} file(s)")
        for f in batch_files:
            print(f"    {f}")

        report = await classify_batch(batch_blocks, str(directory))
        reports.append(report)
        print(
            f"    → {report.total_findings} analysed, "
            f"exposed={report.exposed}, uncertain={report.uncertain}, "
            f"false_positives={report.false_positives}"
        )

    # ── Phase 4: merge + save ─────────────────────────────────────
    final = merge_reports(reports, str(directory))
    append_analysis_to_markdown(str(md_path), final)
    print(f"\nAgent analysis appended to: {md_path}")

    # Persist analyze JSON for validation
    analyze_path = dir_path / "analyze_results.json"
    analyze_path.write_text(
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

    # ── Phase 5: validate ─────────────────────────────────────────
    print(f"\n{'─' * 60}")
    print("VALIDATION")
    print(f"{'─' * 60}")
    _run_validation(entries, final, md_path)

    return str(md_path)


def _run_validation(entries: list[ScanEntry], report: ScanReport, md_path: Path) -> None:
    """Inline validation — exits with code 1 if any checks fail."""
    from auditkit.validator import (
        validate_counts,
        validate_cross_reference,
        validate_markdown,
        validate_paths,
    )

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
    all_ok &= check("Markdown structure", validate_markdown(md_path, report))
    all_ok &= check("File paths existence", validate_paths(entries))

    if all_ok:
        print("  All validations passed.")
    else:
        print(f"  {len(all_errors)} validation error(s) found.")


async def main():

    from auditkit.config import settings

    if not settings.opencode_api_key:
        print("Erro: OPENCODE_API_KEY nao definida.")
        print("Copie .env.example para .env e preencha sua chave do OpenCode Go.")
        return

    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"Scanning directory: {directory}")
    await run(directory)


if __name__ == "__main__":
    asyncio.run(main())
