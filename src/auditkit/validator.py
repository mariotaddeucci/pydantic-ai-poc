"""Report validation — consistency and completeness checks.

Validates that the scan JSONL, analyze JSON, and markdown report are
internally consistent and cross-reference correctly.
"""

from pathlib import Path

from auditkit.models import ScanEntry, ScanReport


def validate_counts(report: ScanReport) -> list[str]:
    """Check that report counts are internally consistent."""
    errors: list[str] = []
    calculated_total = report.exposed + report.uncertain + report.false_positives
    if report.total_findings != calculated_total:
        errors.append(
            f"Counts mismatch: total_findings={report.total_findings} != "
            f"exposed+uncertain+false_positives={calculated_total}"
        )
    actual = len(report.findings)
    if report.total_findings != actual:
        errors.append(f"Counts mismatch: total_findings={report.total_findings} != len(findings)={actual}")
    reported_exposed = sum(1 for f in report.findings if f.assessment == "exposed")
    reported_uncertain = sum(1 for f in report.findings if f.assessment == "uncertain")
    reported_fp = sum(1 for f in report.findings if f.assessment == "false_positive")
    if report.exposed != reported_exposed:
        errors.append(f"exposed count mismatch: declared={report.exposed}, actual={reported_exposed}")
    if report.uncertain != reported_uncertain:
        errors.append(f"uncertain count mismatch: declared={report.uncertain}, actual={reported_uncertain}")
    if report.false_positives != reported_fp:
        errors.append(f"false_positives count mismatch: declared={report.false_positives}, actual={reported_fp}")
    return errors


def validate_cross_reference(scan_entries: list[ScanEntry], report: ScanReport) -> list[str]:
    """Check that every finding in the scan has a match in the analyze report and vice-versa."""
    errors: list[str] = []

    scan_keys = {(e.finding.file_path, e.finding.line_number, e.finding.rule_id) for e in scan_entries}
    analyze_keys = {(f.file_path, f.line_number, f.rule_id) for f in report.findings}

    orphans_in_analyze = analyze_keys - scan_keys
    errors.extend(
        f"Orphan in analyze (not in scan): {key[0]}:{key[1]} [{key[2]}]" for key in sorted(orphans_in_analyze)
    )

    missing_from_analyze = scan_keys - analyze_keys
    errors.extend(
        f"Missing from analyze (in scan but not classified): {key[0]}:{key[1]} [{key[2]}]"
        for key in sorted(missing_from_analyze)
    )

    return errors


def validate_markdown(md_path: Path, report: ScanReport) -> list[str]:
    """Check that the markdown report has required sections."""
    errors: list[str] = []
    if not md_path.exists():
        errors.append(f"Markdown report not found: {md_path}")
        return errors

    content = md_path.read_text(encoding="utf-8")
    if "# Credential Scan Report" not in content:
        errors.append("Markdown missing: header (# Credential Scan Report)")
    if "**Directory:**" not in content:
        errors.append("Markdown missing: directory metadata")
    if "**Tools:**" not in content:
        errors.append("Markdown missing: tools metadata")
    if "**Findings:**" not in content:
        errors.append("Markdown missing: findings count")
    if report.findings and "Análise do Agente" not in content:
        errors.append("Markdown missing: AI analysis section (Análise do Agente)")
    return errors


def validate_paths(scan_entries: list[ScanEntry]) -> list[str]:
    """Check that file paths referenced in findings exist on disk."""
    base = Path.cwd()
    errors: list[str] = []
    seen = set()
    for e in scan_entries:
        fp = e.finding.file_path
        if fp in seen:
            continue
        seen.add(fp)
        full = base / fp
        if not full.exists():
            errors.append(f"File not found: {fp}")
    return errors
