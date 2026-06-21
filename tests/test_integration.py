"""Integration test — runs full scan pipeline against examples and validates results.

Usage:
  uv run python -m pytest tests/test_integration.py -v
  uv run python tests/test_integration.py
"""

import json
import os
import subprocess
import sys
from collections.abc import Generator
from pathlib import Path

import pytest

EXAMPLES_DIR = Path(__file__).resolve().parent / "fixtures"
PROJECT_ROOT = Path(__file__).resolve().parent.parent

CLI_MODULE = "auditkit.cli"
CLI_CMD = [sys.executable, "-m", CLI_MODULE]


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")}
    return subprocess.run(
        [*CLI_CMD, *args],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
        env=env,
    )


def _is_api_key_set() -> bool:
    try:
        from auditkit.config import settings

        return bool(settings.opencode_api_key)
    except Exception:
        return False


def _clean_artifacts(target_dir: Path) -> None:
    for name in ("scan_results.jsonl", "credential_scan_report.md", "analyze_results.json"):
        p = target_dir / name
        if p.exists():
            p.unlink()


@pytest.fixture(autouse=True)
def clean_examples_dir() -> Generator[None]:
    _clean_artifacts(EXAMPLES_DIR)
    yield
    _clean_artifacts(EXAMPLES_DIR)


# ── Phase 1: scan ────────────────────────────────────────────────────


def test_scan_all_tools():
    """Scan examples with all providers — should find findings from every tool."""
    result = _run_cli("scan", str(EXAMPLES_DIR), "-o", str(EXAMPLES_DIR / "scan_results.jsonl"))

    assert "Total raw findings:" in result.stderr, f"stderr:\n{result.stderr}"
    assert result.returncode == 0, f"stderr:\n{result.stderr}"

    jsonl_path = EXAMPLES_DIR / "scan_results.jsonl"
    assert jsonl_path.exists(), f"JSONL not found at {jsonl_path}"

    with open(jsonl_path, encoding="utf-8") as f:
        findings = [json.loads(raw_line) for raw_line in f if raw_line.strip()]

    assert len(findings) >= 30, f"Expected >=30 findings, got {len(findings)}"

    tools = {e["finding"]["tool_name"] for e in findings}
    assert "ruff" in tools, f"ruff not in tools: {tools}"
    assert "bandit" in tools, f"bandit not in tools: {tools}"
    assert "detect-secrets" in tools, f"detect-secrets not in tools: {tools}"


def test_scan_only_ruff():
    result = _run_cli("scan", str(EXAMPLES_DIR), "--select", "ruff", "-o", str(EXAMPLES_DIR / "scan_results.jsonl"))
    assert result.returncode == 0, f"stderr:\n{result.stderr}"

    jsonl_path = EXAMPLES_DIR / "scan_results.jsonl"
    with open(jsonl_path, encoding="utf-8") as f:
        findings = [json.loads(raw_line) for raw_line in f if raw_line.strip()]

    tools = {e["finding"]["tool_name"] for e in findings}
    assert tools == {"ruff"}, f"Expected only ruff, got {tools}"


def test_scan_exclude_bandit():
    result = _run_cli("scan", str(EXAMPLES_DIR), "--exclude", "bandit", "-o", str(EXAMPLES_DIR / "scan_results.jsonl"))
    assert result.returncode == 0, f"stderr:\n{result.stderr}"

    jsonl_path = EXAMPLES_DIR / "scan_results.jsonl"
    with open(jsonl_path, encoding="utf-8") as f:
        findings = [json.loads(raw_line) for raw_line in f if raw_line.strip()]

    tools = {e["finding"]["tool_name"] for e in findings}
    assert "bandit" not in tools, f"bandit should be excluded, got {tools}"
    assert "ruff" in tools
    assert "detect-secrets" in tools


# ── Phase 2: report ──────────────────────────────────────────────────


def test_report_generation():
    """Generate markdown report from JSONL."""
    # First, create JSONL
    scan_result = _run_cli("scan", str(EXAMPLES_DIR), "-o", str(EXAMPLES_DIR / "scan_results.jsonl"))
    assert scan_result.returncode == 0

    md_path = EXAMPLES_DIR / "credential_scan_report.md"
    result = _run_cli("report", str(EXAMPLES_DIR / "scan_results.jsonl"), "-o", str(md_path), "-d", "tests/fixtures")

    assert result.returncode == 0, f"stderr:\n{result.stderr}"
    assert md_path.exists(), f"Markdown not found at {md_path}"

    content = md_path.read_text(encoding="utf-8")
    assert "# Credential Scan Report" in content
    assert "**Directory:** `tests/fixtures`" in content
    assert "**Tools:** " in content
    assert "**Files flagged:**" in content
    assert "```" in content, "Report should contain code snippets"


# ── Phase 3: validate ────────────────────────────────────────────────


def test_validate_without_analyze():
    """Validate report consistency — scan ↔ report (no AI analysis)."""
    scan_result = _run_cli("scan", str(EXAMPLES_DIR), "-o", str(EXAMPLES_DIR / "scan_results.jsonl"))
    assert scan_result.returncode == 0

    md_path = EXAMPLES_DIR / "credential_scan_report.md"
    report_result = _run_cli(
        "report", str(EXAMPLES_DIR / "scan_results.jsonl"), "-o", str(md_path), "-d", "tests/fixtures"
    )
    assert report_result.returncode == 0

    # Without -a, validate will complain about no analyze JSON (stdin is a tty here)
    result = _run_cli("validate", str(EXAMPLES_DIR / "scan_results.jsonl"), "-r", str(md_path))
    assert result.returncode == 1, f"Expected exit 1 without analyze JSON, got {result.returncode}"
    assert "No analyze JSON" in result.stderr, f"Unexpected: {result.stderr[:200]}"


@pytest.mark.skipif(not _is_api_key_set(), reason="OPENCODE_API_KEY not set")
def test_full_pipeline_with_ai():
    """Run full pipeline including AI classification (requires API key)."""
    import asyncio

    from auditkit.pipeline import run as pipeline_run

    report_path = asyncio.run(pipeline_run(str(EXAMPLES_DIR)))
    if report_path:
        assert Path(report_path).exists(), f"Report not found: {report_path}"
        content = Path(report_path).read_text(encoding="utf-8")
        assert "Análise do Agente" in content
    else:
        pytest.skip("No findings — nothing to validate")


# ── Profile validation ───────────────────────────────────────────────


def test_profile_secret_scan_uses_correct_rules():
    """Verify secret-scan profile loads correct rules for each provider."""
    from auditkit.providers import PROFILE_RULES

    rules = PROFILE_RULES["secret-scan"]
    assert rules["ruff"] == ["S105", "S106", "S107"]
    assert rules["bandit"] == ["B105", "B106", "B107"]
    assert rules["detect-secrets"] == []


def test_provider_instantiation_with_rules():
    from auditkit.providers import BanditProvider, RuffProvider

    rp = RuffProvider(".", rules=["S105"])
    assert rp.rules == ["S105"]
    assert str(rp.target_directory) == str(Path(".").resolve())

    bp = BanditProvider(".", rules=["B105", "B301"])
    assert bp.rules == ["B105", "B301"]


def test_provider_uses_default_rules_when_none():
    from auditkit.providers import RuffProvider

    rp = RuffProvider(".", rules=[])
    # generate_audit_records falls back to RUFF_DEFAULT_RULES when rules is empty
    assert rp.rules == []


# ── CLI entry point ───────────────────────────────────────────────────


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
