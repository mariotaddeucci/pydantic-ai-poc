"""Tool adapters that produce RawFinding lists from CLI tools.

Each producer is a function (directory) -> list[RawFinding].
Add new tools by implementing a runner and registering it in TOOL_RUNNERS.
"""

import json
import subprocess
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from credential_scanner.models import RawFinding

RUFF_CREDENTIAL_RULES = [
    "S105",  # hardcoded-password-string
    "S106",  # hardcoded-password-func-arg
    "S107",  # hardcoded-password-default
]

IGNORED_PARTS = {".venv", "venv", ".git", "node_modules", "__pycache__", ".tox", "dist", "build"}


def _is_ignored(file_path: str) -> bool:
    path = Path(file_path)
    return any(p in IGNORED_PARTS or p.endswith(".egg-info") for p in path.parts)


# ── Ruff adapter ─────────────────────────────────────────────────────


class _RuffLocation(BaseModel):
    column: int
    row: int


class _RuffFinding(BaseModel):
    code: str
    filename: str
    location: _RuffLocation
    message: str
    url: str | None = None


def run_ruff(dir_path: str) -> list[RawFinding]:
    rules = ",".join(RUFF_CREDENTIAL_RULES)
    result = subprocess.run(
        ["uv", "run", "ruff", "check", "--output-format", "json", "--select", rules, dir_path],
        capture_output=True,
        text=True,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"ruff failed: {result.stderr.strip()}")
    if not result.stdout.strip():
        return []

    findings: list[RawFinding] = []
    for item in json.loads(result.stdout):
        try:
            f = _RuffFinding.model_validate(item)
        except Exception:
            continue
        if _is_ignored(f.filename):
            continue
        findings.append(RawFinding(
            file_path=f.filename,
            line_number=f.location.row,
            rule_id=f.code,
            description=f.message,
            tool_name="ruff",
            extra={"url": f.url} if f.url else {},
        ))
    return findings


# Registry of tool adapters — add new tools here
TOOL_RUNNERS: list[tuple[str, Any]] = [
    ("ruff", run_ruff),
]
