"""Abstract credential scanning providers with profile-based rule configuration.

Each provider extends BaseCredentialProvider and implements generate_audit_records()
as a generator. The factory create_providers() instantiates all providers for a given
profile.
"""

import json
import subprocess
import sys
from abc import ABC, abstractmethod
from collections.abc import Generator
from pathlib import Path

from pydantic import BaseModel

from auditkit.models import RawFinding

IGNORED_PARTS = {".venv", "venv", ".git", "node_modules", "__pycache__", ".tox", "dist", "build"}


def _is_ignored(file_path: str) -> bool:
    path = Path(file_path)
    return any(p in IGNORED_PARTS or p.endswith(".egg-info") for p in path.parts)


def _normalize_path(file_path: str) -> str:
    p = Path(file_path)
    if p.is_absolute():
        try:
            return str(p.relative_to(Path.cwd()))
        except ValueError:
            return file_path
    return str(p)


# ── Abstract base class ─────────────────────────────────────────────


class BaseCredentialProvider(ABC):
    """Abstract base for credential scanning providers.

    Subclasses implement generate_audit_records() as a generator that yields
    RawFinding objects.
    """

    def __init__(self, target_directory: str, rules: list[str] | None = None):
        self.target_directory = Path(target_directory).resolve()
        self.rules = rules or []

    @abstractmethod
    def generate_audit_records(self) -> Generator[RawFinding]:
        """Yield RawFinding objects for the target directory."""
        ...


# ── Ruff provider ───────────────────────────────────────────────────


class _RuffLocation(BaseModel):
    column: int
    row: int


class _RuffFinding(BaseModel):
    code: str
    filename: str
    location: _RuffLocation
    message: str
    url: str | None = None


RUFF_DEFAULT_RULES = ["S105", "S106", "S107"]


class RuffProvider(BaseCredentialProvider):
    """Runs ruff with credential-focused rules."""

    def generate_audit_records(self) -> Generator[RawFinding]:
        rules_to_run = self.rules if self.rules else RUFF_DEFAULT_RULES
        rules = ",".join(rules_to_run)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "ruff",
                "check",
                "--output-format",
                "json",
                "--select",
                rules,
                str(self.target_directory),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode not in (0, 1):
            raise RuntimeError(f"ruff failed: {result.stderr.strip()}")
        if not result.stdout.strip():
            return

        for item in json.loads(result.stdout):
            try:
                f = _RuffFinding.model_validate(item)
            except Exception:
                continue
            file_path = _normalize_path(f.filename)
            if _is_ignored(file_path):
                continue
            yield RawFinding(
                file_path=file_path,
                line_number=f.location.row,
                rule_id=f.code,
                description=f.message,
                tool_name="ruff",
                extra={"url": f.url} if f.url else {},
            )


# ── Bandit provider ─────────────────────────────────────────────────


BANDIT_DEFAULT_RULES = ["B105", "B106", "B107"]


class BanditProvider(BaseCredentialProvider):
    """Runs bandit with credential-focused rules."""

    def generate_audit_records(self) -> Generator[RawFinding]:
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", "-f", "json", "-l", "-i", str(self.target_directory)],
            capture_output=True,
            text=True,
        )
        if result.returncode not in (0, 1):
            raise RuntimeError(f"bandit failed: {result.stderr.strip()}")
        if not result.stdout.strip():
            return

        raw_results: list[dict] = json.loads(result.stdout).get("results", [])
        rules_to_run = self.rules if self.rules else BANDIT_DEFAULT_RULES
        for item in raw_results:
            test_id = item.get("test_id", "")
            if rules_to_run and test_id not in rules_to_run:
                continue
            filename = item.get("filename", "")
            file_path = _normalize_path(filename)
            if _is_ignored(file_path):
                continue
            yield RawFinding(
                file_path=file_path,
                line_number=item["line_number"],
                rule_id=test_id,
                description=item.get("issue_text", ""),
                tool_name="bandit",
                extra={
                    "confidence": item.get("issue_confidence", ""),
                    "severity": item.get("issue_severity", ""),
                    "more_info": item.get("more_info", ""),
                },
            )


# ── Detect-secrets provider ─────────────────────────────────────────


class DetectSecretsProvider(BaseCredentialProvider):
    """Runs detect-secrets against the target directory."""

    def generate_audit_records(self) -> Generator[RawFinding]:
        result = subprocess.run(
            [sys.executable, "-m", "detect_secrets", "scan", "--all-files", str(self.target_directory)],
            capture_output=True,
            text=True,
        )
        if result.returncode not in (0, 1):
            raise RuntimeError(f"detect-secrets failed: {result.stderr.strip()}")
        if not result.stdout.strip():
            return

        raw_results: dict = json.loads(result.stdout).get("results", {})
        for filename, entries in raw_results.items():
            file_path = _normalize_path(filename)
            if _is_ignored(file_path):
                continue
            for entry in entries:
                yield RawFinding(
                    file_path=file_path,
                    line_number=entry["line_number"],
                    rule_id=entry.get("type", "Secret"),
                    description=entry.get("type", "Secret detected"),
                    tool_name="detect-secrets",
                    extra={
                        "hashed_secret": entry.get("hashed_secret", ""),
                        "is_verified": entry.get("is_verified", False),
                    },
                )


# ── Registry & factory ──────────────────────────────────────────────


AVAILABLE_PROVIDERS: dict[str, type[BaseCredentialProvider]] = {
    "ruff": RuffProvider,
    "bandit": BanditProvider,
    "detect-secrets": DetectSecretsProvider,
}

PROFILE_RULES: dict[str, dict[str, list[str]]] = {
    "secret-scan": {
        "ruff": ["S105", "S106", "S107"],
        "bandit": ["B105", "B106", "B107"],
        "detect-secrets": [],
    },
}


def create_providers(
    directory: str,
    profile: str = "secret-scan",
) -> list[BaseCredentialProvider]:
    """Instantiate all registered providers with rules from the given profile."""
    if profile not in PROFILE_RULES:
        available = ", ".join(PROFILE_RULES)
        raise ValueError(f"Unknown profile '{profile}'. Available: {available}")

    profile_rules = PROFILE_RULES[profile]
    providers: list[BaseCredentialProvider] = []
    for name, cls in AVAILABLE_PROVIDERS.items():
        rules = profile_rules.get(name, [])
        providers.append(cls(directory, rules=rules))
    return providers
