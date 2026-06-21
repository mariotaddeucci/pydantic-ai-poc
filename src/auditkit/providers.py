"""Provider system with agent-driven configuration.

Each provider extends BaseCredentialProvider and implements generate_audit_records()
as an async generator. PROVIDER_REGISTRY maps names to (module, class) strings for
lazy loading. AGENT_PROFILES maps agent names to their provider configurations.
The factory create_providers() instantiates providers for a given agent.
"""

import asyncio
import importlib
import json
import sys
from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator
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

    Subclasses implement generate_audit_records() as an async generator
    that yields RawFinding objects.
    """

    def __init__(self, target_directory: str, rules: list[str] | None = None):
        self.target_directory = Path(target_directory).resolve()
        self.rules = rules or []

    @abstractmethod
    async def generate_audit_records(self) -> AsyncGenerator[RawFinding]:
        """Yield RawFinding objects for the target directory."""
        if False:  # pragma: no cover (makes the generator valid)
            yield


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

    async def generate_audit_records(self) -> AsyncGenerator[RawFinding]:
        rules_to_run = self.rules if self.rules else RUFF_DEFAULT_RULES
        rules = ",".join(rules_to_run)
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--output-format",
            "json",
            "--select",
            rules,
            str(self.target_directory),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await proc.communicate()
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"ruff failed: {stderr_bytes.decode().strip()}")
        stdout = stdout_bytes.decode()
        if not stdout.strip():
            return

        for item in json.loads(stdout):
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

    async def generate_audit_records(self) -> AsyncGenerator[RawFinding]:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "bandit",
            "-r",
            "-f",
            "json",
            "-l",
            "-i",
            str(self.target_directory),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await proc.communicate()
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"bandit failed: {stderr_bytes.decode().strip()}")
        stdout = stdout_bytes.decode()
        if not stdout.strip():
            return

        raw_results: list[dict] = json.loads(stdout).get("results", [])
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

    async def generate_audit_records(self) -> AsyncGenerator[RawFinding]:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "detect_secrets",
            "scan",
            "--all-files",
            str(self.target_directory),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await proc.communicate()
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"detect-secrets failed: {stderr_bytes.decode().strip()}")
        stdout = stdout_bytes.decode()
        if not stdout.strip():
            return

        raw_results: dict = json.loads(stdout).get("results", {})
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


PROVIDER_REGISTRY: dict[str, dict[str, str]] = {
    "ruff": {
        "module": "auditkit.providers",
        "class_name": "RuffProvider",
    },
    "bandit": {
        "module": "auditkit.providers",
        "class_name": "BanditProvider",
    },
    "detect-secrets": {
        "module": "auditkit.providers",
        "class_name": "DetectSecretsProvider",
    },
}

AGENT_PROFILES: dict[str, dict[str, dict[str, list[str]]]] = {
    "credential": {
        "ruff": {"rules": ["S105", "S106", "S107"]},
        "bandit": {"rules": ["B105", "B106", "B107"]},
        "detect-secrets": {"rules": []},
    },
    "injection": {
        "ruff": {"rules": ["S602", "S603", "S604", "S606", "S607"]},
        "bandit": {"rules": ["B601", "B602", "B603", "B604", "B608"]},
    },
    "dependency": {},
}


def create_providers(
    directory: str,
    agent: str = "credential",
    select: list[str] | None = None,
) -> list[BaseCredentialProvider]:
    """Instantiate providers configured for the given agent.

    Uses lazy imports (importlib.import_module) so provider classes are
    loaded only on demand. The select parameter filters by provider name.
    """
    if agent not in AGENT_PROFILES:
        available = ", ".join(sorted(AGENT_PROFILES))
        raise ValueError(f"Unknown agent '{agent}'. Available: {available}")

    agent_providers = AGENT_PROFILES[agent]
    providers: list[BaseCredentialProvider] = []
    for provider_name, kwargs in agent_providers.items():
        if select is not None and provider_name not in select:
            continue
        spec = PROVIDER_REGISTRY[provider_name]
        mod = importlib.import_module(spec["module"])
        cls = getattr(mod, spec["class_name"])
        providers.append(cls(directory, **kwargs))
    return providers
