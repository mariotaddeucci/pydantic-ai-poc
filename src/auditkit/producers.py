"""Tool adapters that produce RawFinding lists — thin wrappers delegating to providers.

Backward-compatible wrapper functions run_ruff / run_bandit / run_detect_secrets
delegate to the provider classes in auditkit.providers.
"""

from typing import Any

from auditkit.models import RawFinding
from auditkit.providers import (
    BanditProvider,
    DetectSecretsProvider,
    RuffProvider,
)


def _collect(provider) -> list[RawFinding]:
    """Collect all findings from a provider generator into a list."""
    return list(provider.generate_audit_records())


def run_ruff(dir_path: str) -> list[RawFinding]:
    return _collect(RuffProvider(dir_path))


def run_bandit(dir_path: str) -> list[RawFinding]:
    return _collect(BanditProvider(dir_path))


def run_detect_secrets(dir_path: str) -> list[RawFinding]:
    return _collect(DetectSecretsProvider(dir_path))


# Registry of tool adapters — add new tools here
TOOL_RUNNERS: list[tuple[str, Any]] = [
    ("ruff", run_ruff),
    ("bandit", run_bandit),
    ("detect-secrets", run_detect_secrets),
]
