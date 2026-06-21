"""Tool adapters that produce RawFinding lists — thin wrappers delegating to providers.

Each wrapper uses the create_providers factory to instantiate the right provider
for a given agent. Defaults to "credential" for backward compatibility.
"""

from typing import Any

from auditkit.models import RawFinding
from auditkit.providers import create_providers


async def _collect(dir_path: str, agent: str = "credential", select: str | None = None) -> list[RawFinding]:
    """Collect all findings from a provider into a list."""
    providers = create_providers(dir_path, agent=agent, select=[select] if select else None)
    if not providers:
        return []
    return [f async for f in providers[0].generate_audit_records()]


async def run_ruff(dir_path: str) -> list[RawFinding]:
    return await _collect(dir_path, select="ruff")


async def run_bandit(dir_path: str) -> list[RawFinding]:
    return await _collect(dir_path, select="bandit")


async def run_detect_secrets(dir_path: str) -> list[RawFinding]:
    return await _collect(dir_path, select="detect-secrets")


# Registry of tool adapters — add new tools here
TOOL_RUNNERS: list[tuple[str, Any]] = [
    ("ruff", run_ruff),
    ("bandit", run_bandit),
    ("detect-secrets", run_detect_secrets),
]
