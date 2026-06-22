"""Provider registry, agent profiles, and factory."""

from __future__ import annotations

import importlib
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from auditkit.scanner.base import BaseCredentialProvider

PROVIDER_REGISTRY: dict[str, dict[str, str]] = {
    "ruff": {"module": "auditkit.scanner.ruff", "class_name": "RuffProvider"},
    "bandit": {"module": "auditkit.scanner.bandit", "class_name": "BanditProvider"},
    "detect-secrets": {"module": "auditkit.scanner.detect_secrets", "class_name": "DetectSecretsProvider"},
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


def filter_provider_names(select: str | None, exclude: str | None, agent: str) -> list[str]:
    """Apply --select / --exclude filters to provider names for a given agent."""
    available = set(AGENT_PROFILES.get(agent, {}))

    selected = {s.strip() for s in select.split(",")} if select else None
    excluded = {s.strip() for s in exclude.split(",")} if exclude else set()

    if selected is not None and excluded:
        print("Error: --select and --exclude are mutually exclusive.", file=sys.stderr)
        raise SystemExit(2)

    if selected is not None:
        invalid = selected - available
        if invalid:
            print(f"Unknown tool(s): {', '.join(sorted(invalid))}", file=sys.stderr)
            raise SystemExit(2)
        return [n for n in available if n in selected]
    return [n for n in available if n not in excluded]


def create_providers(
    directory: str,
    agent: str = "credential",
    select: list[str] | None = None,
) -> list[BaseCredentialProvider]:
    """Instantiate providers configured for the given agent.

    Uses lazy imports so provider classes are loaded only on demand.
    The select parameter filters by provider name.
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
