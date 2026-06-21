"""Registry of available security analysis agents.

New agents are registered here by adding their class to the lazy-loaded
dictionary.  No module-level global state is used — _load_agents() is
called on demand and cached via functools.lru_cache.
"""

import functools
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from auditkit.agents.base import SecurityAgent


@functools.lru_cache(maxsize=1)
def _load_agents() -> dict[str, type[SecurityAgent]]:
    """Lazy-load agent classes to avoid circular imports.

    Result is cached via lru_cache so subsequent calls return instantly.
    """
    from auditkit.agents.contexts.credential import CredentialAgent  # noqa: PLC0415
    from auditkit.agents.contexts.dependency import DependencyAgent  # noqa: PLC0415
    from auditkit.agents.contexts.injection import InjectionAgent  # noqa: PLC0415

    return {
        CredentialAgent.name: CredentialAgent,
        InjectionAgent.name: InjectionAgent,
        DependencyAgent.name: DependencyAgent,
    }


def get_agent(name: str) -> type[SecurityAgent]:
    """Return the agent class registered under `name`."""
    available = _load_agents()
    if name not in available:
        names = ", ".join(sorted(available))
        raise ValueError(f"Unknown agent '{name}'. Available: {names}")
    return available[name]


def list_agents() -> list[str]:
    """Return the names of all registered agents."""
    return sorted(_load_agents())
