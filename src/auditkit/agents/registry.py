"""Registry of available security analysis agents.

New agents are registered here by adding their class to AVAILABLE_AGENTS.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from auditkit.agents.base import SecurityAgent


_AVAILABLE: dict[str, type[SecurityAgent]] | None = None


def _load_agents() -> dict[str, type[SecurityAgent]]:
    """Lazy-load agent classes to avoid circular imports."""
    from auditkit.agents.contexts.credential import CredentialAgent  # noqa: PLC0415
    from auditkit.agents.contexts.dependency import DependencyAgent  # noqa: PLC0415
    from auditkit.agents.contexts.injection import InjectionAgent  # noqa: PLC0415

    return {
        CredentialAgent.name: CredentialAgent,
        InjectionAgent.name: InjectionAgent,
        DependencyAgent.name: DependencyAgent,
    }


def _ensure_loaded() -> dict[str, type[SecurityAgent]]:
    global _AVAILABLE  # noqa: PLW0603
    if _AVAILABLE is None:
        _AVAILABLE = _load_agents()
    return _AVAILABLE


def get_agent(name: str) -> type[SecurityAgent]:
    """Return the agent class registered under `name`."""
    available = _ensure_loaded()
    if name not in available:
        names = ", ".join(sorted(available))
        raise ValueError(f"Unknown agent '{name}'. Available: {names}")
    return available[name]


def list_agents() -> list[str]:
    """Return the names of all registered agents."""
    return sorted(_ensure_loaded())


AVAILABLE_AGENTS: dict[str, type[SecurityAgent]] = _ensure_loaded()
