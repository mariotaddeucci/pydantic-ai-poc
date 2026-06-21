"""Security analysis agents.

Provides a pluggable architecture for specialized security agents that
classify pre-built scan context blocks. All agents produce a standardized
ScanReport so the rest of the pipeline stays agnostic to the agent context.
"""

from auditkit.agents.base import SecurityAgent
from auditkit.agents.registry import AVAILABLE_AGENTS, get_agent, list_agents
from auditkit.agents.runner import classify_batch, merge_reports

__all__ = [
    "AVAILABLE_AGENTS",
    "SecurityAgent",
    "classify_batch",
    "get_agent",
    "list_agents",
    "merge_reports",
]
