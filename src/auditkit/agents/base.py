"""Abstract base class for security analysis agents.

All specialized agents inherit from SecurityAgent and override only the
context-specific parts (name, description, system_prompt). The execution
logic (LLM call, batching, merging) lives in auditkit.agents.runner.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from auditkit.config import Settings
    from auditkit.models import ContextBlock, ScanReport


class SecurityAgent(ABC):
    """Base class for a specialized security-analysis agent.

    Subclasses must define `name`, `description` and `system_prompt`.
    They may override `format_prompt()` if they need a different input
    layout, but the output must remain a `ScanReport`.
    """

    name: str
    description: str
    system_prompt: str
    batch_size: int = 5

    @classmethod
    @abstractmethod
    def create(cls) -> SecurityAgent:
        """Factory method returning a configured agent instance."""
        ...

    def format_prompt(self, blocks: list[ContextBlock], directory: str) -> str:
        """Format context blocks into the user prompt sent to the LLM.

        The default format is tool-agnostic and works for any static-analysis
        finding. Override in subclasses for context-specific wording.
        """
        blocks_text: list[str] = []
        for i, block in enumerate(blocks, 1):
            tools = {finding.tool_name for finding in block.findings}
            rules = {finding.rule_id for finding in block.findings}
            flagged = ", ".join(str(ln) for ln in block.finding_lines)
            blocks_text.append(
                f"## Block {i}\n"
                f"**File:** `{block.file_path}` | "
                f"**Lines:** {block.start_line}-{block.end_line} | "
                f"**Flagged:** {flagged}\n"
                f"**Tools:** {', '.join(sorted(tools))} | "
                f"**Rules:** {', '.join(sorted(rules))}\n\n"
                f"**Findings:**\n"
                + "\n".join(f"- [{f.rule_id}] line {f.line_number}: {f.description}" for f in block.findings)
                + f"\n\n```\n{block.snippet}\n```\n"
            )

        return (
            f"Analyse the following security scan results from directory `{directory}`.\n\n"
            + "\n".join(blocks_text)
            + "\n\nFor each finding, classify it as false_positive, exposed, or uncertain. "
            "Include your reasoning for each classification."
        )

    async def classify(
        self,
        blocks: list[ContextBlock],
        directory: str,
        settings: Settings,
    ) -> ScanReport:
        """Run the agent on a single batch of pre-built context blocks.

        This default implementation delegates to the shared runner so each
        agent only needs to care about its prompt and criteria.
        """
        from auditkit.agents.runner import classify_batch  # noqa: PLC0415

        return await classify_batch(self, blocks, directory, settings)
