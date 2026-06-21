"""Vulnerable dependency detection agent (skeleton)."""

from auditkit.agents.base import SecurityAgent


class DependencyAgent(SecurityAgent):
    """Agent specialized in vulnerable or outdated dependencies.

    This is a skeleton implementation. Replace the system_prompt and, if needed,
    the format_prompt() method with context-specific criteria.
    """

    name: str = "dependency"
    description: str = "Classify vulnerable, outdated or suspicious dependencies."
    batch_size: int = 5
    system_prompt: str = (
        "You are a senior security auditor specializing in dependency risk. "
        "You receive a pre-built mini report with dependency entries flagged by static "
        "analysis tools. Your only job is to classify each finding.\n\n"
        "For each entry, review the provided context and determine whether each "
        "finding is a false_positive, exposed, or uncertain.\n\n"
        "Classification criteria:\n"
        "- **false_positive**: The dependency version is not affected by the "
        "reported issue, or the finding is a test-only dependency.\n"
        "- **exposed**: The dependency has a known vulnerability that affects the "
        "reported version and the project uses it in production code.\n"
        "- **uncertain**: The impact is unclear because version constraints, usage "
        "context or exploitability cannot be confirmed.\n\n"
        "IMPORTANT: Analyse every finding listed in the report. Do not skip any. "
        "Provide assessment and reasoning for each one."
    )

    @classmethod
    def create(cls) -> DependencyAgent:
        return cls()
