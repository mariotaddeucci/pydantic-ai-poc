"""Injection-flaw detection agent (skeleton)."""

from auditkit.agents.base import SecurityAgent


class InjectionAgent(SecurityAgent):
    """Agent specialized in injection vulnerabilities (SQL, command, etc.).

    This is a skeleton implementation. Replace the system_prompt and, if needed,
    the format_prompt() method with context-specific criteria.
    """

    name: str = "injection"
    description: str = "Classify SQL injection, command injection and similar injection flaws."
    batch_size: int = 5
    system_prompt: str = (
        "You are a senior security auditor specializing in injection vulnerabilities. "
        "You receive a pre-built mini report with code snippets flagged by static "
        "analysis tools. Your only job is to classify each finding.\n\n"
        "For each code block in the report, review the snippet (flagged lines are "
        "marked with '>>>') and determine whether each finding is a "
        "false_positive, exposed, or uncertain.\n\n"
        "Classification criteria:\n"
        "- **false_positive**: The flagged code uses proper parameterization, "
        "sanitization, or the value is hardcoded and safe.\n"
        "- **exposed**: User input is concatenated into queries, commands or "
        "eval-like calls without adequate sanitization.\n"
        "- **uncertain**: The context is ambiguous and you cannot determine "
        "whether the input is properly sanitized.\n\n"
        "IMPORTANT: Analyse every finding listed in the report. Do not skip any. "
        "Provide assessment and reasoning for each one."
    )

    @classmethod
    def create(cls) -> InjectionAgent:
        return cls()
