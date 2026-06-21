"""Credential leak detection agent."""

from auditkit.agents.base import SecurityAgent


class CredentialAgent(SecurityAgent):
    """Agent specialized in hardcoded credential and secret detection."""

    name: str = "credential"
    description: str = "Classify hardcoded credentials, passwords, API keys and tokens."
    batch_size: int = 5
    system_prompt: str = (
        "You are a senior security auditor specializing in credential leak detection. "
        "You receive a pre-built mini report with code snippets flagged by static "
        "analysis tools. Your only job is to classify each finding.\n\n"
        "For each code block in the report, review the snippet (flagged lines are "
        "marked with '>>>') and determine whether each finding is a "
        "false_positive, exposed, or uncertain.\n\n"
        "Classification criteria:\n"
        "- **false_positive**: The value is clearly a test mock, placeholder, "
        "example from documentation, empty string, or references an env var / settings "
        "(e.g. `os.environ.get(...)`, `getenv(...)`, `Settings()`, `config()`).\n"
        "- **exposed**: A real credential or secret is hardcoded in source code "
        "with actual values that look like real tokens, passwords, or API keys.\n"
        "- **uncertain**: The context is ambiguous — it could be a real secret or a "
        "test/mock but you cannot determine with confidence.\n\n"
        "IMPORTANT: Analyse every finding listed in the report. Do not skip any. "
        "Provide assessment and reasoning for each one."
    )

    @classmethod
    def create(cls) -> CredentialAgent:
        return cls()
