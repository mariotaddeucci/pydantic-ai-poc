"""AI agent that classifies credential findings.

Receives pre-built ContextBlocks, formats a prompt, and runs the
pydantic-ai agent to produce a ScanReport with classifications.
"""

from dataclasses import dataclass

from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIChatModelSettings
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.usage import UsageLimits

from config import settings
from credential_scanner.models import ContextBlock, ScanReport

BATCH_SIZE = 5


@dataclass
class ScanDeps:
    directory: str
    blocks: list[ContextBlock]


agent = Agent(
    deps_type=ScanDeps,
    output_type=ScanReport,
    system_prompt=(
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
    ),
    defer_model_check=True,
)


def _format_prompt(blocks: list[ContextBlock], directory: str) -> str:
    blocks_text: list[str] = []
    for i, b in enumerate(blocks, 1):
        tools = {f.tool_name for f in b.findings}
        rules = {f.rule_id for f in b.findings}
        flagged = ", ".join(str(ln) for ln in b.finding_lines)
        blocks_text.append(
            f"## Block {i}\n"
            f"**File:** `{b.file_path}` | **Lines:** {b.start_line}-{b.end_line} | "
            f"**Flagged:** {flagged}\n"
            f"**Tools:** {', '.join(sorted(tools))} | **Rules:** {', '.join(sorted(rules))}\n\n"
            f"**Findings:**\n" +
            "\n".join(f"- [{f.rule_id}] line {f.line_number}: {f.description}" for f in b.findings) +
            f"\n\n```\n{b.snippet}\n```\n"
        )
    return (
        f"Analyse the following security scan results from directory `{directory}`.\n\n"
        + "\n".join(blocks_text) +
        "\n\nFor each finding, classify it as false_positive, exposed, or uncertain. "
        "Include your reasoning for each classification."
    )


async def classify_batch(
    blocks: list[ContextBlock],
    directory: str,
) -> ScanReport:
    """Run the agent on a single batch of pre-built context blocks."""
    provider = OpenAIProvider(
        base_url=settings.opencode_base_url,
        api_key=settings.opencode_api_key,
    )
    model = OpenAIChatModel(settings.opencode_model_light, provider=provider)

    prompt = _format_prompt(blocks, directory)
    deps = ScanDeps(directory=directory, blocks=blocks)

    result = await agent.run(
        prompt,
        deps=deps,
        model=model,
        model_settings=OpenAIChatModelSettings(
            extra_body={"thinking": {"type": "disabled"}}
        ),
        usage_limits=UsageLimits(request_limit=200),
    )
    return result.output


def merge_reports(reports: list[ScanReport], directory: str) -> ScanReport:
    merged = ScanReport(directory=directory)
    for r in reports:
        merged.total_findings += r.total_findings
        merged.false_positives += r.false_positives
        merged.exposed += r.exposed
        merged.uncertain += r.uncertain
        merged.findings.extend(r.findings)
    return merged
