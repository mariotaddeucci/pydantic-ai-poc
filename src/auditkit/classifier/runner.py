from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIChatModelSettings
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.usage import UsageLimits

from auditkit.config import Settings
from auditkit.models import ContextBlock, ScanDeps, ScanReport


class AgentConfig:
    """Configuration for a security analysis agent."""

    def __init__(
        self,
        name: str,
        description: str,
        system_prompt: str,
        batch_size: int = 5,
    ):
        self.name = name
        self.description = description
        self.system_prompt = system_prompt
        self.batch_size = batch_size


def _format_prompt(blocks: list[ContextBlock], directory: str) -> str:
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


def _openai_model(settings: Settings) -> OpenAIChatModel:
    if settings.openai_base_url:
        provider = OpenAIProvider(api_key=settings.openai_api_key, base_url=settings.openai_base_url)
    else:
        provider = OpenAIProvider(api_key=settings.openai_api_key)
    return OpenAIChatModel(settings.openai_model_light, provider=provider)


async def classify_batch(
    config: AgentConfig,
    blocks: list[ContextBlock],
    directory: str,
    settings: Settings,
) -> ScanReport:
    """Run a batch of context blocks through an LLM agent."""
    agent = Agent(
        deps_type=ScanDeps,
        output_type=ScanReport,
        system_prompt=config.system_prompt,
        defer_model_check=True,
    )
    prompt = _format_prompt(blocks, directory)
    deps = ScanDeps(directory=directory, blocks=blocks)

    result = await agent.run(
        prompt,
        deps=deps,
        model=_openai_model(settings),
        model_settings=OpenAIChatModelSettings(extra_body={"thinking": {"type": "disabled"}}),
        usage_limits=UsageLimits(request_limit=200),
    )
    return result.output


def merge_reports(reports: list[ScanReport], directory: str) -> ScanReport:
    """Merge multiple ScanReport objects into one."""
    merged = ScanReport(directory=directory)
    for report in reports:
        merged.total_findings += report.total_findings
        merged.false_positives += report.false_positives
        merged.exposed += report.exposed
        merged.uncertain += report.uncertain
        merged.findings.extend(report.findings)
    return merged
