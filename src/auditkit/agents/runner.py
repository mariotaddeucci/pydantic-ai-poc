"""Shared execution logic for all security agents.

Handles LLM setup, per-batch classification and report merging. Agent
subclasses only define prompts and classification criteria.
Settings are passed as a parameter rather than imported from a global
singleton.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIChatModelSettings
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.usage import UsageLimits

from auditkit.models import ContextBlock, ScanDeps, ScanReport

if TYPE_CHECKING:
    from auditkit.config import Settings

    from .base import SecurityAgent


def _openai_model(settings: Settings) -> OpenAIChatModel:
    if settings.openai_base_url:
        provider = OpenAIProvider(api_key=settings.openai_api_key, base_url=settings.openai_base_url)
    else:
        provider = OpenAIProvider(api_key=settings.openai_api_key)
    return OpenAIChatModel(settings.openai_model_light, provider=provider)


def _build_agent(agent: SecurityAgent) -> Agent[ScanDeps, ScanReport]:
    return Agent(
        deps_type=ScanDeps,
        output_type=ScanReport,
        system_prompt=agent.system_prompt,
        defer_model_check=True,
    )


async def classify_batch(
    agent: SecurityAgent,
    blocks: list[ContextBlock],
    directory: str,
    settings: Settings,
) -> ScanReport:
    """Run a single batch of context blocks through the given agent."""
    pydantic_agent = _build_agent(agent)
    prompt = agent.format_prompt(blocks, directory)
    deps = ScanDeps(directory=directory, blocks=blocks)

    result = await pydantic_agent.run(
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
