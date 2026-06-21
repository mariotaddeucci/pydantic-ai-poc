from dataclasses import dataclass
from datetime import datetime

from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIChatModelSettings
from pydantic_ai.providers.openai import OpenAIProvider

from config import settings


class ReviewResult(BaseModel):
    score: int = Field(description="Overall score from 1 to 10")
    summary: str = Field(description="Brief summary of the code review")
    issues: list[str] = Field(default_factory=list, description="List of issues found")
    suggestions: list[str] = Field(default_factory=list, description="List of improvement suggestions")


@dataclass
class CodeContext:
    language: str
    lines: int


agent = Agent(
    deps_type=CodeContext,
    output_type=ReviewResult,
    system_prompt=(
        "You are a senior code reviewer. Analyse the provided code and return a "
        "structured review with score, summary, issues, and suggestions. "
        "Use the available tools to gather information about the code."
    ),
    defer_model_check=True,
)


@agent.tool
async def count_lines(ctx: RunContext[CodeContext]) -> str:
    """Return the number of lines in the code."""
    return f"The code has {ctx.deps.lines} lines"


@agent.tool
async def detect_language(ctx: RunContext[CodeContext]) -> str:
    """Return the programming language of the code."""
    return f"The code is written in {ctx.deps.language}"


@agent.tool
async def current_timestamp() -> str:
    """Return the current date and time."""
    return datetime.now().isoformat()


async def main():
    if not settings.opencode_api_key:
        print("Erro: OPENCODE_API_KEY nao definida.")
        print("Copie .env.example para .env e preencha sua chave do OpenCode Go.")
        return

    provider = OpenAIProvider(
        base_url=settings.opencode_base_url,
        api_key=settings.opencode_api_key,
    )
    model = OpenAIChatModel(settings.opencode_model, provider=provider)

    sample_code = '''
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)
'''

    deps = CodeContext(language="python", lines=7)

    result = await agent.run(
        f"Review this code:\n```python\n{sample_code}```",
        deps=deps,
        model=model,
        model_settings=OpenAIChatModelSettings(
            extra_body={"thinking": {"type": "disabled"}}
        ),
    )

    review = result.output
    print(f"Score: {review.score}/10")
    print(f"Summary: {review.summary}")
    if review.issues:
        print(f"Issues: {review.issues}")
    if review.suggestions:
        print(f"Suggestions: {review.suggestions}")

    print(f"\nUsage: {result.usage}")


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
