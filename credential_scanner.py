import json
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIChatModelSettings
from pydantic_ai.providers.openai import OpenAIProvider

from config import settings

RUFF_CREDENTIAL_RULES = [
    "S105",  # hardcoded-password-string
    "S106",  # hardcoded-password-func-arg
    "S107",  # hardcoded-password-default
]


class RuffLocation(BaseModel):
    column: int
    row: int


class RuffFinding(BaseModel):
    code: str
    filename: str
    location: RuffLocation
    message: str
    url: str | None = None


class RawFinding(BaseModel):
    file_path: str
    line_number: int
    rule_id: str
    message: str


class Assessment(str, Enum):
    FALSE_POSITIVE = "false_positive"
    EXPOSED = "exposed"
    UNCERTAIN = "uncertain"


class AnalyzedFinding(BaseModel):
    file_path: str
    line_number: int
    rule_id: str
    assessment: Assessment
    context: str = Field(description="Code block with surrounding lines for context")
    reasoning: str = Field(description="Justification for the assessment")


class ScanReport(BaseModel):
    directory: str
    total_findings: int = 0
    false_positives: int = 0
    exposed: int = 0
    uncertain: int = 0
    findings: list[AnalyzedFinding] = Field(default_factory=list)


IGNORED_DIRS = {".venv", "venv", ".git", "node_modules", "__pycache__", ".tox", "dist", "build", "*.egg-info"}


def _is_ignored(file_path: str) -> bool:
    path = Path(file_path)
    return any(p in IGNORED_DIRS or p.endswith(".egg-info") for p in path.parts)


def _run_ruff(dir_path: str) -> list[RawFinding]:
    rules = ",".join(RUFF_CREDENTIAL_RULES)
    result = subprocess.run(
        [
            "uv", "run", "ruff", "check",
            "--output-format", "json",
            "--select", rules,
            dir_path,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"ruff failed: {result.stderr.strip()}")

    if not result.stdout.strip():
        return []

    raw = json.loads(result.stdout)
    findings: list[RawFinding] = []
    for item in raw:
        try:
            finding = RuffFinding.model_validate(item)
        except Exception:
            continue
        if _is_ignored(finding.filename):
            continue
        findings.append(RawFinding(
            file_path=finding.filename,
            line_number=finding.location.row,
            rule_id=finding.code,
            message=finding.message,
        ))
    return findings


def _read_file_context(file_path: str, line_number: int, context_lines: int = 8) -> str:
    p = Path(file_path)
    if not p.exists():
        return f"[File not found: {file_path}]"

    with open(p, encoding="utf-8", errors="replace") as f:
        all_lines = f.readlines()

    start = max(0, line_number - context_lines - 1)
    end = min(len(all_lines), line_number + context_lines)

    result_lines = []
    for i in range(start, end):
        prefix = ">>> " if i == line_number - 1 else "    "
        result_lines.append(f"{prefix}{i + 1:4d}: {all_lines[i].rstrip()}")

    return "\n".join(result_lines)


@dataclass
class ScanContext:
    directory: str
    findings: list[RawFinding] = None


agent = Agent(
    deps_type=ScanContext,
    output_type=ScanReport,
    system_prompt=(
        "You are a senior security auditor specializing in credential leak detection. "
        "Your job is to analyse each finding from static analysis tools and classify them.\n\n"
        "Classification criteria:\n"
        "- **false_positive**: The value is clearly a test mock, placeholder, "
        "example from documentation, empty string, or a reference to an env var "
        "(e.g. `os.environ.get(...)`, `getenv(...)`, `Settings()`).\n"
        "- **exposed**: A real credential or secret is hardcoded in the source code "
        "with actual values that look like real tokens, passwords, or API keys.\n"
        "- **uncertain**: The context is ambiguous — it could be a real secret or a test/mock "
        "but you cannot determine with confidence from the available context.\n\n"
        "For each finding, use the `read_context` tool to get the surrounding code, "
        "then provide your assessment and reasoning."
    ),
    defer_model_check=True,
)


@agent.tool
async def get_findings(ctx: RunContext[ScanContext]) -> str:
    """Return the list of all security findings to be analysed."""
    if not ctx.deps.findings:
        return "No findings to analyse."

    lines = []
    for i, f in enumerate(ctx.deps.findings, 1):
        lines.append(f"{i}. [{f.rule_id}] {f.file_path}:{f.line_number} — {f.message}")
    return "\n".join(lines)


@agent.tool
async def read_context(
    ctx: RunContext[ScanContext], file_path: str, line_number: int
) -> str:
    """Read the surrounding code context of a finding at a specific line."""
    return _read_file_context(file_path, line_number)


async def main():
    import sys

    if not settings.opencode_api_key:
        print("Erro: OPENCODE_API_KEY nao definida.")
        print("Copie .env.example para .env e preencha sua chave do OpenCode Go.")
        return

    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"Scanning directory: {directory}")
    print(f"Running ruff with {len(RUFF_CREDENTIAL_RULES)} credential rules...")

    findings = _run_ruff(directory)
    print(f"Found {len(findings)} potential issues.")

    if not findings:
        print("No security issues found.")
        return

    provider = OpenAIProvider(
        base_url=settings.opencode_base_url,
        api_key=settings.opencode_api_key,
    )
    model = OpenAIChatModel(settings.opencode_model, provider=provider)

    deps = ScanContext(directory=directory, findings=findings)

    findings_list = "\n".join(
        f"- [{f.rule_id}] {f.file_path}:{f.line_number} — {f.message}"
        for f in findings
    )

    result = await agent.run(
        f"Analyse the following security findings found in {directory}:\n\n{findings_list}\n\n"
        "For each finding, read the context and classify it as false_positive, exposed, or uncertain.",
        deps=deps,
        model=model,
        model_settings=OpenAIChatModelSettings(
            extra_body={"thinking": {"type": "disabled"}}
        ),
    )

    report = result.output
    print(f"\n=== SCAN REPORT ===")
    print(f"Directory: {report.directory}")
    print(f"Total: {report.total_findings}")
    print(f"False positives: {report.false_positives}")
    print(f"Exposed: {report.exposed}")
    print(f"Uncertain: {report.uncertain}")
    print(f"\n--- Findings ---")
    for f in report.findings:
        print(f"\n[{f.assessment.upper()}] {f.file_path}:{f.line_number} [{f.rule_id}]")
        print(f"  Reasoning: {f.reasoning}")
        print(f"  Context:\n{f.context}")

    print(f"\nUsage: {result.usage}")


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
