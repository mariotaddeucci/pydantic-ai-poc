# AGENTS.md

## Overview

**auditkit** — standardized scanner agents for credential and security auditing. Built with pydantic-ai + Typer. Runs static analysis tools (ruff, bandit, detect-secrets), merges overlapping findings into consolidated context blocks, then optionally classifies them via AI through any OpenAI-compatible API.

## Commands

```bash
# Scan directory (default: credential agent → ruff + bandit + detect-secrets)
uv run python -m auditkit.cli scan <dir>

# Scan with a specific agent (credential / injection / dependency)
uv run python -m auditkit.cli scan <dir> --agent injection

# Generate markdown report from JSONL (title matches agent)
uv run python -m auditkit.cli report <jsonl_file> --agent injection

# AI classification (requires .env with OPENAI_API_KEY)
uv run python -m auditkit.cli analyze <jsonl_file> --agent injection

# Full pipeline: scan → report → classify → validate
uv run python -m auditkit.pipeline <dir> --agent injection

# Validate report integrity
uv run python -m auditkit.cli validate <jsonl_file> -a analyze_results.json -r report.md

# Scan with only specific tools (filtered from the agent's providers)
uv run python -m auditkit.cli scan . --agent credential --select ruff,detect-secrets
uv run python -m auditkit.cli scan . --agent credential --exclude bandit

# Run integration tests
uv run python -m pytest tests/ -v
```

## Setup

```bash
cp .env.example .env    # then edit .env with OPENAI_API_KEY
uv sync
uv run pre-commit install
```

Required env vars: `OPENAI_API_KEY`. Optional: `OPENAI_BASE_URL` (defaults to the official OpenAI endpoint), `OPENAI_MODEL` (default `gpt-4o`), `OPENAI_MODEL_LIGHT` (default `gpt-4o-mini`), `OPENAI_DEFAULT_AGENT` (default `credential`). Loaded via `auditkit/config.py` (pydantic-settings from `.env`). Each Typer command calls `Settings()` directly — no global singleton.

## Architecture

```
src/auditkit/
  config.py           # pydantic-settings (loads .env), no module-level instance
  models.py           # Pydantic models: RawFinding, ContextBlock, ScanEntry, ScanReport, AnalyzedFinding, ScanDeps

  scanner/            # Phase 1: static analysis tools
    __init__.py       # PROVIDER_REGISTRY, AGENT_PROFILES, create_providers(), filter_provider_names()
    base.py           # BaseCredentialProvider ABC + _is_ignored / _normalize_path helpers
    ruff.py           # RuffProvider — runs ruff with --select S105,S106,S107
    bandit.py         # BanditProvider — runs bandit with -l -i flags
    detect_secrets.py # DetectSecretsProvider — runs detect-secrets scan --all-files

  reporter/           # Phase 2: context building and markdown reports
    context.py        # build_context_blocks() + merge_context_blocks() with ±2 line merging
    markdown.py       # build_markdown_report() + append_analysis_to_markdown()

  classifier/         # Phase 3: AI classification
    runner.py         # classify_batch() — shared LLM execution via pydantic-ai
    prompts.py        # AGENTS dict: system_prompts + get_agent() + list_agents()

  cli.py              # Typer app: scan, report, analyze, validate commands
  pipeline.py         # Orchestrator: scan → report → classify → validate
  validator.py        # Async report validation: counts, cross-reference, markdown structure, file paths
```

## Key design decisions

- **Flat pipeline flow**: `scanner/` → `reporter/` → `classifier/` reflects the actual execution sequence. No architectural layering that doesn't correspond to real phases.
- **No ABC for agents**: Agents are `AgentConfig` instances (dataclass-like) with `name`, `description`, `system_prompt`, and `batch_size`. The `SecurityAgent` ABC and its class hierarchy were removed — the only variation between agents was their prompt, which is now a dictionary entry in `prompts.py`.
- **No dead wrappers**: `producers.py` and `agent_classifier.py` were removed — they only re-exported or delegated without adding logic.
- **Provider abstraction**: `BaseCredentialProvider` ABC with `async def generate_audit_records() -> AsyncGenerator[RawFinding]`. New providers subclass it and register in `PROVIDER_REGISTRY`.
- **JSONL as interchange format**: `scan` writes `scan_results.jsonl`, `report`/`analyze`/`validate` read it.
- **Block merging**: `merge_context_blocks()` consolidates overlapping (±2 line gap) context blocks from different tools. Same-line findings from ruff + bandit + detect-secrets appear in one merged block with multiple `>>>` markers.
- **Normalized paths**: `_normalize_path()` converts all tool output paths to relative paths from cwd.
- **Agent profiles**: `AGENT_PROFILES` dict maps agent names (e.g. `"credential"`, `"injection"`, `"dependency"`) to per-provider kwargs. `create_providers(dir, agent)` factory instantiates all providers.
- **Async everywhere**: All I/O (subprocess, file reads/writes) is async. Sync Typer commands wrap async implementations with `asyncio.run()`. Providers use `asyncio.create_subprocess_exec`. File I/O uses `asyncio.to_thread`.
- **No global state**: `Settings()` is created per-command invocation. No global singleton, no DI container.
- **Simplified CLI**: Commands are silent on success. Output goes to stdout/JSONL. Errors are logged to stderr as structured JSON.

## Adding a new scanner tool

1. Create `scanner/yourtool.py` — subclass `BaseCredentialProvider`, implement `generate_audit_records()`
2. Add to `PROVIDER_REGISTRY` in `scanner/__init__.py`
3. Add configuration in `AGENT_PROFILES` for each agent that should use the tool

## Adding a new classifier agent

1. Add a new `AgentConfig(...)` entry to `AGENTS` dict in `classifier/prompts.py`
2. If the agent needs different scanner tools, configure them in `AGENT_PROFILES` in `scanner/__init__.py`

## Caveats

- Python 3.14 minimum.
- Package manager is **uv**. All commands prefixed with `uv run`.
- `uv.lock` is gitignored — each developer generates their own.
- `**/*_scan_report.md`, `**/scan_results.jsonl`, `**/analyze_results.json` are gitignored.
- `bandit` provider uses `-l -i` flags (LOW severity + LOW confidence) to include B105-B107 password rules.
- `detect-secrets` scans all files including generated reports; scan output files may appear as false findings in subsequent scans.
- Typer (v0.26.7) does not have a built-in `Depends` — DI is purely functional (create-and-pass).
