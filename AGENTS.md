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
  providers.py        # ABC BaseCredentialProvider + RuffProvider, BanditProvider, DetectSecretsProvider
                      # All providers use async generators (async def generate_audit_records)
                      # Subprocess calls via asyncio.create_subprocess_exec
                      # Factory: create_providers(dir, agent) via lazy imports
                      # PROVIDER_REGISTRY: dict mapping name → (module, class) for lazy loading
                      # AGENT_PROFILES: dict mapping agent name → provider config + kwargs
  producers.py        # Backward-compat async wrappers delegating to providers
  report_generator.py # Async context building + merge + markdown (file I/O via asyncio.to_thread)
  models.py           # Pydantic models: RawFinding, ContextBlock, ScanEntry, ScanReport, AnalyzedFinding, ScanDeps
  agents/             # Pluggable security-analysis agents
    base.py           # SecurityAgent ABC: name, description, system_prompt, format_prompt, classify
    registry.py       # get_agent() / list_agents() (cached via functools.lru_cache, no global)
    runner.py         # Shared LLM execution, batching and report merging
    formatter.py      # Reusable prompt-formatting helpers
    contexts/         # Specialized agents by security context
      credential.py   # Credential/secrets classifier (default)
      injection.py    # SQL/command injection classifier (skeleton)
      dependency.py   # Vulnerable dependency classifier (skeleton)
  agent_classifier.py # Backward-compat re-exports delegating to agents/
  cli.py              # Typer app: sync commands wrapping async helpers with asyncio.run()
  config.py           # pydantic-settings (loads .env), no module-level instance
  validator.py        # Async report validation: counts, cross-reference, markdown structure, file paths
  pipeline.py         # Typer orchestrator: runs all phases, saves JSONL + JSON + MD, validates at end
tests/
  test_integration.py # Integration tests: scan → report → validate, profile/provider unit tests
  fixtures/           # Sample files with known credential patterns (Python, YAML, JSON, .env)
```

## Key design decisions

- **Provider abstraction**: `BaseCredentialProvider` ABC with `async def generate_audit_records() -> AsyncGenerator[RawFinding]`. New providers subclass it and register in `PROVIDER_REGISTRY`.
- **Agent-driven profiles**: `AGENT_PROFILES` dict maps agent names (e.g. `"credential"`, `"injection"`, `"dependency"`) to per-provider kwargs. `create_providers(dir, agent)` factory instantiates all providers with lazy imports. Extensible: add a new provider in `PROVIDER_REGISTRY` + add its config to an agent profile in `AGENT_PROFILES`.
- **JSONL as interchange format**: `scan` writes `scan_results.jsonl`, `report`/`analyze`/`validate` read it.
- **Block merging**: `merge_context_blocks()` consolidates overlapping (±2 line gap) context blocks from different tools. Same-line findings from ruff + bandit + detect-secrets appear in one merged block with multiple `>>>` markers.
- **Normalized paths**: `_normalize_path()` in providers.py converts all tool output paths to relative paths from cwd. Always apply it to new provider output.
- **New providers**: subclass `BaseCredentialProvider`, implement `async def generate_audit_records()`, add to `PROVIDER_REGISTRY` and `AGENT_PROFILES`.
- **Agent abstraction**: `SecurityAgent` ABC with context-specific `system_prompt`. `analyze`/`pipeline` accept `--agent <name>` to pick a registered agent from `get_agent()`. New agents only need to subclass `SecurityAgent`, set `name`/`description`/`system_prompt` and register in `AVAILABLE_AGENTS` (via registry's `_load_agents`).
- **Batched AI classification**: `analyze` groups findings by file and sends batches per agent (`batch_size`, default 5). Uses the configured `OPENAI_MODEL_LIGHT` through the standard OpenAI connector with thinking disabled.
- **Unified output model**: All agents produce the same `ScanReport` with `exposed`/`uncertain`/`false_positive` assessments, keeping reports and validation agnostic of the analysis context.
- **No ruff config in pyproject.toml**: ruff runs with defaults. The scanner invokes ruff directly via subprocess with `--select S105,S106,S107`.
- **src/ layout**: package lives under `src/auditkit/`. Build system is hatchling.
- **Async everywhere**: All I/O (subprocess, file reads/writes) is async. Sync Typer commands wrap async implementations with `asyncio.run()`. Providers use `asyncio.create_subprocess_exec`. File I/O uses `asyncio.to_thread`. Report-generator and validator functions are async.
- **No global state**: `Settings()` is created per-command invocation. Agent registry uses `functools.lru_cache` (no `global` statement, no module-level `AVAILABLE_AGENTS`). Settings are passed as explicit parameters to functions that need them.
- **Functional DI**: Each command creates its own dependencies (`settings = Settings()`) and passes them down explicitly. No DI container, no global singletons, no context vars.
- **Simplified CLI**: Commands are silent on success — no progress bars or status lines. Output goes to stdout/JSONL (pydantic model dumps with `indent=2` for human readability). Errors are logged to stderr as structured JSON with full traceback.

## Caveats

- Python 3.14 minimum (uses `str | None` syntax, `asyncio.to_thread`, `asyncio.create_subprocess_exec`).
- Package manager is **uv**. All commands prefixed with `uv run`.
- `uv.lock` is gitignored — each developer generates their own.
- `.secrets.baseline` is gitignored — pre-commit regenerates it.
- `**/*_scan_report.md`, `**/scan_results.jsonl`, `**/analyze_results.json` are gitignored.
- `bandit` provider uses `-l -i` flags (LOW severity + LOW confidence) to include B105-B107 password rules.
- `detect-secrets` scans all files including generated reports; scan output files may appear as false findings in subsequent scans.
- Typer (v0.26.7) does not have a built-in `Depends` — DI is purely functional (create-and-pass).
- `AVAILABLE_AGENTS` was removed as a module-level constant in favor of `get_agent()` / `list_agents()`.
