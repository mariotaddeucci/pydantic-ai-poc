# AGENTS.md

## Overview

**auditkit** — standardized scanner agents for credential and security auditing. Built with pydantic-ai + Typer. Runs static analysis tools (ruff, bandit, detect-secrets), merges overlapping findings into consolidated context blocks, then optionally classifies them via AI through any OpenAI-compatible API.

## Commands

```bash
# Scan directory with all three providers (default: ruff + bandit + detect-secrets)
uv run python -m auditkit.cli scan <dir>

# Scan with a specific profile (default: secret-scan)
uv run python -m auditkit.cli scan <dir> --profile secret-scan

# Generate markdown report from JSONL
uv run python -m auditkit.cli report <jsonl_file>

# AI classification (requires .env with OPENAI_API_KEY)
uv run python -m auditkit.cli analyze <jsonl_file>

# Full pipeline: scan → report → classify → validate
uv run python -m auditkit.pipeline <dir>

# Validate report integrity
uv run python -m auditkit.cli validate <jsonl_file> -a analyze_results.json -r report.md

# Scan with only specific tools
uv run python -m auditkit.cli scan . --select ruff,detect-secrets
uv run python -m auditkit.cli scan . --exclude bandit

# Run integration tests
uv run python -m pytest tests/ -v
```

## Setup

```bash
cp .env.example .env    # then edit .env with OPENAI_API_KEY
uv sync
uv run pre-commit install
```

Required env vars: `OPENAI_API_KEY`. Optional: `OPENAI_BASE_URL` (defaults to the official OpenAI endpoint), `OPENAI_MODEL` (default `gpt-4o`), `OPENAI_MODEL_LIGHT` (default `gpt-4o-mini`), `OPENAI_DEFAULT_AGENT` (default `credential`). Loaded via `auditkit/config.py` (pydantic-settings from `.env`).

## Architecture

```
src/auditkit/
  providers.py        # ABC BaseCredentialProvider + RuffProvider, BanditProvider, DetectSecretsProvider
                      # Factory: create_providers(dir, profile) → list[BaseCredentialProvider]
                      # PROFILE_RULES: dict mapping profile name → per-tool rules
  producers.py        # Backward-compat wrappers (run_ruff/run_bandit/run_detect_secrets) delegating to providers
  report_generator.py # build_context_blocks → merge_context_blocks → markdown
  models.py           # Pydantic models: RawFinding, ContextBlock, ScanEntry, ScanReport, AnalyzedFinding, ScanDeps
  agents/             # Pluggable security-analysis agents
    base.py           # SecurityAgent ABC: name, description, system_prompt, format_prompt, classify
    registry.py       # AVAILABLE_AGENTS + get_agent() / list_agents()
    runner.py         # Shared LLM execution, batching and report merging
    formatter.py      # Reusable prompt-formatting helpers
    contexts/         # Specialized agents by security context
      credential.py   # Credential/secrets classifier (default)
      injection.py    # SQL/command injection classifier (skeleton)
      dependency.py   # Vulnerable dependency classifier (skeleton)
  agent_classifier.py # Backward-compat re-exports delegating to agents/
  cli.py              # Typer app: scan, report, analyze, validate subcommands
  config.py           # pydantic-settings (loads .env)
  validator.py        # Report validation: counts, cross-reference, markdown structure, file paths
  pipeline.py         # Typer orchestrator: runs all phases, saves JSONL + JSON + MD, validates at end
tests/
  test_integration.py # Integration tests: scan → report → validate, profile/provider unit tests
  fixtures/           # Sample files with known credential patterns (Python, YAML, JSON, .env)
```

## Key design decisions

- **Provider abstraction**: `BaseCredentialProvider` ABC with `generate_audit_records() → Generator[RawFinding]`. New providers subclass it and register in `AVAILABLE_PROVIDERS`.
- **Profile-based rules**: `PROFILE_RULES` dict maps profile names (e.g. `"secret-scan"`) to per-tool rule lists. `create_providers(dir, profile)` factory instantiates all providers with the right rules. Extensible: add a new profile by adding a dict entry.
- **JSONL as interchange format**: `scan` writes `scan_results.jsonl`, `report`/`analyze`/`validate` read it.
- **Block merging**: `merge_context_blocks()` consolidates overlapping (±2 line gap) context blocks from different tools. Same-line findings from ruff + bandit + detect-secrets appear in one merged block with multiple `>>>` markers.
- **Normalized paths**: `_normalize_path()` in providers.py converts all tool output paths to relative paths from cwd. Always apply it to new provider output.
- **New providers**: subclass `BaseCredentialProvider`, implement `generate_audit_records()`, add to `AVAILABLE_PROVIDERS` and `PROFILE_RULES`.
- **Agent abstraction**: `SecurityAgent` ABC with context-specific `system_prompt`. `analyze`/`pipeline` accept `--agent <name>` to pick a registered agent from `AVAILABLE_AGENTS`. New agents only need to subclass `SecurityAgent`, set `name`/`description`/`system_prompt` and register in `AVAILABLE_AGENTS`.
- **Batched AI classification**: `analyze` groups findings by file and sends batches per agent (`batch_size`, default 5). Uses the configured `OPENAI_MODEL_LIGHT` through the standard OpenAI connector with thinking disabled.
- **Unified output model**: All agents produce the same `ScanReport` with `exposed`/`uncertain`/`false_positive` assessments, keeping reports and validation agnostic of the analysis context.
- **No ruff config in pyproject.toml**: ruff runs with defaults. The scanner invokes ruff directly via subprocess with `--select S105,S106,S107`.
- **src/ layout**: package lives under `src/auditkit/`. Build system is hatchling.

## Caveats

- Python 3.14 minimum (uses `str | None` syntax).
- Package manager is **uv**. All commands prefixed with `uv run`.
- `uv.lock` is gitignored — each developer generates their own.
- `.secrets.baseline` is gitignored — pre-commit regenerates it.
- `**/credential_scan_report.md`, `**/scan_results.jsonl`, `**/analyze_results.json` are gitignored.
- `bandit` provider uses `-l -i` flags (LOW severity + LOW confidence) to include B105-B107 password rules.
- `detect-secrets` scans all files including generated reports; scan output files may appear as false findings in subsequent scans.
