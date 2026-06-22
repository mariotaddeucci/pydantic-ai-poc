import asyncio
import json
import sys
from collections.abc import AsyncGenerator

from pydantic import BaseModel

from auditkit.models import RawFinding
from auditkit.scanner.base import BaseCredentialProvider, _is_ignored, _normalize_path


class _RuffLocation(BaseModel):
    column: int
    row: int


class _RuffFinding(BaseModel):
    code: str
    filename: str
    location: _RuffLocation
    message: str
    url: str | None = None


RUFF_DEFAULT_RULES = ["S105", "S106", "S107"]


class RuffProvider(BaseCredentialProvider):
    async def generate_audit_records(self) -> AsyncGenerator[RawFinding]:
        rules_to_run = self.rules if self.rules else RUFF_DEFAULT_RULES
        rules = ",".join(rules_to_run)
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--output-format",
            "json",
            "--select",
            rules,
            str(self.target_directory),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await proc.communicate()
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"ruff failed: {stderr_bytes.decode().strip()}")
        stdout = stdout_bytes.decode()
        if not stdout.strip():
            return

        for item in json.loads(stdout):
            try:
                f = _RuffFinding.model_validate(item)
            except Exception:
                continue
            file_path = _normalize_path(f.filename)
            if _is_ignored(file_path):
                continue
            yield RawFinding(
                file_path=file_path,
                line_number=f.location.row,
                rule_id=f.code,
                description=f.message,
                tool_name="ruff",
                extra={"url": f.url} if f.url else {},
            )
