import asyncio
import json
import sys
from collections.abc import AsyncGenerator

from auditkit.models import RawFinding
from auditkit.scanner.base import BaseCredentialProvider, _is_ignored, _normalize_path


class DetectSecretsProvider(BaseCredentialProvider):
    async def healthy(self) -> tuple[bool, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                "-c",
                "import detect_secrets",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode == 0:
                return True, "detect_secrets available"
            return False, stderr.decode().strip()
        except FileNotFoundError:
            return False, "detect_secrets not found"

    async def generate_audit_records(self) -> AsyncGenerator[RawFinding]:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "detect_secrets",
            "scan",
            "--all-files",
            str(self.target_directory),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await proc.communicate()
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"detect-secrets failed: {stderr_bytes.decode().strip()}")
        stdout = stdout_bytes.decode()
        if not stdout.strip():
            return

        raw_results: dict = json.loads(stdout).get("results", {})
        for filename, entries in raw_results.items():
            file_path = _normalize_path(filename)
            if _is_ignored(file_path):
                continue
            for entry in entries:
                yield RawFinding(
                    file_path=file_path,
                    line_number=entry["line_number"],
                    rule_id=entry.get("type", "Secret"),
                    description=entry.get("type", "Secret detected"),
                    tool_name="detect-secrets",
                    extra={
                        "hashed_secret": entry.get("hashed_secret", ""),
                        "is_verified": entry.get("is_verified", False),
                    },
                )
