import asyncio
import json
import sys
from collections.abc import AsyncGenerator

from auditkit.models import RawFinding
from auditkit.scanner.base import BaseCredentialProvider, _is_ignored, _normalize_path

BANDIT_DEFAULT_RULES = ["B105", "B106", "B107"]


class BanditProvider(BaseCredentialProvider):
    async def generate_audit_records(self) -> AsyncGenerator[RawFinding]:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "bandit",
            "-r",
            "-f",
            "json",
            "-l",
            "-i",
            str(self.target_directory),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await proc.communicate()
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"bandit failed: {stderr_bytes.decode().strip()}")
        stdout = stdout_bytes.decode()
        if not stdout.strip():
            return

        raw_results: list[dict] = json.loads(stdout).get("results", [])
        rules_to_run = self.rules if self.rules else BANDIT_DEFAULT_RULES
        for item in raw_results:
            test_id = item.get("test_id", "")
            if rules_to_run and test_id not in rules_to_run:
                continue
            filename = item.get("filename", "")
            file_path = _normalize_path(filename)
            if _is_ignored(file_path):
                continue
            yield RawFinding(
                file_path=file_path,
                line_number=item["line_number"],
                rule_id=test_id,
                description=item.get("issue_text", ""),
                tool_name="bandit",
                extra={
                    "confidence": item.get("issue_confidence", ""),
                    "severity": item.get("issue_severity", ""),
                    "more_info": item.get("more_info", ""),
                },
            )
