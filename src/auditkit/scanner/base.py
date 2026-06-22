from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from auditkit.models import RawFinding


IGNORED_PARTS = {".venv", "venv", ".git", "node_modules", "__pycache__", ".tox", "dist", "build"}


def _is_ignored(file_path: str) -> bool:
    path = Path(file_path)
    return any(p in IGNORED_PARTS or p.endswith(".egg-info") for p in path.parts)


def _normalize_path(file_path: str) -> str:
    p = Path(file_path)
    if p.is_absolute():
        try:
            return str(p.relative_to(Path.cwd()))
        except ValueError:
            return file_path
    return str(p)


class BaseCredentialProvider(ABC):
    def __init__(self, target_directory: str, rules: list[str] | None = None):
        self.target_directory = Path(target_directory).resolve()
        self.rules = rules or []

    @abstractmethod
    async def generate_audit_records(self) -> AsyncGenerator[RawFinding]:
        if False:
            yield
