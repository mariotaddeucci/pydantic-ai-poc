"""Shared Pydantic models for the credential scanner pipeline."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class RawFinding(BaseModel):
    """Generic finding produced by any scanning tool."""
    file_path: str
    line_number: int
    rule_id: str
    description: str
    tool_name: str
    extra: dict[str, Any] = Field(default_factory=dict)


class ContextBlock(BaseModel):
    """Pre-assembled context for one or more merged findings."""
    file_path: str
    start_line: int
    end_line: int
    finding_lines: list[int]
    findings: list[RawFinding]
    snippet: str


class Assessment(str, Enum):
    FALSE_POSITIVE = "false_positive"
    EXPOSED = "exposed"
    UNCERTAIN = "uncertain"


class AnalyzedFinding(BaseModel):
    file_path: str
    line_number: int
    rule_id: str
    assessment: Assessment
    context: str
    reasoning: str


class ScanReport(BaseModel):
    directory: str
    total_findings: int = 0
    false_positives: int = 0
    exposed: int = 0
    uncertain: int = 0
    findings: list[AnalyzedFinding] = Field(default_factory=list)
