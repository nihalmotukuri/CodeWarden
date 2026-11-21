from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class DiffHunk(BaseModel):
    file_path: str
    added_lines: list[int] = Field(default_factory=list)
    removed_lines: list[int] = Field(default_factory=list)
    deletion_anchors: list[int] = Field(default_factory=list)
    raw_patch: str = ""


class FunctionSlice(BaseModel):
    file_path: str
    language: str
    symbol_name: str
    node_type: str
    start_line: int
    end_line: int
    changed_lines: list[int]
    imports: list[str] = Field(default_factory=list)
    raw_patch: str = ""
    source_code: str


class ReviewFinding(BaseModel):
    severity: Literal["critical", "high", "medium", "low"]
    category: Literal["security", "bug", "logic", "race-condition", "performance", "type-safety"]
    file_path: str
    symbol_name: str
    line: int
    title: str
    explanation: str
    suggested_fix: str
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("confidence", mode="before")
    @classmethod
    def _normalize_confidence(cls, value: object) -> float:
        num = float(value)  # type: ignore[arg-type]
        if num > 1.0:
            num = num / 100.0
        return max(0.0, min(1.0, num))


class SliceReview(BaseModel):
    has_issues: bool
    findings: list[ReviewFinding] = Field(default_factory=list)
    summary: str


class ReviewReport(BaseModel):
    repo: str
    model: str
    slices_analyzed: int
    tool_calls_made: int
    findings: list[ReviewFinding] = Field(default_factory=list)
