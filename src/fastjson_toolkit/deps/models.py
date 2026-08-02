"""Structured dependency scan results."""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

DepMethod = Literal["character", "dns"]
DepStatus = Literal["present", "absent", "unknown", "error"]


class DepHit(BaseModel):
    clazz: str
    description: str
    category: str = "other"
    status: DepStatus = "unknown"
    method: DepMethod = "character"
    matched: list[str] = Field(default_factory=list)
    status_code: int = 0
    elapsed_ms: float = 0.0
    response_excerpt: str = ""
    payload: str = ""
    dns_filter: Optional[str] = None
    dns_hit: Optional[bool] = None
    error: Optional[str] = None


class DepsResult(BaseModel):
    target: str
    method: DepMethod = "character"
    scanned: int = 0
    present_count: int = 0
    absent_count: int = 0
    unknown_count: int = 0
    error_count: int = 0
    present: list[DepHit] = Field(default_factory=list)
    results: list[DepHit] = Field(default_factory=list)
    dns_filter: Optional[str] = None
    dns_records: list[dict[str, Any]] = Field(default_factory=list)
    summary: str = ""
    next_actions: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
