"""Structured detection results for Agent / CLI / Web."""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class LibraryGuess(str, Enum):
    FASTJSON = "fastjson"
    JACKSON = "jackson"
    GSON = "gson"
    ORG_JSON = "org.json"
    HUTOOL = "hutool"
    UNKNOWN = "unknown"


class Evidence(BaseModel):
    probe_id: str
    category: str
    description: str
    matched: list[str] = Field(default_factory=list)
    score_delta: float = 0.0
    library_hint: Optional[str] = None
    status_code: int = 0
    elapsed_ms: float = 0.0
    response_excerpt: str = ""
    payload: str = ""


class DetectResult(BaseModel):
    target: str
    is_fastjson: bool
    confidence: float
    autotype_disabled_hint: Optional[bool] = None
    primary_guess: LibraryGuess = LibraryGuess.UNKNOWN
    scores: dict[str, float] = Field(default_factory=dict)
    evidence: list[Evidence] = Field(default_factory=list)
    dns_timing_suspicious: Optional[bool] = None
    dns_confirmed: Optional[bool] = None
    dns_filter: Optional[str] = None
    dns_records: list[dict[str, Any]] = Field(default_factory=list)
    baseline_ms: Optional[float] = None
    dns_probe_ms: Optional[float] = None
    summary: str = ""
    next_actions: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
