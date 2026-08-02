"""Structured results for expected-class (期望类) detection."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class ExpectEvidence(BaseModel):
    probe_id: str
    category: str
    description: str
    payload: str = ""
    status_code: int = 0
    elapsed_ms: float = 0.0
    errored: Optional[bool] = None
    matched: list[str] = Field(default_factory=list)
    response_excerpt: str = ""
    interpretation: str = ""


class ExpectClassResult(BaseModel):
    target: str
    """Whether the deserialization point binds an expected Java type."""
    has_expect_class: Optional[bool] = None
    """True when empty-key root probe errors → expected type is not Map/subclass."""
    expect_not_map: Optional[bool] = None
    """Feature class missing hint → Fastjson likely < 1.2.68."""
    version_lt_1_2_68_hint: Optional[bool] = None
    confidence: float = 0.0
    base_body: str = ""
    methods_used: list[str] = Field(default_factory=list)
    evidence: list[ExpectEvidence] = Field(default_factory=list)
    summary: str = ""
    next_actions: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
