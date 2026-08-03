"""Structured Fastjson version detection results."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class VersionEvidence(BaseModel):
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


class VersionResult(BaseModel):
    target: str
    autotype_enabled: Optional[bool] = None
    safemode_enabled: Optional[bool] = None
    reported_version: Optional[str] = None
    reported_version_note: Optional[str] = None
    is_1_2_83_hint: Optional[bool] = None
    version_range: Optional[str] = None
    version_detail: Optional[str] = Field(
        None,
        description=(
            "比 version_range 更细的区间，如 ≈1.2.24 / 1.2.25-1.2.47 / "
            "1.2.48-1.2.68 / 1.2.70-1.2.80（70 与 73 无法再分）"
        ),
    )
    confidence: float = 0.0
    methods_used: list[str] = Field(default_factory=list)
    evidence: list[VersionEvidence] = Field(default_factory=list)
    dns_filter: Optional[str] = None
    dns_records: list[dict[str, Any]] = Field(default_factory=list)
    dns_hits: dict[str, bool] = Field(default_factory=dict)
    summary: str = ""
    next_actions: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
