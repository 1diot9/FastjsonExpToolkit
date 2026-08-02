"""API request/response schemas."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class DetectRequest(BaseModel):
    target: str = Field(..., description="目标 URL")
    include_dns: bool = Field(True, description="是否发送 DNS 探针")
    use_ceye: bool = Field(True, description="是否使用 CEYE 轮询确认")
    dnslog: Optional[str] = Field(None, description="自定义 DNSLog 域名（无 CEYE 时）")
    ceye_token: Optional[str] = Field(None, description="覆盖 .env 中的 CEYE token")
    ceye_domain: Optional[str] = Field(None, description="覆盖 CEYE 域名")
    ceye_wait: float = Field(8.0, ge=0, le=60, description="CEYE 轮询等待秒数")
    timeout: float = Field(10.0, ge=1, le=120)
    timing_threshold_ms: float = Field(800.0, ge=0)
    headers: dict[str, str] = Field(default_factory=dict)
    proxy: Optional[str] = None
    insecure: bool = False
    content_type: str = "application/json"


class HealthResponse(BaseModel):
    status: str
    version: str
    ceye_configured: bool
    ceye_domain: Optional[str] = None


class SettingsResponse(BaseModel):
    ceye_token_set: bool
    ceye_token_masked: str = ""
    ceye_identifier: str = ""
    ceye_domain: str = ""
    env_path: str = ""


class SettingsUpdateRequest(BaseModel):
    ceye_token: Optional[str] = Field(
        None, description="CEYE API token；留空则保留原值"
    )
    ceye_identifier: str = Field(
        ...,
        min_length=1,
        description="CEYE Identifier 子域名，如 hpdth2 或 hpdth2.ceye.io",
    )


class SettingsUpdateResponse(BaseModel):
    ok: bool = True
    message: str = "已保存"
    settings: SettingsResponse
