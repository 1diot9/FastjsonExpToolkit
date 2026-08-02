"""Fastjson 1.2.80 PoC 结构化输入/输出。"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from fastjson_toolkit.waf.models import WafOptions


class Poc1280GenerateOptions(BaseModel):
    """生成 ≤1.2.80 Exception 缓存绕过证明 payload。"""

    gadget: str = Field(
        "io_write",
        description="见 GET /api/poc/1.2.80/gadgets（一律写文件证明 RCE）",
    )
    file: Optional[str] = Field(None, description="写入目标路径（marker）")
    content: Optional[str] = Field(None, description="写入内容")
    url: Optional[str] = Field(None, description="io_copy_write 的 file:// 源 URL")
    guess_byte: Optional[int] = Field(None, description="已废弃，保留兼容")
    host: Optional[str] = Field(None, description="MySQL/PG host")
    port: Optional[int] = Field(None, description="MySQL/PG port")
    user: Optional[str] = Field(None, description="MySQL user")
    socket_factory_arg: Optional[str] = Field(
        None, description="postgresql/jython ClassPathXml URL"
    )
    classpath: Optional[str] = Field(None, description="groovy classpathList jar URL")
    wrap_currency: bool = Field(
        False,
        description=(
            "对每步 payload 套 java.util.Currency 以触发 getter；"
            "业务点有期望类时使用（与版本无关）"
        ),
    )
    currency_field: str = Field(
        "currency",
        description="Currency MiscCodec 字段：currency 或 currencyCode",
    )
    waf_techniques: list[str] = Field(
        default_factory=list,
        description="生成后按顺序叠加的 WAF 变换 id（见 GET /api/waf/techniques）",
    )
    waf_options: Optional[WafOptions] = Field(
        None, description="WAF 变换参数（逗号数/填充长度等）"
    )


class Poc1280GenerateResult(BaseModel):
    ok: bool = True
    gadget: str
    title: str = ""
    payload: str = Field(description="最后一步 payload（便于复制）")
    payload_raw: Optional[str] = Field(
        None, description="WAF 变换前最后一步；未变换时为 null"
    )
    steps: list[str] = Field(default_factory=list, description="按顺序全部步骤")
    steps_raw: list[str] = Field(
        default_factory=list, description="WAF 变换前的步骤；未变换时为空"
    )
    wrap_currency: bool = False
    waf_techniques: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    requires: list[str] = Field(default_factory=list)
    jdk: str = ""


class Poc1280SendOptions(Poc1280GenerateOptions):
    """生成并（可选）按步骤发送到目标。"""

    target: str = Field(
        "http://127.0.0.1:18180/api/fastjson",
        description="反序列化点 URL（默认 1.2.80 依赖靶场）",
    )
    send: bool = Field(False, description="是否按步骤 POST payload 到 target")
    reset_cache: bool = Field(
        False,
        description="发送前 POST /api/reset 清空靶场 ParserConfig 缓存（若目标支持）",
    )
    timeout: float = Field(20.0, ge=1, le=120)
    headers: dict[str, str] = Field(default_factory=dict)
    proxy: Optional[str] = None
    insecure: bool = False
    content_type: str = "application/json"


class Poc1280SendResult(BaseModel):
    ok: bool
    gadget: str
    title: str = ""
    payload: str = ""
    payload_raw: Optional[str] = None
    steps: list[str] = Field(default_factory=list)
    steps_raw: list[str] = Field(default_factory=list)
    wrap_currency: bool = False
    waf_techniques: list[str] = Field(default_factory=list)
    sent: bool = False
    status_codes: list[int] = Field(default_factory=list)
    response_previews: list[str] = Field(default_factory=list)
    status_code: Optional[int] = None
    response_preview: str = ""
    summary: str = ""
    notes: list[str] = Field(default_factory=list)
    requires: list[str] = Field(default_factory=list)
    jdk: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)
