"""Fastjson 1.2.68 PoC 结构化输入/输出。"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from fastjson_toolkit.waf.models import WafOptions


class Poc1268GenerateOptions(BaseModel):
    """生成 ≤1.2.68 AutoCloseable 证明 payload。"""

    gadget: str = Field(
        "file_truncate",
        description="见 GET /api/poc/1.2.68/gadgets",
    )
    file: Optional[str] = Field(None, description="写入/截断目标路径")
    content: Optional[str] = Field(None, description="写入内容（写文件链）")
    source: Optional[str] = Field(None, description="file_copy 源路径 tempPath")
    url: Optional[str] = Field(None, description="io_read_* 的 file:// / http URL")
    guess_byte: Optional[int] = Field(None, description="io_read_error 猜测首字节 0-255")
    bom_bytes: Optional[list[int]] = Field(None, description="io_read_echo BOM 前缀字节")
    host: Optional[str] = Field(None, description="MySQL/PG host")
    port: Optional[int] = Field(None, description="MySQL/PG port")
    user: Optional[str] = Field(None, description="MySQL user")
    jdbc_url: Optional[str] = Field(None, description="mysql_jdbc_60 完整 JDBC URL")
    socket_factory_arg: Optional[str] = Field(
        None, description="postgresql_ssrf ClassPathXml URL"
    )
    wrap_currency: bool = Field(
        False,
        description=(
            "套 java.util.Currency（MiscCodec）以触发 getter；"
            "业务点有期望类、且内嵌 $ref 不够时使用（与版本无关）"
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


class Poc1268GenerateResult(BaseModel):
    ok: bool = True
    gadget: str
    title: str = ""
    payload: str
    payload_raw: Optional[str] = Field(
        None, description="WAF 变换前的原始 payload；未变换时为 null"
    )
    wrap_currency: bool = False
    waf_techniques: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    requires: list[str] = Field(default_factory=list)
    jdk: str = ""


class Poc1268SendOptions(Poc1268GenerateOptions):
    """生成并（可选）发送到目标。"""

    target: str = Field(
        "http://127.0.0.1:18268/api/fastjson",
        description="反序列化点 URL（默认 1.2.68 依赖靶场）",
    )
    send: bool = Field(False, description="是否 POST payload 到 target")
    timeout: float = Field(15.0, ge=1, le=120)
    headers: dict[str, str] = Field(default_factory=dict)
    proxy: Optional[str] = None
    insecure: bool = False
    content_type: str = "application/json"


class Poc1268SendResult(BaseModel):
    ok: bool
    gadget: str
    title: str = ""
    payload: str
    payload_raw: Optional[str] = None
    wrap_currency: bool = False
    waf_techniques: list[str] = Field(default_factory=list)
    sent: bool = False
    status_code: Optional[int] = None
    response_preview: str = ""
    summary: str = ""
    notes: list[str] = Field(default_factory=list)
    requires: list[str] = Field(default_factory=list)
    jdk: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)
