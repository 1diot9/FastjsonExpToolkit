"""Fastjson 1.2.68 PoC 结构化输入/输出。"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from fastjson_toolkit.waf.models import WafOptions

EchoEngineField = Literal[
    "auto",
    "spring",
    "undertow",
    "tomcat",
    "jetty",
    "weblogic",
    "websphere",
    "resin",
    "struts2",
    "httpserver",
    "dfs",
]



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
    echo: bool = Field(False, description="postgresql_ssrf 回显")
    engine: EchoEngineField = Field("auto", description="回显引擎")
    cmd: str = Field("id", description="回显默认命令")
    cmd_header: str = Field("X-Cmd", description="命令请求头")
    attack_base: Optional[str] = Field(None, description="回显/内存马资源托管基址")
    memshell: bool = Field(False, description="注入内存马（与 echo 互斥；仅 postgresql_ssrf）")
    ms_api: str = Field(
        "jar",
        description="jar=内置 memshell-gen.jar；或 http(s)://... MemShellParty boot",
    )
    ms_server: str = Field("Undertow", description="中间件类型")
    ms_tool: str = Field("Command", description="C2/管理工具")
    ms_type: str = Field("Filter", description="马类型 Filter/Listener/...")
    ms_path: str = Field("/*", description="urlPattern")
    ms_jdk: str = Field("8", description="目标 JDK 大版本：6/8/9/11/17/21")
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
    echo: bool = False
    engine: str = ""
    cmd_header: str = ""
    attack_jar_b64: Optional[str] = None
    attack_xml_b64: Optional[str] = None
    memshell: bool = False
    memshell_info: Optional[dict] = None
    memshell_connect: Optional[str] = None


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
    echo: bool = False
    engine: str = ""
    cmd_header: str = ""
    attack_jar_b64: Optional[str] = None
    attack_xml_b64: Optional[str] = None
    echo_output: Optional[str] = None
    memshell: bool = False
    memshell_info: Optional[dict] = None
    memshell_connect: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)
