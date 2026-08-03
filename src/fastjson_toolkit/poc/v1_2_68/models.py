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

RcePresetField = Literal["file", "custom", "exec", "echo", "memshell"]


def normalize_rce_preset(
    preset: RcePresetField | str,
    *,
    echo: bool = False,
    memshell: bool = False,
) -> RcePresetField:
    """file/custom/exec/echo/memshell 统一为预设；旧 bool 标志可覆盖。"""
    if memshell:
        return "memshell"
    if echo:
        return "echo"
    p = (preset or "file").strip().lower()
    if p in ("file", "custom", "exec", "echo", "memshell"):
        return p  # type: ignore[return-value]
    return "file"



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
    guess_byte: Optional[int] = Field(
        None, description="io_read_error 单字节探测 0-255（不爆破时）"
    )
    bom_bytes: Optional[list[int]] = Field(
        None,
        description="io_read_error / io_read_echo 的 BOM 前缀字节；报错读可多字节",
    )
    read_length: Optional[int] = Field(
        None,
        ge=1,
        le=4096,
        description=(
            "io_read_error 爆破读取最大字节数；send=true 时启用逐字节报错读"
        ),
    )
    read_charset: Optional[str] = Field(
        "mixed",
        description="爆破码表：mixed(默认含大小写) / lower / printable",
    )
    read_charset_bytes: Optional[list[int]] = Field(
        None, description="自定义爆破码表（优先于 read_charset）"
    )
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
    preset: RcePresetField = Field(
        "file",
        description=(
            "postgresql_ssrf 预设：file=写证明文件（默认）；"
            "custom=自备 class 投递；exec=ProcessBuilder；"
            "echo=命令回显；memshell=内存马"
        ),
    )
    class_b64: Optional[str] = Field(
        None, description="preset=custom 时的恶意 .class Base64"
    )
    echo: bool = Field(
        False, description="兼容旧字段：true 等价于 preset=echo"
    )
    engine: EchoEngineField = Field("auto", description="回显引擎（preset=echo）")
    cmd: str = Field("id", description="回显默认命令 / preset=exec 执行命令")
    cmd_header: str = Field("X-Cmd", description="命令请求头（preset=echo）")
    attack_base: Optional[str] = Field(None, description="回显/内存马资源托管基址")
    memshell: bool = Field(
        False,
        description="兼容旧字段：true 等价于 preset=memshell（仅 postgresql_ssrf）",
    )
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
    read_bytes: Optional[list[int]] = Field(
        None, description="io_read_error 爆破得到的字节"
    )
    read_content: Optional[str] = Field(
        None, description="io_read_error 爆破得到的文本"
    )


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
    read_bytes: Optional[list[int]] = None
    read_content: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)
