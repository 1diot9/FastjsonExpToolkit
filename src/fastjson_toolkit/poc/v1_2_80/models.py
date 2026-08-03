"""Fastjson 1.2.80 PoC 结构化输入/输出。"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from fastjson_toolkit.poc.v1_2_68.models import RcePresetField, normalize_rce_preset
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

__all__ = [
    "EchoEngineField",
    "Poc1280GenerateOptions",
    "Poc1280GenerateResult",
    "Poc1280SendOptions",
    "Poc1280SendResult",
    "RcePresetField",
    "normalize_rce_preset",
]



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
    outbound: bool = Field(
        True,
        description="mysql_jdbc：true=出网；false=NamedPipe 不出网",
    )
    named_pipe_path: Optional[str] = Field(
        "/tmp/mysql.pcap",
        description="mysql_jdbc 不出网 NamedPipe 路径",
    )
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
    preset: RcePresetField = Field(
        "file",
        description=(
            "postgresql/jython/groovy 预设：file=写证明文件（默认）；"
            "custom=自备 class；exec=ProcessBuilder/静态块；"
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
        description="兼容旧字段：true 等价于 preset=memshell（postgresql/jython/groovy）",
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
    echo: bool = False
    engine: str = ""
    cmd_header: str = ""
    attack_jar_b64: Optional[str] = None
    attack_xml_b64: Optional[str] = None
    memshell: bool = False
    memshell_info: Optional[dict] = None
    memshell_connect: Optional[str] = None


class Poc1280SendOptions(Poc1280GenerateOptions):
    """生成并（可选）按步骤发送到目标。"""

    target: str = Field(
        "http://127.0.0.1:18280/api/fastjson",
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
