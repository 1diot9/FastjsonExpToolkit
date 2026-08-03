"""API request/response schemas."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from fastjson_toolkit.waf.models import WafOptions


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


class VersionRequest(BaseModel):
    target: str = Field(..., description="目标 URL")
    include_dns: bool = Field(False, description="是否发送 DNS 版本探针")
    use_ceye: bool = Field(True, description="是否使用 CEYE 轮询确认 DNS")
    dnslog: Optional[str] = Field(None, description="自定义 DNSLog 域名（无 CEYE 时）")
    ceye_token: Optional[str] = Field(None, description="覆盖 .env 中的 CEYE token")
    ceye_domain: Optional[str] = Field(None, description="覆盖 CEYE 域名")
    ceye_wait: float = Field(10.0, ge=0, le=60, description="CEYE 轮询等待秒数")
    timeout: float = Field(10.0, ge=1, le=120)
    headers: dict[str, str] = Field(default_factory=dict)
    proxy: Optional[str] = None
    insecure: bool = False
    content_type: str = "application/json"


class DepsRequest(BaseModel):
    target: str = Field(..., description="目标 URL")
    method: str = Field(
        "character",
        description=(
            "探测方法：character（默认，失败时自动降级 Class MiscCodec）、"
            "class（AutoType 关闭推荐）、dns（Locale+Inet4，版本敏感）"
        ),
    )
    classes: list[str] = Field(
        default_factory=list,
        description="仅扫描这些全限定类名；空则用内置目录",
    )
    categories: list[str] = Field(
        default_factory=list,
        description="按类别过滤，如 spring / c3p0 / jdk；空则不过滤",
    )
    use_ceye: bool = Field(True, description="DNS 方法时是否用 CEYE 轮询确认")
    dnslog: Optional[str] = Field(None, description="自定义 DNSLog 域名（无 CEYE 时）")
    ceye_token: Optional[str] = Field(None, description="覆盖 .env 中的 CEYE token")
    ceye_domain: Optional[str] = Field(None, description="覆盖 CEYE 域名")
    ceye_wait: float = Field(10.0, ge=0, le=60, description="CEYE 轮询等待秒数")
    timeout: float = Field(10.0, ge=1, le=120)
    concurrency: int = Field(6, ge=1, le=20, description="Character 方法并发数")
    headers: dict[str, str] = Field(default_factory=dict)
    proxy: Optional[str] = None
    insecure: bool = False
    content_type: str = "application/json"


class ExpectClassRequest(BaseModel):
    target: str = Field(..., description="目标 URL（反序列化点）")
    base_body: Optional[str] = Field(
        None,
        description=(
            "原始请求 JSON（对象或对象数组）；"
            "探针会在其上注入 Feature @type / 空键语法。"
            '默认 {"age":20,"name":"Bob"}'
        ),
    )
    timeout: float = Field(10.0, ge=1, le=120)
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
    mcp_http_host: str = "127.0.0.1"
    mcp_http_port: int = 8100
    mcp_http_url: str = "http://127.0.0.1:8100/mcp"
    mcp_http_running: bool = False
    mcp_http_token_set: bool = False
    mcp_http_token_masked: str = ""
    mcp_http_error: str = ""


class SettingsUpdateRequest(BaseModel):
    ceye_token: Optional[str] = Field(
        None, description="CEYE API token；留空则保留原值"
    )
    ceye_identifier: str = Field(
        ...,
        min_length=1,
        description="CEYE Identifier 子域名，如 hpdth2 或 hpdth2.ceye.io",
    )


class McpHttpSettingsUpdateRequest(BaseModel):
    host: str = Field("127.0.0.1", description="MCP HTTP 监听地址")
    port: int = Field(8100, ge=1, le=65535, description="MCP HTTP 端口")
    token: Optional[str] = Field(
        None,
        description="访问 Token；留空保留原值；客户端用 Authorization: Bearer 或 X-MCP-Token",
    )
    clear_token: bool = Field(False, description="清空已保存的 Token")


class McpHttpStartRequest(BaseModel):
    host: Optional[str] = Field(None, description="覆盖监听地址；默认用已保存配置")
    port: Optional[int] = Field(None, ge=1, le=65535, description="覆盖端口")
    token: Optional[str] = Field(
        None, description="覆盖 Token；非空则写入配置后启动"
    )
    persist: bool = Field(True, description="是否将本次参数写入 .env")


class McpHttpStatusResponse(BaseModel):
    ok: bool = True
    message: str = ""
    running: bool
    host: str
    port: int
    url: str
    token_set: bool
    token_masked: str = ""
    error: str = ""
    pid: Optional[int] = None
    cursor_config: dict = Field(
        default_factory=dict,
        description="可粘贴到 Cursor mcp.json 的片段",
    )


class SettingsUpdateResponse(BaseModel):
    ok: bool = True
    message: str = "已保存"
    settings: SettingsResponse


class Poc16723Request(BaseModel):
    target: str = Field(
        "http://127.0.0.1:18083",
        description="目标基址（默认 CVE-2026-16723 Undertow 靶场）",
    )
    mode: str = Field("http", description="http=jar:http 出网；fd=fd-cache 不出网")
    host: str = Field("attacker", description="攻击者 HTTP 主机（靶场视角）")
    port: int = Field(9192, ge=1, le=65535)
    cmd: str = Field("id", description="执行 / 回显验证命令")
    echo: bool = Field(True, description="回显模式（推荐证明）")
    engine: str = Field(
        "auto",
        description="auto/spring/undertow/tomcat/jetty/weblogic/websphere/resin/struts2/httpserver/dfs",
    )
    json_path: str = Field("/json", description="反序列化路径")
    docker_container: str = Field(
        "cve-2026-16723-undertow",
        description="读证明文件的 docker 容器名；空则禁用",
    )
    reuse_type: Optional[str] = Field(None, description="复用已命中的 @type")
    memshell: bool = Field(
        False, description="注入内存马（默认内置 memshell-gen.jar；也可指定 HTTP boot）"
    )
    ms_api: str = Field(
        "jar",
        description="jar=内置 memshell-gen.jar；或 http(s)://... MemShellParty boot",
    )
    ms_server: str = "Undertow"
    ms_tool: str = "Command"
    ms_type: str = "Filter"
    ms_path: str = "/*"
    ms_jdk: str = "8"


class MemShellGenerateRequest(BaseModel):
    """独立生成内存马（不经 Fastjson 链）。"""

    backend: str = Field(
        "jar",
        description="jar=内置 memshell-gen.jar；或 http(s)://... MemShellParty boot",
    )
    server: str = Field("Undertow", description="中间件类型")
    tool: str = Field("Command", description="C2/管理工具")
    shell_type: str = Field("Filter", description="马类型")
    path: str = Field("/*", description="urlPattern")
    jdk: str = Field("8", description="目标 JDK 大版本")
    static_initialize: bool = Field(
        False, description="BCEL/H2 类加载场景建议 true；Spring XML / Groovy 用 false"
    )


class Poc1247Request(BaseModel):
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
        description="JdbcRowSetImpl.dataSourceName",
    )
    bcel_code: Optional[str] = Field(None, description="$$BCEL$$... 或裸编码")
    class_b64: Optional[str] = Field(None, description=".class Base64（BCEL/H2）")
    user_overrides: Optional[str] = Field(
        None, description="C3P0 HexAsciiSerializedMap:...;"
    )
    serialized_b64: Optional[str] = Field(
        None, description="二次反序列化 gadget Base64"
    )
    h2_url: Optional[str] = Field(None, description="完整 H2 JDBC URL")
    getter_trigger: str = Field(
        "ref",
        description=(
            "ref / json_key / currency / currency_json_key；"
            "有期望类时用 currency 或 currency_json_key"
        ),
    )
    currency_field: str = Field(
        "currency", description="Currency 字段：currency 或 currencyCode"
    )
    json_key_with_type: bool = Field(
        True, description="json_key 是否带 @type=JSONObject"
    )
    json_key_as_array: bool = Field(
        False, description="json_key 用 JSONArray 作 key"
    )
    preset: str = Field(
        "auto",
        description=(
            "预设字节码：auto / custom / touch / exec / echo / memshell（off→custom）；"
            "未提供字节码时 auto 默认生成 exec 类"
        ),
    )
    proof_path: Optional[str] = Field(
        None, description="preset=touch/exec/auto 证明文件路径"
    )
    proof_content: Optional[str] = Field(
        None, description="preset=touch/exec/auto 写入内容前缀"
    )
    echo: bool = Field(
        False, description="兼容旧字段：true 等价于 preset=echo"
    )
    engine: str = Field("auto", description="回显引擎（preset=echo）")
    cmd: str = Field("id", description="回显 / preset=exec 命令")
    cmd_header: str = Field("X-Cmd", description="命令请求头（preset=echo）")
    memshell: bool = Field(
        False, description="兼容旧字段：true 等价于 preset=memshell"
    )
    ms_api: str = Field(
        "jar",
        description="jar=内置 memshell-gen.jar；或 http(s)://... MemShellParty boot",
    )
    ms_server: str = "Undertow"
    ms_tool: str = "Command"
    ms_type: str = "Filter"
    ms_path: str = "/*"
    ms_jdk: str = "8"
    waf_techniques: list[str] = Field(
        default_factory=list,
        description="生成后叠加的 WAF 变换 id（见 GET /api/waf/techniques）",
    )
    waf_options: Optional[WafOptions] = None
    target: str = Field(
        "http://127.0.0.1:18247/api/fastjson",
        description="可选发送目标（send=true 时）",
    )
    send: bool = Field(False, description="是否 POST 到 target")
    timeout: float = Field(10.0, ge=1, le=120)
    headers: dict[str, str] = Field(default_factory=dict)
    proxy: Optional[str] = None
    insecure: bool = False
    content_type: str = "application/json"


class Poc1268Request(BaseModel):
    gadget: str = Field(
        "file_truncate",
        description="见 GET /api/poc/1.2.68/gadgets",
    )
    file: Optional[str] = Field(None, description="写入/截断目标路径")
    content: Optional[str] = Field(None, description="写入内容")
    source: Optional[str] = Field(None, description="file_copy 源路径")
    url: Optional[str] = Field(None, description="io_read_* URL")
    guess_byte: Optional[int] = Field(None, ge=0, le=255)
    bom_bytes: Optional[list[int]] = Field(None)
    read_length: Optional[int] = Field(
        None,
        ge=1,
        le=4096,
        description="io_read_error 爆破最大字节数（send=true 时启用）",
    )
    read_charset: Optional[str] = Field(
        "mixed",
        description="爆破码表：mixed / lower / printable",
    )
    read_charset_bytes: Optional[list[int]] = Field(
        None, description="自定义爆破码表"
    )
    host: Optional[str] = None
    port: Optional[int] = None
    user: Optional[str] = None
    jdbc_url: Optional[str] = None
    mysql_version: Optional[str] = Field(
        "5.1", description="mysql_jdbc：5.1 / 6.0 / 8.0"
    )
    outbound: bool = Field(
        True, description="mysql_jdbc：true=出网；false=NamedPipe 不出网"
    )
    named_pipe_path: Optional[str] = Field(
        "/tmp/mysql.pcap", description="mysql_jdbc 不出网 pipe 路径"
    )
    socket_factory_arg: Optional[str] = None
    wrap_currency: bool = Field(
        False,
        description="套 Currency 触发 getter（业务点有期望类时；与版本无关）",
    )
    currency_field: str = Field(
        "currency", description="Currency 字段：currency 或 currencyCode"
    )
    preset: str = Field(
        "file",
        description=(
            "postgresql_ssrf 预设：file / custom / exec / echo / memshell"
        ),
    )
    class_b64: Optional[str] = Field(
        None, description="preset=custom 时的恶意 .class Base64"
    )
    echo: bool = Field(
        False, description="兼容旧字段：true 等价于 preset=echo"
    )
    engine: str = Field("auto", description="回显引擎（preset=echo）")
    cmd: str = Field("id", description="回显 / preset=exec 命令")
    cmd_header: str = Field("X-Cmd", description="命令请求头（preset=echo）")
    attack_base: Optional[str] = Field(None, description="回显/内存马资源托管基址")
    memshell: bool = Field(
        False, description="兼容旧字段：true 等价于 preset=memshell"
    )
    ms_api: str = Field(
        "jar",
        description="jar=内置 memshell-gen.jar；或 http(s)://... MemShellParty boot",
    )
    ms_server: str = "Undertow"
    ms_tool: str = "Command"
    ms_type: str = "Filter"
    ms_path: str = "/*"
    ms_jdk: str = "8"
    waf_techniques: list[str] = Field(
        default_factory=list,
        description="生成后叠加的 WAF 变换 id（见 GET /api/waf/techniques）",
    )
    waf_options: Optional[WafOptions] = None
    target: str = Field(
        "http://127.0.0.1:18268/api/fastjson",
        description="可选发送目标（send=true 时）",
    )
    send: bool = Field(False, description="是否 POST 到 target")
    timeout: float = Field(15.0, ge=1, le=120)
    headers: dict[str, str] = Field(default_factory=dict)
    proxy: Optional[str] = None
    insecure: bool = False
    content_type: str = "application/json"


class LabStartRequest(BaseModel):
    build: bool = Field(True, description="启动时是否 docker compose --build")
    timeout: float = Field(600.0, ge=30, le=1800, description="compose 超时秒数")
    ports: Optional[dict[str, int]] = Field(
        None,
        description=(
            "主机端口覆盖，key 与靶场 port_infos.key 对应，"
            "如 {\"http\": 19080} 或 CVE 的 {\"http\": 18083, \"jdwp\": 18505}"
        ),
    )


class LabStopRequest(BaseModel):
    remove: bool = Field(True, description="停止后是否移除容器（down / rm）")
    timeout: float = Field(180.0, ge=10, le=600, description="compose 超时秒数")


class Poc1280Request(BaseModel):
    gadget: str = Field(
        "io_write",
        description="见 GET /api/poc/1.2.80/gadgets（一律写文件证明 RCE）",
    )
    file: Optional[str] = Field(None, description="写入目标路径")
    content: Optional[str] = Field(None, description="写入内容")
    url: Optional[str] = Field(None, description="io_copy_write 源 URL")
    guess_byte: Optional[int] = Field(None, ge=0, le=255, description="已废弃")
    host: Optional[str] = None
    port: Optional[int] = None
    user: Optional[str] = None
    outbound: bool = Field(
        True, description="mysql_jdbc：true=出网；false=NamedPipe 不出网"
    )
    named_pipe_path: Optional[str] = Field(
        "/tmp/mysql.pcap", description="mysql_jdbc 不出网 pipe 路径"
    )
    socket_factory_arg: Optional[str] = None
    classpath: Optional[str] = Field(None, description="groovy classpathList jar URL")
    wrap_currency: bool = Field(
        False,
        description="对每步套 Currency 触发 getter（业务点有期望类时；与版本无关）",
    )
    currency_field: str = Field(
        "currency", description="Currency 字段：currency 或 currencyCode"
    )
    preset: str = Field(
        "file",
        description=(
            "postgresql/jython/groovy 预设：file / custom / exec / echo / memshell"
        ),
    )
    class_b64: Optional[str] = Field(
        None, description="preset=custom 时的恶意 .class Base64"
    )
    echo: bool = Field(
        False, description="兼容旧字段：true 等价于 preset=echo"
    )
    engine: str = Field("auto", description="回显引擎（preset=echo）")
    cmd: str = Field("id", description="回显 / preset=exec 命令")
    cmd_header: str = Field("X-Cmd", description="命令请求头（preset=echo）")
    attack_base: Optional[str] = Field(None, description="回显/内存马资源托管基址")
    memshell: bool = Field(
        False, description="兼容旧字段：true 等价于 preset=memshell"
    )
    ms_api: str = Field(
        "jar",
        description="jar=内置 memshell-gen.jar；或 http(s)://... MemShellParty boot",
    )
    ms_server: str = "Undertow"
    ms_tool: str = "Command"
    ms_type: str = "Filter"
    ms_path: str = "/*"
    ms_jdk: str = "8"
    waf_techniques: list[str] = Field(
        default_factory=list,
        description="生成后叠加的 WAF 变换 id（多步链逐步应用）",
    )
    waf_options: Optional[WafOptions] = None
    target: str = Field(
        "http://127.0.0.1:18280/api/fastjson",
        description="可选发送目标（send=true 时）",
    )
    send: bool = Field(False, description="是否按步骤 POST 到 target")
    reset_cache: bool = Field(
        False, description="发送前调用靶场 /api/reset 清空 ParserConfig 缓存"
    )
    timeout: float = Field(20.0, ge=1, le=120)
    headers: dict[str, str] = Field(default_factory=dict)
    proxy: Optional[str] = None
    insecure: bool = False
    content_type: str = "application/json"
