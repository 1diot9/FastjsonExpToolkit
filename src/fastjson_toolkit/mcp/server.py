"""FastMCP server: tool registration + stdio / Streamable HTTP factories."""

from __future__ import annotations

from typing import Annotated, Any, Literal, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field
from starlette.applications import Starlette

from fastjson_toolkit import __version__
from fastjson_toolkit.mcp import tools_impl as tools

PocFamily = Literal["1.2.47", "1.2.68", "1.2.80", "cve-2026-16723"]
DepsMethod = Literal["character", "class", "dns"]

INSTRUCTIONS = """
FastjsonExpToolkit MCP：授权测试 / 真实环境 Fastjson 利用辅助（与 REST 同源）。

重要契约：
- target 必须是 JSON 反序列化 POST 点（例 http://127.0.0.1:18268/api/fastjson）。
- 站点根路径 / 常 404，不等于「非 Fastjson」；detect_pipeline 会尝试 /api/health 与常见路径。
- SafeMode 仅为低置信启发式，须与 AutoCloseable 交叉校验；AutoType 关闭 ≠ SafeMode。
- deps_probe(method=character) 会自动校准：AutoType 关闭时改用 Class MiscCodec（类名回显 / null）。
- poc_run io_read_error：options.read_length + send=true 才会逐字节爆破，结果在 read_bytes/read_content。
- 命中判定含 HTTP≥400、响应 "bOM"/"BOM"、或 charSequence（本仓库靶场多为 200+bOM）。
- 本地靶场：18068=版本矩阵（瘦依赖）；18268=1.2.68 gadget（含 commons-io）；先看 health.deps / deps_probe。

推荐工作流：
1. detect_pipeline(target) — 识别 → 版本 → 期望类（DNS/CEYE 读项目 .env）
2. deps_probe(target) — 依赖探测（character 自动降级 class；无回显可试 dns）
3. poc_catalog / poc_run — 生成或发送 PoC（注意 gadget.requires）
4. poc_script — 取固定原脚本（如 1.2.68/io_read_error）按环境改命中特征
5. docs_list → docs_get(slug) — 先看标题摘要，再读正文

CEYE：在 Web 设置页或 .env 配置 CEYE_TOKEN / CEYE_DOMAIN，工具自动使用，勿在参数里传 token。
next_actions 均为可直接调用的工具提示，不要打开 Web 页面路径。
""".strip()


def create_mcp(*, streamable_http_path: str = "/") -> FastMCP:
    mcp = FastMCP(
        "FastjsonExpToolkit",
        instructions=INSTRUCTIONS,
        streamable_http_path=streamable_http_path,
        stateless_http=True,
        json_response=True,
    )

    @mcp.tool(
        name="detect_pipeline",
        description=(
            "Fastjson 探测流水线：识别 →（若为 Fastjson）版本 → 期望类。"
            "target 应为反序列化 POST URL；若传入站点根路径，会尝试 /api/health "
            "与 /api/fastjson 等常见路径。非 Fastjson 时跳过后续步骤。"
            "返回 detect/version/expect；detect.target 可能是解析后的反序列化点。"
            "DNS 探针默认开启；CEYE 读 .env。SafeMode 字段为低置信，已与 AutoCloseable 交叉校验。"
        ),
    )
    def detect_pipeline(
        target: Annotated[
            str,
            Field(
                description=(
                    "目标反序列化 URL，如 http://127.0.0.1:18268/api/fastjson。"
                    "也可传 http://host:port/ ，工具会尝试发现 /api/fastjson。"
                    "必填。"
                )
            ),
        ],
        include_dns_detect: Annotated[
            bool,
            Field(
                description=(
                    "识别阶段是否发送 DNS/autoType 出网探针。"
                    "默认 true；已配置 CEYE 时会轮询确认。"
                )
            ),
        ] = True,
        include_dns_version: Annotated[
            bool,
            Field(
                description=(
                    "版本阶段是否发送 DNS 侧信道探针（较慢）。"
                    "默认 false；仅在报错回显不足、需 DNS 辅助定版本时开启。"
                )
            ),
        ] = False,
        timeout: Annotated[
            float,
            Field(
                description="单次 HTTP 请求超时秒数，范围建议 1–120。默认 10。",
                ge=1,
                le=120,
            ),
        ] = 10.0,
        headers: Annotated[
            Optional[dict[str, str]],
            Field(
                description=(
                    "额外请求头，如 Cookie / Authorization。"
                    "默认 null（不加额外头）。"
                )
            ),
        ] = None,
        proxy: Annotated[
            Optional[str],
            Field(
                description=(
                    "HTTP/HTTPS 代理，如 http://127.0.0.1:8080。"
                    "默认 null（直连）。"
                )
            ),
        ] = None,
        insecure: Annotated[
            bool,
            Field(description="跳过 TLS 证书校验。默认 false。"),
        ] = False,
        base_body: Annotated[
            Optional[str],
            Field(
                description=(
                    "期望类探测用的原始请求 JSON（对象或对象数组）。"
                    "探针会在其上注入 Feature @type / 空键语法。"
                    '默认 null，等价于 {"age":20,"name":"Bob"}。'
                )
            ),
        ] = None,
    ) -> dict[str, Any]:
        return tools.detect_pipeline(
            target,
            include_dns_detect=include_dns_detect,
            include_dns_version=include_dns_version,
            timeout=timeout,
            headers=headers,
            proxy=proxy,
            insecure=insecure,
            base_body=base_body,
        )

    @mcp.tool(
        name="deps_probe",
        description=(
            "Fastjson 依赖 / classpath 探测。"
            "method=character（默认）会先校准：AutoType 关闭时自动改用 Class MiscCodec"
            "（类存在回显类名，不存在为 null）；也可显式 method=class。"
            "无回显可试 method=dns（CEYE 读 .env）。"
            "可用 classes / categories 缩小扫描范围。"
        ),
    )
    def deps_probe(
        target: Annotated[
            str,
            Field(description="目标反序列化 URL（与 detect 相同点）。必填。"),
        ],
        method: Annotated[
            DepsMethod,
            Field(
                description=(
                    "探测方法：character=报错侧信道并自动降级 Class（默认）；"
                    "class=强制 Class MiscCodec（AutoType 关闭推荐）；"
                    "dns=Locale+Inet4（需 .env 中 CEYE，版本敏感）。"
                )
            ),
        ] = "character",
        classes: Annotated[
            Optional[list[str]],
            Field(
                description=(
                    "仅扫描这些全限定类名，如 "
                    '["org.springframework.context.support.ClassPathXmlApplicationContext"]。'
                    "默认 null=用内置目录。"
                )
            ),
        ] = None,
        categories: Annotated[
            Optional[list[str]],
            Field(
                description=(
                    "按类别过滤内置目录，可多选："
                    "aspectj / c3p0 / commons / commons-io / groovy / jackson / "
                    "jdbc / jdk / jython / mybatis / spring / tomcat。"
                    "默认 null=不过滤。"
                )
            ),
        ] = None,
        timeout: Annotated[
            float,
            Field(
                description="单次 HTTP 请求超时秒数。默认 10。",
                ge=1,
                le=120,
            ),
        ] = 10.0,
        concurrency: Annotated[
            int,
            Field(
                description="character 方法并发数，1–20。默认 6。",
                ge=1,
                le=20,
            ),
        ] = 6,
        headers: Annotated[
            Optional[dict[str, str]],
            Field(description="额外请求头。默认 null。"),
        ] = None,
        proxy: Annotated[
            Optional[str],
            Field(description="HTTP/HTTPS 代理 URL。默认 null。"),
        ] = None,
        insecure: Annotated[
            bool,
            Field(description="跳过 TLS 证书校验。默认 false。"),
        ] = False,
    ) -> dict[str, Any]:
        return tools.deps_probe(
            target,
            method=method,
            classes=classes,
            categories=categories,
            timeout=timeout,
            concurrency=concurrency,
            headers=headers,
            proxy=proxy,
            insecure=insecure,
        )

    @mcp.tool(
        name="poc_catalog",
        description=(
            "列出 PoC gadget（1.2.47 / 1.2.68 / 1.2.80 / cve-2026-16723）、"
            "回显引擎与 WAF 绕过技巧。可选 family 过滤。"
            "调用 poc_run 前建议先查目录确认 gadget / preset / engine。"
        ),
    )
    def poc_catalog(
        family: Annotated[
            Optional[PocFamily],
            Field(
                description=(
                    "可选过滤：1.2.47 | 1.2.68 | 1.2.80 | cve-2026-16723。"
                    "默认 null=返回全部 family 的 gadget 与全局 echo/WAF 列表。"
                )
            ),
        ] = None,
    ) -> dict[str, Any]:
        return tools.poc_catalog(family)

    @mcp.tool(
        name="poc_run",
        description=(
            "生成或发送 Fastjson PoC。"
            "先 poc_catalog 看可用 gadget；复杂逻辑改参请用 poc_script 取原脚本。"
            "cve-2026-16723 始终对 target 执行完整证明（忽略 send）。"
        ),
    )
    def poc_run(
        family: Annotated[
            PocFamily,
            Field(
                description=(
                    "PoC 族：1.2.47 | 1.2.68 | 1.2.80 | cve-2026-16723。必填。"
                )
            ),
        ],
        send: Annotated[
            bool,
            Field(
                description=(
                    "是否 POST 到 target。默认 false=仅生成 payload；"
                    "true 时必须有 target（options.target 或本参数 target）。"
                    "cve-2026-16723 始终执行，不受此开关影响。"
                )
            ),
        ] = False,
        target: Annotated[
            Optional[str],
            Field(
                description=(
                    "发送/证明目标 URL。send=true 或 cve-2026-16723 时需要；"
                    "也可放在 options.target。默认 null。"
                )
            ),
        ] = None,
        expect_bypass: Annotated[
            bool,
            Field(
                description=(
                    "存在期望类时的绕过包装："
                    "1.2.47→getter_trigger=currency；"
                    "1.2.68/1.2.80→wrap_currency=true。"
                    "默认 false。"
                )
            ),
        ] = False,
        waf_techniques: Annotated[
            Optional[list[str]],
            Field(
                description=(
                    "生成后叠加的 WAF 变换 id 列表，可多选："
                    "unicode / hex / unicode_hex / unicode_plus / "
                    "hex_ghost / unicode_digit / ghost_bits / "
                    "multi_comma / key_underscore / key_hyphen / key_mixed / "
                    "pad / url_value。"
                    "完整说明见 poc_catalog.waf_techniques。默认 null。"
                )
            ),
        ] = None,
        waf_options: Annotated[
            Optional[dict[str, Any]],
            Field(
                description=(
                    "WAF 变换选项，如 pad 的填充长度等（字段见 WafOptions / poc_catalog）。"
                    "默认 null。"
                )
            ),
        ] = None,
        options: Annotated[
            Optional[dict[str, Any]],
            Field(
                description=(
                    "其余 PoC 字段，随 family 变化；常用："
                    "gadget（必选之一，见 poc_catalog，注意 requires）、"
                    "jndi_url / bcel_code / class_b64（1.2.47）、"
                    "file / content / url / source（1.2.68 文件类）、"
                    "read_length / read_charset / bom_bytes / guess_byte"
                    "（1.2.68 io_read_error：send=true 且 read_length≥1 时逐字节爆破，"
                    "命中=HTTP≥400 或响应含 bOM/BOM/charSequence）、"
                    "preset=auto|custom|touch|exec|echo|memshell、"
                    "echo/engine/cmd/cmd_header、memshell 与 ms_*、"
                    "mode/host/port（cve-2026-16723）、"
                    "timeout/headers/proxy/insecure。"
                    "默认 null=用各 family 默认值。不确定时先 poc_catalog。"
                )
            ),
        ] = None,
    ) -> dict[str, Any]:
        return tools.poc_run(
            family,
            send=send,
            target=target,
            expect_bypass=expect_bypass,
            waf_techniques=waf_techniques,
            waf_options=waf_options,
            options=options,
        )

    @mcp.tool(
        name="poc_script",
        description=(
            "返回固定原脚本供 LLM 按真实环境自行修改（工具不做参数化生成）。"
            "不传参：列出可用脚本（family/gadget/title/summary）。"
            "传 family + gadget：返回脚本正文。"
        ),
    )
    def poc_script(
        family: Annotated[
            Optional[str],
            Field(
                description=(
                    "脚本所属版本族，如 1.2.68。"
                    "与 gadget 同时传入才返回正文；"
                    "仅传 family 可过滤列表。默认 null=列全部。"
                )
            ),
        ] = None,
        gadget: Annotated[
            Optional[str],
            Field(
                description=(
                    "脚本 gadget id，如 io_read_error。"
                    "与 family 成对使用；可用脚本以不传参列出的结果为准。"
                    "默认 null。"
                )
            ),
        ] = None,
    ) -> dict[str, Any]:
        return tools.poc_script(family=family, gadget=gadget)

    @mcp.tool(
        name="docs_list",
        description=(
            "首次查阅漏洞分析文档：返回 slug / title / description / order。"
            "随后用 docs_get(slug) 获取 Markdown 正文。无参数。"
        ),
    )
    def docs_list() -> dict[str, Any]:
        return tools.docs_list()

    @mcp.tool(
        name="docs_get",
        description=(
            "按 slug 返回漏洞分析文档 Markdown 正文。"
            "先 docs_list 获取可用 slug（如 fastjson-detect、fastjson-1.2.47、waf-bypass）。"
        ),
    )
    def docs_get(
        slug: Annotated[
            str,
            Field(
                description=(
                    "文档 slug（不含 .md），来自 docs_list。"
                    "例：fastjson-detect、getter-trigger、waf-bypass。必填。"
                )
            ),
        ],
    ) -> dict[str, Any]:
        return tools.docs_get(slug)

    # Keep a readable version hint for clients that show server info.
    mcp._fjtoolkit_version = __version__  # type: ignore[attr-defined]
    return mcp


_mcp: FastMCP | None = None


def get_mcp() -> FastMCP:
    global _mcp
    if _mcp is None:
        _mcp = create_mcp()
    return _mcp


def get_mcp_http_app() -> Starlette:
    """Streamable HTTP ASGI app；应挂载到 FastAPI 的 ``/mcp``。"""
    return get_mcp().streamable_http_app()


def run_stdio() -> None:
    """阻塞运行 stdio MCP（供 ``fjtoolkit mcp``）。"""
    from fastjson_toolkit.config import load_dotenv

    load_dotenv()
    get_mcp().run(transport="stdio")
