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
ProbeKind = Literal["detect", "version", "expect", "deps", "all"]
ProbeGetKind = Literal["detect", "version", "expect"]
WafMode = Literal["stack", "variants"]

INSTRUCTIONS = """
FastjsonExpToolkit MCP：授权测试 / 本地靶场 Fastjson 利用辅助（与 REST 同源）。
定位：探测 + PoC/探针检索 + 本地 WAF 混淆。不代发 exploit。

契约：
- target = JSON 反序列化 POST 点（例 http://127.0.0.1:18268/api/fastjson）。
- 根路径 404 ≠ 非 Fastjson；detect_pipeline 会尝试常见路径。
- SafeMode 低置信；AutoType 关 ≠ SafeMode。
- deps_probe(character) 在 AutoType 关时自动降级 Class MiscCodec。
- 输出刻意精简：poc_get / waf_apply 成功时直接返回 JSON payload 字符串；
  docs_list 仅顶级目录；docs_get(顶级slug) 返回章节目录；docs_get(顶级/章节) 返回该段。

工作流：
1. detect_pipeline(target) → 识别/版本/期望类（CEYE 读 .env）
2. deps_probe(target)
3. 不准 → probe_catalog → probe_get；docs_list → docs_get('fastjson-detect') → docs_get('fastjson-detect/…')
4. poc_catalog(family) → poc_meta(family, gadget) → poc_get → payload
5. 需要时 docs_get(章节) / poc_script / waf_apply；自行 POST

期望类：poc_get(expect_bypass=true)。CEYE 勿在参数传 token。
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
            "识别 → 版本 → 期望类。返回精简决策字段。"
            "CEYE 读 .env。失败时用 probe_catalog / probe_get。"
        ),
    )
    def detect_pipeline(
        target: Annotated[
            str,
            Field(
                description=(
                    "反序列化 URL，如 http://127.0.0.1:18268/api/fastjson。"
                    "也可传站点根，工具会尝试常见路径。必填。"
                )
            ),
        ],
        include_dns_detect: Annotated[
            bool,
            Field(description="识别阶段 DNS/autoType 探针。默认 true。"),
        ] = True,
        include_dns_version: Annotated[
            bool,
            Field(description="版本阶段 DNS 探针（较慢）。默认 false。"),
        ] = False,
        timeout: Annotated[
            float,
            Field(description="HTTP 超时秒数。默认 10。", ge=1, le=120),
        ] = 10.0,
        headers: Annotated[
            Optional[dict[str, str]],
            Field(description="额外请求头。默认 null。"),
        ] = None,
        proxy: Annotated[
            Optional[str],
            Field(description="代理 URL。默认 null。"),
        ] = None,
        insecure: Annotated[
            bool,
            Field(description="跳过 TLS 校验。默认 false。"),
        ] = False,
        base_body: Annotated[
            Optional[str],
            Field(description="期望类探测基线 JSON。默认 null。"),
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
            "依赖探测；默认全量。"
            "character 自动降级 class；无回显试 dns。"
            "失败用 probe_catalog(kind='deps')。"
        ),
    )
    def deps_probe(
        target: Annotated[
            str,
            Field(description="反序列化 URL。必填。"),
        ],
        method: Annotated[
            DepsMethod,
            Field(description="character（默认）| class | dns。"),
        ] = "character",
        classes: Annotated[
            Optional[list[str]],
            Field(description="仅扫这些类名；null=全量。"),
        ] = None,
        timeout: Annotated[
            float,
            Field(description="HTTP 超时秒数。默认 10。", ge=1, le=120),
        ] = 10.0,
        concurrency: Annotated[
            int,
            Field(description="character 并发。默认 6。", ge=1, le=20),
        ] = 6,
        headers: Annotated[
            Optional[dict[str, str]],
            Field(description="额外请求头。默认 null。"),
        ] = None,
        proxy: Annotated[
            Optional[str],
            Field(description="代理 URL。默认 null。"),
        ] = None,
        insecure: Annotated[
            bool,
            Field(description="跳过 TLS 校验。默认 false。"),
        ] = False,
    ) -> dict[str, Any]:
        return tools.deps_probe(
            target,
            method=method,
            classes=classes,
            timeout=timeout,
            concurrency=concurrency,
            headers=headers,
            proxy=proxy,
            insecure=insecure,
        )

    @mcp.tool(
        name="probe_catalog",
        description=(
            "探测探针目录（默认不含 payload）。"
            "完整 payload：probe_get 或 include_payload=true。"
            "deps 返回 templates；详解 docs_get('fastjson-detect')。"
        ),
    )
    def probe_catalog(
        kind: Annotated[
            ProbeKind,
            Field(description="detect|version|expect|deps|all。默认 all。"),
        ] = "all",
        dnslog_host: Annotated[
            Optional[str],
            Field(description="DNSLog 主机；null=仅离线探针。"),
        ] = None,
        base_body: Annotated[
            Optional[str],
            Field(description="expect 基线 JSON。默认 null。"),
        ] = None,
        include_deps_classes: Annotated[
            bool,
            Field(description="deps 是否附类目录。默认 false。"),
        ] = False,
        include_payload: Annotated[
            bool,
            Field(description="目录是否内嵌 payload。默认 false。"),
        ] = False,
    ) -> dict[str, Any]:
        return tools.probe_catalog(
            kind,
            dnslog_host=dnslog_host,
            base_body=base_body,
            include_deps_classes=include_deps_classes,
            include_payload=include_payload,
        )

    @mcp.tool(
        name="probe_get",
        description=(
            "取单条探测探针完整 payload。"
            "先 probe_catalog 看 id；deps 用 catalog.templates。"
        ),
    )
    def probe_get(
        kind: Annotated[
            ProbeGetKind,
            Field(description="detect | version | expect。必填。"),
        ],
        probe_id: Annotated[
            str,
            Field(description="探针 id（来自 probe_catalog）。必填。"),
        ],
        dnslog_host: Annotated[
            Optional[str],
            Field(description="DNSLog 主机（DNS 探针需要）。默认 null。"),
        ] = None,
        base_body: Annotated[
            Optional[str],
            Field(description="expect 基线 JSON。默认 null。"),
        ] = None,
    ) -> dict[str, Any]:
        return tools.probe_get(
            kind,
            probe_id,
            dnslog_host=dnslog_host,
            base_body=base_body,
        )

    @mcp.tool(
        name="poc_catalog",
        description=(
            "按版本列 gadget（id/title/requires/jdk/doc）。"
            "选型后 poc_meta 看参数 → poc_get 生成 payload；文档→docs_get；脚本→poc_script。"
        ),
    )
    def poc_catalog(
        family: Annotated[
            Optional[PocFamily],
            Field(description="1.2.47|1.2.68|1.2.80|cve-2026-16723；null=全部。"),
        ] = None,
    ) -> dict[str, Any]:
        return tools.poc_catalog(family)

    @mcp.tool(
        name="poc_meta",
        description=(
            "返回单个 gadget 的参数元数据（供填写 poc_get）。"
            "每项：flag（=options 键名，如 host）/ required / arg_type / help / default。"
            "另含 tool_args（如 expect_bypass）。先 poc_catalog 选型。"
        ),
    )
    def poc_meta(
        family: Annotated[
            PocFamily,
            Field(description="1.2.47 | 1.2.68 | 1.2.80 | cve-2026-16723。必填。"),
        ],
        gadget: Annotated[
            str,
            Field(description="gadget id（来自 poc_catalog）。必填。"),
        ],
    ) -> dict[str, Any]:
        return tools.poc_meta(family, gadget)

    @mcp.tool(
        name="poc_get",
        description=(
            "生成单个 gadget 的 JSON payload（不发包）。"
            "成功时直接返回 payload 字符串；多步链返回字符串数组。"
            "失败返回 {ok:false,error}。参数先看 poc_meta；文档用 docs_get；脚本用 poc_script。"
            "期望类：expect_bypass=true。cve-2026-16723 不生成。"
        ),
    )
    def poc_get(
        family: Annotated[
            PocFamily,
            Field(description="1.2.47 | 1.2.68 | 1.2.80 | cve-2026-16723。必填。"),
        ],
        gadget: Annotated[
            str,
            Field(description="gadget id（来自 poc_catalog）。必填。"),
        ],
        expect_bypass: Annotated[
            bool,
            Field(
                description=(
                    "期望类绕过：1.2.47→currency；1.2.68/80→wrap_currency。"
                    "默认 false。"
                )
            ),
        ] = False,
        options: Annotated[
            Optional[dict[str, Any]],
            Field(
                description=(
                    "生成参数，键名与 poc_meta().args[].flag 一致。"
                    "勿传 send/target/waf_*。默认 null=用内置默认值。"
                )
            ),
        ] = None,
    ) -> Any:
        return tools.poc_get(
            family,
            gadget,
            expect_bypass=expect_bypass,
            options=options,
        )

    @mcp.tool(
        name="poc_script",
        description=(
            "固定原脚本。不传参列目录；传 family+gadget 返回正文。"
            "与 poc_get / docs_get 分离。"
        ),
    )
    def poc_script(
        family: Annotated[
            Optional[str],
            Field(description="版本族，如 1.2.68。默认 null=列全部。"),
        ] = None,
        gadget: Annotated[
            Optional[str],
            Field(description="gadget id，如 io_read_error。默认 null。"),
        ] = None,
    ) -> dict[str, Any]:
        return tools.poc_script(family=family, gadget=gadget)

    @mcp.tool(
        name="waf_catalog",
        description="WAF 技巧 id/title；详解 docs_get('waf-bypass')。",
    )
    def waf_catalog() -> dict[str, Any]:
        return tools.waf_catalog()

    @mcp.tool(
        name="waf_apply",
        description=(
            "本地 WAF 混淆（不发包）。成功时直接返回 payload 字符串；"
            "mode=variants 返回字符串数组。失败返回 {ok:false,error}。"
        ),
    )
    def waf_apply(
        payload: Annotated[
            str,
            Field(description="原始 JSON payload。必填。"),
        ],
        techniques: Annotated[
            Optional[list[str]],
            Field(description="技巧 id 列表，见 waf_catalog。默认 null。"),
        ] = None,
        mode: Annotated[
            WafMode,
            Field(description="stack（默认）| variants。"),
        ] = "stack",
        options: Annotated[
            Optional[dict[str, Any]],
            Field(description="WafOptions，如 pad_size。默认 null。"),
        ] = None,
    ) -> Any:
        return tools.waf_apply(
            payload,
            techniques=techniques,
            mode=mode,
            options=options,
        )

    @mcp.tool(
        name="docs_list",
        description="文档一级目录：仅返回 top-level slug/title（不含 sections）。",
    )
    def docs_list() -> dict[str, Any]:
        return tools.docs_list()

    @mcp.tool(
        name="docs_get",
        description=(
            "两级读取：docs_get(顶级 slug) 仅返回该文档章节目录；"
            "docs_get(顶级/章节) 返回该段 Markdown。"
        ),
    )
    def docs_get(
        slug: Annotated[
            str,
            Field(
                description=(
                    "文档或章节 slug。例：fastjson-detect（返回章节目录）、"
                    "fastjson-1.2.68/13-1-出网（返回章节正文）。"
                )
            ),
        ],
    ) -> dict[str, Any]:
        return tools.docs_get(slug)

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
