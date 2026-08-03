"""FastMCP server: tool registration + stdio / Streamable HTTP factories."""

from __future__ import annotations

from typing import Any, Literal, Optional

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette

from fastjson_toolkit import __version__
from fastjson_toolkit.mcp import tools_impl as tools

PocFamily = Literal["1.2.47", "1.2.68", "1.2.80", "cve-2026-16723"]

INSTRUCTIONS = """
FastjsonExpToolkit MCP：授权测试 / 本地靶场复现。

推荐工作流：
1. detect_pipeline(target) — 识别 → 版本 → 期望类
2. deps_probe(target) — 有报错回显时探测依赖（method=character）
3. poc_catalog / poc_run — 生成或发送 PoC
4. poc_script — 取固定原脚本（如 1.2.68/io_read_error），由 LLM 按环境自行修改
5. docs_list → docs_get(slug) — 先看标题摘要，再读正文
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
            "非 Fastjson 时跳过后续步骤。返回 detect/version/expect 聚合 JSON。"
        ),
    )
    def detect_pipeline(
        target: str,
        include_dns_detect: bool = True,
        include_dns_version: bool = False,
        use_ceye: bool = True,
        dnslog: Optional[str] = None,
        ceye_token: Optional[str] = None,
        ceye_domain: Optional[str] = None,
        ceye_wait: float = 8.0,
        timeout: float = 10.0,
        timing_threshold_ms: float = 800.0,
        headers: Optional[dict[str, str]] = None,
        proxy: Optional[str] = None,
        insecure: bool = False,
        content_type: str = "application/json",
        base_body: Optional[str] = None,
    ) -> dict[str, Any]:
        return tools.detect_pipeline(
            target,
            include_dns_detect=include_dns_detect,
            include_dns_version=include_dns_version,
            use_ceye=use_ceye,
            dnslog=dnslog,
            ceye_token=ceye_token,
            ceye_domain=ceye_domain,
            ceye_wait=ceye_wait,
            timeout=timeout,
            timing_threshold_ms=timing_threshold_ms,
            headers=headers,
            proxy=proxy,
            insecure=insecure,
            content_type=content_type,
            base_body=base_body,
        )

    @mcp.tool(
        name="deps_probe",
        description=(
            "Fastjson 依赖 / classpath 探测。"
            "有报错回显时用 method=character（默认）；"
            "无回显可试 method=dns（需 CEYE）。"
            "可用 classes / categories 缩小扫描范围。"
        ),
    )
    def deps_probe(
        target: str,
        method: str = "character",
        classes: Optional[list[str]] = None,
        categories: Optional[list[str]] = None,
        use_ceye: bool = True,
        dnslog: Optional[str] = None,
        ceye_token: Optional[str] = None,
        ceye_domain: Optional[str] = None,
        ceye_wait: float = 10.0,
        timeout: float = 10.0,
        concurrency: int = 6,
        headers: Optional[dict[str, str]] = None,
        proxy: Optional[str] = None,
        insecure: bool = False,
        content_type: str = "application/json",
    ) -> dict[str, Any]:
        return tools.deps_probe(
            target,
            method=method,
            classes=classes,
            categories=categories,
            use_ceye=use_ceye,
            dnslog=dnslog,
            ceye_token=ceye_token,
            ceye_domain=ceye_domain,
            ceye_wait=ceye_wait,
            timeout=timeout,
            concurrency=concurrency,
            headers=headers,
            proxy=proxy,
            insecure=insecure,
            content_type=content_type,
        )

    @mcp.tool(
        name="poc_catalog",
        description=(
            "列出 PoC gadget（1.2.47 / 1.2.68 / 1.2.80 / cve-2026-16723）、"
            "回显引擎与 WAF 绕过技巧。可选 family 过滤。"
        ),
    )
    def poc_catalog(family: Optional[PocFamily] = None) -> dict[str, Any]:
        return tools.poc_catalog(family)

    @mcp.tool(
        name="poc_run",
        description=(
            "生成或发送 Fastjson PoC。"
            "family: 1.2.47 | 1.2.68 | 1.2.80 | cve-2026-16723。"
            "send 默认 false（仅生成）；true 时 POST 到 target。"
            "cve-2026-16723 始终对 target 执行完整证明。"
            "expect_bypass：1247→currency getter；68/80→wrap_currency。"
            "waf_techniques：WAF 变换 id 列表。"
            "options：其余字段（gadget/preset/echo/memshell 等），见 poc_catalog。"
            "需要按环境改复杂逻辑时，另用 poc_script 取固定原脚本。"
        ),
    )
    def poc_run(
        family: PocFamily,
        send: bool = False,
        target: Optional[str] = None,
        expect_bypass: bool = False,
        waf_techniques: Optional[list[str]] = None,
        waf_options: Optional[dict[str, Any]] = None,
        options: Optional[dict[str, Any]] = None,
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
            "例：family=1.2.68, gadget=io_read_error（报错读；自行改 ERROR_MARKERS 等）。"
        ),
    )
    def poc_script(
        family: Optional[str] = None,
        gadget: Optional[str] = None,
    ) -> dict[str, Any]:
        return tools.poc_script(family=family, gadget=gadget)

    @mcp.tool(
        name="docs_list",
        description=(
            "首次查阅漏洞分析文档：返回 slug / title / description / order。"
            "随后用 docs_get(slug) 获取 Markdown 正文。"
        ),
    )
    def docs_list() -> dict[str, Any]:
        return tools.docs_list()

    @mcp.tool(
        name="docs_get",
        description="按 slug 返回漏洞分析文档 Markdown 正文（先 docs_list 再查阅）。",
    )
    def docs_get(slug: str) -> dict[str, Any]:
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
