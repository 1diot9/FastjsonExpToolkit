"""内存马选项 / 结果模型。"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class MemShellOptions(BaseModel):
    """生成参数（各版本 PoC 共用）。"""

    enabled: bool = Field(False, description="是否注入内存马")
    backend: str = Field(
        "jar",
        description="jar=内置 memshell-gen.jar；或 http(s)://... 回退到 MemShellParty boot",
    )
    server: str = Field("Undertow", description="中间件类型（MemShellParty server）")
    tool: str = Field("Command", description="C2/管理工具")
    shell_type: str = Field("Filter", description="马类型 Filter/Servlet/...")
    path: str = Field("/*", description="urlPattern")
    jdk: str = Field("8", description="目标 JDK 大版本：6/8/9/11/17/21")
    static_initialize: Optional[bool] = Field(
        None,
        description="None 时由投递方式决定；BCEL/H2 类加载场景建议 true",
    )


class MemShellResult(BaseModel):
    """生成结果（含连接信息）。"""

    injector_b64: str
    injector_class: str
    shell_class: str = ""
    injector_size: int = 0
    shell_size: int = 0
    server: str = ""
    tool: str = ""
    shell_type: str = ""
    url_pattern: str = "/*"
    param_name: str = ""
    header_name: str = ""
    header_value: str = ""
    godzilla_pass: str = ""
    godzilla_key: str = ""
    behinder_pass: str = ""
    antsword_pass: str = ""
    connect_info: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)

    def as_info_dict(self) -> dict[str, Any]:
        """与历史 16723 runner 的 memshell_info 字段对齐。"""
        return {
            "injector_b64": self.injector_b64,
            "injector_class": self.injector_class,
            "shell_class": self.shell_class,
            "server": self.server,
            "tool": self.tool,
            "shell_type": self.shell_type,
            "url_pattern": self.url_pattern,
            "param_name": self.param_name,
            "header_name": self.header_name,
            "header_value": self.header_value,
            "godzilla_pass": self.godzilla_pass,
            "godzilla_key": self.godzilla_key,
            "behinder_pass": self.behinder_pass,
            "antsword_pass": self.antsword_pass,
        }
