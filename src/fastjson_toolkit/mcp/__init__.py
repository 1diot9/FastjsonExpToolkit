"""MCP server for Agent tool calling (stdio + Streamable HTTP)."""

from __future__ import annotations

from typing import Any

__all__ = [
    "create_mcp",
    "get_mcp_http_app",
    "run_stdio",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from fastjson_toolkit.mcp import server

        return getattr(server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
