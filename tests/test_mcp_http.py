"""MCP HTTP auth + runtime tests."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from fastjson_toolkit.mcp.auth import McpTokenMiddleware, extract_mcp_token
from fastjson_toolkit.mcp import http_runtime as runtime
from starlette.datastructures import Headers


def test_extract_mcp_token_header_and_query() -> None:
    assert extract_mcp_token(Headers({"x-mcp-token": "abc"})) == "abc"
    assert (
        extract_mcp_token(Headers({}), query_string=b"token=fromqs") == "fromqs"
    )
    # Authorization: Bearer is intentionally ignored (avoids OAuth misdetection)
    assert extract_mcp_token(Headers({"authorization": "Bearer secret"})) is None


def test_token_middleware_rejects_without_token() -> None:
    async def ok(_request):  # noqa: ANN001
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", endpoint=ok)])
    app.add_middleware(McpTokenMiddleware, expected_token="s3cret")
    client = TestClient(app)
    assert client.get("/").status_code == 401
    # no WWW-Authenticate (would look like OAuth to Cursor)
    assert "www-authenticate" not in {k.lower() for k in client.get("/").headers}
    assert client.get("/", headers={"Authorization": "Bearer s3cret"}).status_code == 401
    assert client.get("/", headers={"X-MCP-Token": "wrong"}).status_code == 401
    assert client.get("/", headers={"X-MCP-Token": "s3cret"}).text == "ok"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_mcp_http_runtime_start_stop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MCP_HTTP_HOST", raising=False)
    monkeypatch.delenv("MCP_HTTP_PORT", raising=False)
    monkeypatch.delenv("MCP_HTTP_TOKEN", raising=False)

    # Isolate singleton
    monkeypatch.setattr(runtime, "_runtime", None)

    port = _free_port()
    rt = runtime.get_mcp_http_runtime()
    st = rt.start(host="127.0.0.1", port=port, token="t0ken", persist=True)
    assert st.running is True
    assert st.url == f"http://127.0.0.1:{port}/mcp"
    assert st.token_set is True

    # Health-ish: port open
    assert runtime._port_open("127.0.0.1", port)

    stopped = rt.stop()
    assert stopped.running is False
