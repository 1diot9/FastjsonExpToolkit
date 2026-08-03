"""MCP HTTP access-token helpers."""

from __future__ import annotations

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send


def extract_mcp_token(headers: Headers, query_string: bytes = b"") -> str | None:
    """Resolve client token from Authorization / X-MCP-Token / ?token=."""
    auth = headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        value = auth[7:].strip()
        if value:
            return value

    header_token = (headers.get("x-mcp-token") or "").strip()
    if header_token:
        return header_token

    if query_string:
        from urllib.parse import parse_qs

        qs = parse_qs(query_string.decode("latin-1"), keep_blank_values=False)
        values = qs.get("token") or []
        if values and values[0].strip():
            return values[0].strip()
    return None


class McpTokenMiddleware:
    """Require a shared access token when ``expected_token`` is non-empty."""

    def __init__(self, app: ASGIApp, expected_token: str) -> None:
        self.app = app
        self.expected_token = (expected_token or "").strip()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.expected_token:
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        got = extract_mcp_token(headers, scope.get("query_string", b"") or b"")
        if got != self.expected_token:
            body = '{"error":"unauthorized","detail":"MCP Token invalid or missing"}'.encode(
                "utf-8"
            )
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json; charset=utf-8"),
                        (b"content-length", str(len(body)).encode("ascii")),
                        (b"www-authenticate", b'Bearer realm="mcp"'),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return

        await self.app(scope, receive, send)
