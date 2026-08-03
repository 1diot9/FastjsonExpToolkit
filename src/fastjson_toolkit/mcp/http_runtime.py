"""Dedicated MCP Streamable HTTP runtime (start/stop from settings / CLI)."""

from __future__ import annotations

import os
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

import uvicorn
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware

from fastjson_toolkit.config import mask_secret, update_dotenv
from fastjson_toolkit.mcp.auth import McpTokenMiddleware
from fastjson_toolkit.mcp.server import create_mcp

DEFAULT_MCP_HOST = "127.0.0.1"
DEFAULT_MCP_PORT = 8100

ENV_HOST = "MCP_HTTP_HOST"
ENV_PORT = "MCP_HTTP_PORT"
ENV_TOKEN = "MCP_HTTP_TOKEN"


@dataclass
class McpHttpStatus:
    running: bool
    host: str
    port: int
    url: str
    token_set: bool
    token_masked: str
    error: str = ""
    pid: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "token_set": self.token_set,
            "token_masked": self.token_masked,
            "error": self.error,
            "pid": self.pid,
        }


def load_mcp_http_config() -> tuple[str, int, str]:
    host = (os.environ.get(ENV_HOST) or DEFAULT_MCP_HOST).strip() or DEFAULT_MCP_HOST
    port_raw = (os.environ.get(ENV_PORT) or str(DEFAULT_MCP_PORT)).strip()
    try:
        port = int(port_raw)
    except ValueError:
        port = DEFAULT_MCP_PORT
    if not (1 <= port <= 65535):
        port = DEFAULT_MCP_PORT
    token = (os.environ.get(ENV_TOKEN) or "").strip()
    return host, port, token


def save_mcp_http_config(
    *,
    host: str | None = None,
    port: int | None = None,
    token: str | None = None,
    clear_token: bool = False,
) -> tuple[str, int, str]:
    cur_host, cur_port, cur_token = load_mcp_http_config()
    new_host = (host if host is not None else cur_host).strip() or DEFAULT_MCP_HOST
    new_port = int(port if port is not None else cur_port)
    if not (1 <= new_port <= 65535):
        raise ValueError("port 须在 1–65535")
    if clear_token:
        new_token = ""
    elif token is not None and token.strip():
        new_token = token.strip()
    else:
        new_token = cur_token

    update_dotenv(
        {
            ENV_HOST: new_host,
            ENV_PORT: str(new_port),
            ENV_TOKEN: new_token,
        }
    )
    return new_host, new_port, new_token


def mcp_public_url(host: str, port: int) -> str:
    display = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    return f"http://{display}:{port}/mcp"


def build_mcp_http_app(*, token: str) -> Starlette:
    """Build a fresh FastMCP ASGI app at /mcp with optional token middleware."""
    mcp = create_mcp(**{"streamable_http_path": "/mcp"})
    app = mcp.streamable_http_app()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    if token.strip():
        app.add_middleware(McpTokenMiddleware, expected_token=token.strip())
    return app


def _port_open(host: str, port: int) -> bool:
    probe_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    try:
        with socket.create_connection((probe_host, port), timeout=0.4):
            return True
    except OSError:
        return False


class McpHttpRuntime:
    """Background uvicorn for MCP Streamable HTTP."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None
        self._host = DEFAULT_MCP_HOST
        self._port = DEFAULT_MCP_PORT
        self._token = ""
        self._error = ""

    def status(self) -> McpHttpStatus:
        host, port, token = load_mcp_http_config()
        with self._lock:
            running = bool(
                self._thread
                and self._thread.is_alive()
                and self._server
                and not self._server.should_exit
            )
            if running:
                host, port, token = self._host, self._port, self._token
            return McpHttpStatus(
                running=running,
                host=host,
                port=port,
                url=mcp_public_url(host, port),
                token_set=bool(token),
                token_masked=mask_secret(token) if token else "",
                error=self._error,
                pid=os.getpid() if running else None,
            )

    def start(
        self,
        *,
        host: str | None = None,
        port: int | None = None,
        token: str | None = None,
        persist: bool = True,
    ) -> McpHttpStatus:
        with self._lock:
            cur = self.status()
            if cur.running:
                raise RuntimeError(f"MCP HTTP 已在运行：{cur.url}")

            if persist:
                host, port, token_val = save_mcp_http_config(
                    host=host, port=port, token=token
                )
            else:
                h, p, t = load_mcp_http_config()
                host = (host or h).strip() or DEFAULT_MCP_HOST
                port = int(port if port is not None else p)
                if token is not None and token.strip():
                    token_val = token.strip()
                else:
                    token_val = t

            assert host is not None and port is not None
            if _port_open(host, port):
                raise RuntimeError(f"端口已被占用：{host}:{port}")

            app = build_mcp_http_app(token=token_val)
            config = uvicorn.Config(
                app=app,
                host=host,
                port=port,
                log_level="info",
                access_log=False,
            )
            server = uvicorn.Server(config)
            thread = threading.Thread(
                target=server.run,
                name=f"mcp-http-{port}",
                daemon=True,
            )
            self._server = server
            self._thread = thread
            self._host = host
            self._port = port
            self._token = token_val
            self._error = ""
            thread.start()

        deadline = time.time() + 3.0
        while time.time() < deadline:
            if _port_open(host, port):
                break
            if not thread.is_alive():
                with self._lock:
                    self._error = "MCP HTTP 线程已退出（启动失败）"
                    self._server = None
                    self._thread = None
                raise RuntimeError(self._error)
            time.sleep(0.05)
        else:
            if not _port_open(host, port):
                with self._lock:
                    self._error = f"启动超时，未能监听 {host}:{port}"
                raise RuntimeError(self._error)

        return self.status()

    def stop(self, *, timeout: float = 5.0) -> McpHttpStatus:
        with self._lock:
            server = self._server
            thread = self._thread
            if not server or not thread or not thread.is_alive():
                self._server = None
                self._thread = None
                self._error = ""
                return self.status()
            server.should_exit = True

        thread.join(timeout=timeout)
        with self._lock:
            if thread.is_alive():
                self._error = "停止超时，线程仍在运行"
                raise RuntimeError(self._error)
            self._server = None
            self._thread = None
            self._error = ""
        return self.status()


_runtime: McpHttpRuntime | None = None
_runtime_lock = threading.Lock()


def get_mcp_http_runtime() -> McpHttpRuntime:
    global _runtime
    with _runtime_lock:
        if _runtime is None:
            _runtime = McpHttpRuntime()
        return _runtime
