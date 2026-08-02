"""HTTP helper for probe delivery."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional

import httpx


@dataclass
class HttpResponse:
    status_code: int
    text: str
    elapsed_ms: float
    headers: dict[str, str]


class HttpClient:
    """Reuse one httpx client — creating a client per request is multi-second on Windows."""

    def __init__(
        self,
        timeout: float = 10.0,
        headers: Optional[Mapping[str, str]] = None,
        proxy: Optional[str] = None,
        verify: bool = True,
        trust_env: bool = False,
    ) -> None:
        self._headers = dict(headers or {})
        self._client = httpx.Client(
            timeout=timeout,
            proxy=proxy,
            verify=verify,
            follow_redirects=True,
            # Avoid Windows system-proxy / env lookup cost on every new client.
            trust_env=trust_env,
        )

    def post_raw(self, url: str, body: str, content_type: str = "application/json") -> HttpResponse:
        headers = {"Content-Type": content_type, **self._headers}
        resp = self._client.post(url, content=body.encode("utf-8"), headers=headers)
        return HttpResponse(
            status_code=resp.status_code,
            text=resp.text,
            elapsed_ms=resp.elapsed.total_seconds() * 1000.0,
            headers={k: v for k, v in resp.headers.items()},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
