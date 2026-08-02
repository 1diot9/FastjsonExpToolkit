"""CEYE DNSLog client (api.ceye.io)."""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional

import httpx


DEFAULT_DOMAIN = "hpdth2.ceye.io"
DEFAULT_API = "http://api.ceye.io/v1/records"


@dataclass(frozen=True)
class CeyeConfig:
    token: str
    domain: str = DEFAULT_DOMAIN
    api_base: str = DEFAULT_API

    @classmethod
    def from_env(cls) -> Optional["CeyeConfig"]:
        token = (
            os.environ.get("CEYE_TOKEN")
            or os.environ.get("FJTOOLKIT_CEYE_TOKEN")
            or ""
        ).strip()
        if not token:
            return None
        domain = (
            os.environ.get("CEYE_DOMAIN")
            or os.environ.get("FJTOOLKIT_CEYE_DOMAIN")
            or DEFAULT_DOMAIN
        ).strip()
        return cls(token=token, domain=domain)


@dataclass
class CeyeRecord:
    name: str
    remote_addr: str = ""
    created_at: str = ""
    raw: dict[str, Any] | None = None


class CeyeClient:
    def __init__(self, config: CeyeConfig, timeout: float = 10.0) -> None:
        self.config = config
        self._client = httpx.Client(timeout=timeout, trust_env=False)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "CeyeClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @staticmethod
    def new_filter(prefix: str = "fj") -> str:
        """CEYE filter max length is 20."""
        raw = f"{prefix}{uuid.uuid4().hex}"
        return raw[:20]

    def build_host(self, filter_id: str, tag: str = "") -> str:
        # host label must stay DNS-safe; keep total filter matchable by filter_id
        label = filter_id if not tag else f"{filter_id}{tag}"[:63]
        return f"{label}.{self.config.domain}"

    def query(self, record_type: str = "dns", filter_text: str = "") -> list[CeyeRecord]:
        if len(filter_text) > 20:
            filter_text = filter_text[:20]
        # API doc: type is 'dns' or 'request'
        resp = self._client.get(
            self.config.api_base,
            params={
                "token": self.config.token,
                "type": record_type,
                "filter": filter_text,
            },
        )
        resp.raise_for_status()
        payload = resp.json()
        meta = payload.get("meta") or {}
        if meta.get("code") not in (200, "200", None):
            raise RuntimeError(f"CEYE API error: {meta}")
        rows = payload.get("data") or []
        out: list[CeyeRecord] = []
        for row in rows:
            out.append(
                CeyeRecord(
                    name=str(row.get("name") or row.get("url") or ""),
                    remote_addr=str(row.get("remote_addr") or ""),
                    created_at=str(row.get("created_at") or ""),
                    raw=row,
                )
            )
        return out

    def wait_for_dns(
        self,
        filter_text: str,
        *,
        timeout: float = 8.0,
        interval: float = 1.0,
    ) -> list[CeyeRecord]:
        deadline = time.time() + timeout
        last: list[CeyeRecord] = []
        while time.time() < deadline:
            last = self.query("dns", filter_text)
            if last:
                return last
            time.sleep(interval)
        return last
