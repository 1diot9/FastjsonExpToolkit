"""Shared argparse helpers for tools/*.py entrypoints."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Callable, Optional


def parse_headers(items: Optional[list[str]]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in items or []:
        if ":" not in item:
            raise SystemExit(f"非法 header: {item}（期望 Key:Value）")
        k, v = item.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def parse_json_obj(raw: Optional[str], *, flag: str) -> dict[str, Any] | None:
    if raw is None or raw.strip() == "":
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{flag} 不是合法 JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"{flag} 须为 JSON object")
    return data


def add_http_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        default=None,
        help="额外请求头 Key:Value，可重复",
    )
    parser.add_argument("--proxy", default=None, help="HTTP 代理")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="跳过 TLS 校验",
    )


def emit(result: Any, *, raw_payload: bool = False) -> None:
    """Print handler result as JSON (or bare payload string for poc_get / waf_apply).

    Exit 1 when result is a dict with ``ok: false``.
    """
    failed = isinstance(result, dict) and result.get("ok") is False
    if raw_payload and isinstance(result, (str, list)):
        # Match MCP: successful poc_get / waf_apply return payload directly.
        if isinstance(result, list):
            sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        else:
            sys.stdout.write(result if result.endswith("\n") else result + "\n")
    else:
        sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    if failed:
        raise SystemExit(1)


def run_tool(
    build_parser: Callable[[], argparse.ArgumentParser],
    invoke: Callable[[argparse.Namespace], Any],
    *,
    raw_payload: bool = False,
) -> None:
    from tools._lib.bootstrap import ensure_src_path

    ensure_src_path()
    parser = build_parser()
    args = parser.parse_args()
    result = invoke(args)
    emit(result, raw_payload=raw_payload)
