#!/usr/bin/env python3
"""waf_apply — 本地 WAF 混淆（不发包，对齐 MCP）。"""

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
        prog="waf_apply.py",
        description="对 payload 做本地 WAF 混淆（不发包）。成功时 stdout 为变换后 payload。",
    )
    p.add_argument("payload", help="原始 JSON payload 字符串")
    p.add_argument(
        "-t",
        "--technique",
        action="append",
        default=None,
        dest="techniques",
        help="技巧 id，可重复（见 waf_catalog）",
    )
    p.add_argument(
        "--mode",
        choices=("stack", "variants"),
        default="stack",
        help="stack=串联；variants=各技巧独立变体",
    )
    p.add_argument(
        "--options",
        default=None,
        help='WafOptions JSON，例 \'{"pad_size":100}\'',
    )
    return p


def main() -> None:
    args = _parser().parse_args()
    result = handlers.waf_apply(
        args.payload,
        techniques=args.techniques,
        mode=args.mode,
        options=cli_common.parse_json_obj(args.options, flag="--options"),
    )
    cli_common.emit(result, raw_payload=True)


if __name__ == "__main__":
    main()
