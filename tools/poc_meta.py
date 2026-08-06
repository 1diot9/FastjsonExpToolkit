#!/usr/bin/env python3
"""poc_meta — gadget options 元数据（对齐 MCP）。"""

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
        prog="poc_meta.py",
        description="返回 gadget 的 options 参数元数据（供 poc_get 填写）。",
    )
    p.add_argument(
        "family",
        choices=("1.2.47", "1.2.68", "1.2.80", "cve-2026-16723"),
    )
    p.add_argument("gadget", help="gadget id")
    return p


def main() -> None:
    args = _parser().parse_args()
    result = handlers.poc_meta(args.family, args.gadget)
    cli_common.emit(result)


if __name__ == "__main__":
    main()
