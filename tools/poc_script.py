#!/usr/bin/env python3
"""poc_script — 固定原脚本目录 / 正文（对齐 MCP）。"""

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
        prog="poc_script.py",
        description="固定原脚本。不传参列目录；传 family+gadget 返回正文。",
    )
    p.add_argument("--family", default=None, help="如 1.2.68")
    p.add_argument("--gadget", default=None, help="如 io_read_error")
    return p


def main() -> None:
    args = _parser().parse_args()
    result = handlers.poc_script(args.family, args.gadget)
    cli_common.emit(result)


if __name__ == "__main__":
    main()
