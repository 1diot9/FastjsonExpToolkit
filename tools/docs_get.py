#!/usr/bin/env python3
"""docs_get — 按 slug 取文档 / 章节（对齐 MCP）。"""

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
        prog="docs_get.py",
        description="父文档返回 sections；父/章节 返回该段正文。",
    )
    p.add_argument("slug", help="例 fastjson-1.2.68 或 fastjson-1.2.68/13-1-出网")
    return p


def main() -> None:
    args = _parser().parse_args()
    cli_common.emit(handlers.docs_get(args.slug))


if __name__ == "__main__":
    main()
