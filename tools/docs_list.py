#!/usr/bin/env python3
"""docs_list — 文档一级目录（对齐 MCP）。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools._lib.bootstrap import ensure_src_path  # noqa: E402

ensure_src_path()

from tools._lib import cli_common, handlers  # noqa: E402


def main() -> None:
    argparse.ArgumentParser(
        prog="docs_list.py",
        description="文档一级目录：仅返回 top-level slug/title。",
    ).parse_args()
    cli_common.emit(handlers.docs_list())


if __name__ == "__main__":
    main()
