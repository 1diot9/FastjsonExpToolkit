#!/usr/bin/env python3
"""waf_catalog — WAF 技巧目录（对齐 MCP）。"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools._lib.bootstrap import ensure_src_path  # noqa: E402

ensure_src_path()

from tools._lib import cli_common, handlers  # noqa: E402


def main() -> None:
    import argparse

    argparse.ArgumentParser(
        prog="waf_catalog.py",
        description="WAF 技巧目录（选型）；详解 docs_get waf-bypass。",
    ).parse_args()
    cli_common.emit(handlers.waf_catalog())


if __name__ == "__main__":
    main()
