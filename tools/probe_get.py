#!/usr/bin/env python3
"""probe_get — 取单条探测探针完整 payload（对齐 MCP）。"""

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
        prog="probe_get.py",
        description="取单条探测探针的完整 payload。",
    )
    p.add_argument("kind", choices=("detect", "version", "expect"))
    p.add_argument("probe_id", help="探针 id（见 probe_catalog）")
    p.add_argument("--dnslog-host", default=None)
    p.add_argument("--base-body", default=None)
    return p


def main() -> None:
    args = _parser().parse_args()
    result = handlers.probe_get(
        args.kind,
        args.probe_id,
        dnslog_host=args.dnslog_host,
        base_body=args.base_body,
    )
    cli_common.emit(result)


if __name__ == "__main__":
    main()
