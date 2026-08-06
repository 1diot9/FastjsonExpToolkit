#!/usr/bin/env python3
"""probe_catalog — 探测探针目录（对齐 MCP）。"""

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
        prog="probe_catalog.py",
        description="列探测探针目录。默认不含 payload；完整 payload 用 --include-payload 或 probe_get。",
    )
    p.add_argument(
        "--kind",
        choices=("detect", "version", "expect", "deps", "all"),
        default="all",
    )
    p.add_argument("--dnslog-host", default=None, help="DNS 探针域名（version/detect）")
    p.add_argument("--base-body", default=None, help="expect 探针基础 JSON")
    p.add_argument(
        "--include-deps-classes",
        action="store_true",
        help="deps 目录附带内置类名列表",
    )
    p.add_argument(
        "--include-payload",
        action="store_true",
        help="目录条目包含完整 payload",
    )
    return p


def main() -> None:
    args = _parser().parse_args()
    result = handlers.probe_catalog(
        args.kind,
        dnslog_host=args.dnslog_host,
        base_body=args.base_body,
        include_deps_classes=args.include_deps_classes,
        include_payload=args.include_payload,
    )
    cli_common.emit(result)


if __name__ == "__main__":
    main()
