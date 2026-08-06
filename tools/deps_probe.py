#!/usr/bin/env python3
"""deps_probe — 依赖探测（对齐 MCP）。"""

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
        prog="deps_probe.py",
        description="依赖探测。character 在 AutoType 关时自动降级 Class MiscCodec。",
    )
    p.add_argument("target", help="反序列化点 URL")
    p.add_argument(
        "--method",
        choices=("character", "class", "dns"),
        default="character",
        help="探测方法（默认 character）",
    )
    p.add_argument(
        "--class",
        dest="classes",
        action="append",
        default=None,
        help="仅扫描该类名，可重复；默认全量目录",
    )
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--concurrency", type=int, default=6, help="character 并发（1–20）")
    cli_common.add_http_args(p)
    return p


def main() -> None:
    args = _parser().parse_args()
    result = handlers.deps_probe(
        args.target,
        method=args.method,
        classes=args.classes,
        timeout=args.timeout,
        concurrency=args.concurrency,
        headers=cli_common.parse_headers(args.header),
        proxy=args.proxy,
        insecure=args.insecure,
    )
    cli_common.emit(result)


if __name__ == "__main__":
    main()
