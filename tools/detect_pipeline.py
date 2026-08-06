#!/usr/bin/env python3
"""detect_pipeline — 识别 → 版本 → 期望类（对齐 MCP）。"""

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
        prog="detect_pipeline.py",
        description="识别 → 版本 → 期望类。DNS/CEYE 读 .env（CEYE_TOKEN / CEYE_DOMAIN）。",
    )
    p.add_argument("target", help="反序列化点 URL，例 http://127.0.0.1:18268/api/fastjson")
    p.add_argument(
        "--no-dns-detect",
        action="store_true",
        help="跳过识别阶段 DNS 探针（默认开启）",
    )
    p.add_argument(
        "--include-dns-version",
        action="store_true",
        help="版本探测启用 DNS（默认关闭）",
    )
    p.add_argument("--timeout", type=float, default=10.0, help="请求超时秒数（1–120）")
    p.add_argument("--base-body", default=None, help="期望类探测用原始 JSON body")
    cli_common.add_http_args(p)
    return p


def main() -> None:
    args = _parser().parse_args()
    result = handlers.detect_pipeline(
        args.target,
        include_dns_detect=not args.no_dns_detect,
        include_dns_version=args.include_dns_version,
        timeout=args.timeout,
        headers=cli_common.parse_headers(args.header),
        proxy=args.proxy,
        insecure=args.insecure,
        base_body=args.base_body,
    )
    cli_common.emit(result)


if __name__ == "__main__":
    main()
