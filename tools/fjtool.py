#!/usr/bin/env python3
"""Portable Fastjson tools CLI — single entry, MCP-aligned subcommands.

Usage::

    python tools/fjtool.py -h
    python tools/fjtool.py detect_pipeline -h
    ./tools/fjtool.sh docs_list
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools._lib.bootstrap import ensure_src_path  # noqa: E402

ensure_src_path()

from tools._lib import cli_common, handlers  # noqa: E402

_FAMILIES = ("1.2.47", "1.2.68", "1.2.80", "cve-2026-16723")
_RAW_PAYLOAD_CMDS = frozenset({"poc_get", "waf_apply"})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fjtool",
        description=(
            "Fastjson 可迁移 CLI（对齐 MCP）：探测 + PoC/探针检索 + 本地 WAF 混淆；不代发 exploit。"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  fjtool detect_pipeline http://127.0.0.1:18268/api/fastjson\n"
            "  fjtool poc_catalog --family 1.2.68\n"
            "  fjtool poc_get 1.2.68 mysql_jdbc --options '{\"ldap_url\":\"ldap://...\"}'\n"
            "  fjtool docs_get fastjson-detect\n"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    # --- detect_pipeline ---
    p = sub.add_parser(
        "detect_pipeline",
        help="识别 → 版本 → 期望类",
        description="识别 → 版本 → 期望类。DNS/CEYE 读 .env（CEYE_TOKEN / CEYE_DOMAIN）。",
    )
    p.add_argument("target", help="反序列化点 URL")
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

    # --- deps_probe ---
    p = sub.add_parser(
        "deps_probe",
        help="依赖探测",
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

    # --- probe_catalog ---
    p = sub.add_parser(
        "probe_catalog",
        help="探测探针目录",
        description="列探测探针目录。默认不含 payload。",
    )
    p.add_argument(
        "--kind",
        choices=("detect", "version", "expect", "deps", "all"),
        default="all",
    )
    p.add_argument("--dnslog-host", default=None, help="DNS 探针域名")
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

    # --- probe_get ---
    p = sub.add_parser(
        "probe_get",
        help="取单条探测探针 payload",
        description="取单条探测探针的完整 payload。",
    )
    p.add_argument("kind", choices=("detect", "version", "expect"))
    p.add_argument("probe_id", help="探针 id（见 probe_catalog）")
    p.add_argument("--dnslog-host", default=None)
    p.add_argument("--base-body", default=None)

    # --- poc_catalog ---
    p = sub.add_parser(
        "poc_catalog",
        help="PoC gadget 目录",
        description="按版本列 gadget 目录（无 payload 正文）。",
    )
    p.add_argument(
        "--family",
        choices=_FAMILIES,
        default=None,
        help="仅列出该 family；默认全部",
    )

    # --- poc_meta ---
    p = sub.add_parser(
        "poc_meta",
        help="gadget options 元数据",
        description="返回 gadget 的 options 参数元数据（供 poc_get 填写）。",
    )
    p.add_argument("family", choices=_FAMILIES)
    p.add_argument("gadget", help="gadget id")

    # --- poc_get ---
    p = sub.add_parser(
        "poc_get",
        help="生成 PoC payload（不发包）",
        description="生成单个 gadget 的 JSON payload。成功时 stdout 为 payload 字符串。",
    )
    p.add_argument("family", choices=_FAMILIES)
    p.add_argument("gadget", help="gadget id")
    p.add_argument(
        "--expect-bypass",
        action="store_true",
        help="有期望类时绕过（1.2.47→currency；1.2.68/80→wrap_currency）",
    )
    p.add_argument(
        "--options",
        default=None,
        help='gadget 参数 JSON object，例 \'{"ldap_url":"ldap://..."}\'',
    )

    # --- poc_script ---
    p = sub.add_parser(
        "poc_script",
        help="固定原脚本目录/正文",
        description="不传参列目录；传 family+gadget 返回正文。",
    )
    p.add_argument("--family", default=None, help="如 1.2.68")
    p.add_argument("--gadget", default=None, help="如 io_read_error")

    # --- waf_catalog ---
    sub.add_parser(
        "waf_catalog",
        help="WAF 技巧目录",
        description="WAF 技巧目录（选型）；详解 docs_get waf-bypass。",
    )

    # --- waf_apply ---
    p = sub.add_parser(
        "waf_apply",
        help="本地 WAF 混淆（不发包）",
        description="对 payload 做本地 WAF 混淆。成功时 stdout 为变换后 payload。",
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

    # --- docs_list ---
    sub.add_parser(
        "docs_list",
        help="文档一级目录",
        description="文档一级目录：仅返回 top-level slug/title。",
    )

    # --- docs_get ---
    p = sub.add_parser(
        "docs_get",
        help="取文档/章节",
        description="父文档返回 sections；父/章节 返回该段正文。",
    )
    p.add_argument("slug", help="例 fastjson-1.2.68 或 fastjson-1.2.68/13-1-出网")

    return parser


def _dispatch(args: argparse.Namespace) -> Any:
    cmd = args.command
    if cmd == "detect_pipeline":
        return handlers.detect_pipeline(
            args.target,
            include_dns_detect=not args.no_dns_detect,
            include_dns_version=args.include_dns_version,
            timeout=args.timeout,
            headers=cli_common.parse_headers(args.header),
            proxy=args.proxy,
            insecure=args.insecure,
            base_body=args.base_body,
        )
    if cmd == "deps_probe":
        return handlers.deps_probe(
            args.target,
            method=args.method,
            classes=args.classes,
            timeout=args.timeout,
            concurrency=args.concurrency,
            headers=cli_common.parse_headers(args.header),
            proxy=args.proxy,
            insecure=args.insecure,
        )
    if cmd == "probe_catalog":
        return handlers.probe_catalog(
            args.kind,
            dnslog_host=args.dnslog_host,
            base_body=args.base_body,
            include_deps_classes=args.include_deps_classes,
            include_payload=args.include_payload,
        )
    if cmd == "probe_get":
        return handlers.probe_get(
            args.kind,
            args.probe_id,
            dnslog_host=args.dnslog_host,
            base_body=args.base_body,
        )
    if cmd == "poc_catalog":
        return handlers.poc_catalog(args.family)
    if cmd == "poc_meta":
        return handlers.poc_meta(args.family, args.gadget)
    if cmd == "poc_get":
        return handlers.poc_get(
            args.family,
            args.gadget,
            expect_bypass=args.expect_bypass,
            options=cli_common.parse_json_obj(args.options, flag="--options"),
        )
    if cmd == "poc_script":
        return handlers.poc_script(args.family, args.gadget)
    if cmd == "waf_catalog":
        return handlers.waf_catalog()
    if cmd == "waf_apply":
        return handlers.waf_apply(
            args.payload,
            techniques=args.techniques,
            mode=args.mode,
            options=cli_common.parse_json_obj(args.options, flag="--options"),
        )
    if cmd == "docs_list":
        return handlers.docs_list()
    if cmd == "docs_get":
        return handlers.docs_get(args.slug)
    raise SystemExit(f"未知命令: {cmd}")


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    result = _dispatch(args)
    cli_common.emit(result, raw_payload=args.command in _RAW_PAYLOAD_CMDS)


if __name__ == "__main__":
    main()
