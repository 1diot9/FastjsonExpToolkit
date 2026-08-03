"""统一预设字节码模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

PresetKind = Literal[
    "auto",
    "custom",
    "touch",
    "exec",
    "echo",
    "memshell",
    "file",
    "off",  # legacy → custom
]

# 对外归一化后的有效 kind（不含 auto/off）
ResolvedKind = Literal["custom", "touch", "exec", "echo", "memshell"]


@dataclass
class BytecodePresetOptions:
    """resolve_bytecode_payload 输入。"""

    preset: PresetKind | str = "auto"
    echo: bool = False
    memshell: bool = False

    # touch / exec
    cmd: str = "id"
    proof_path: Optional[str] = None
    proof_content: Optional[str] = None
    class_name: Optional[str] = None
    for_c3p0: bool = False

    # custom 用户自备
    class_b64: Optional[str] = None
    bcel_code: Optional[str] = None
    serialized_b64: Optional[str] = None
    h2_url: Optional[str] = None
    user_overrides: Optional[str] = None

    # echo
    engine: str = "auto"
    cmd_header: str = "X-Cmd"

    # memshell
    ms_api: str = "jar"
    ms_server: str = "Undertow"
    ms_tool: str = "Command"
    ms_type: str = "Filter"
    ms_path: str = "/*"
    ms_jdk: str = "8"
    ms_static_initialize: bool = True
    ms_jar_url: Optional[str] = None
    ms_include_groovy: bool = False

    # 链上下文：用户是否已提供可投递载荷（影响 auto）
    missing_user_payload: bool = True


@dataclass
class BytecodeArtifact:
    """统一字节码产物（各 PoC 只消费此形状）。"""

    kind: ResolvedKind
    class_name: str = ""
    class_bytes: bytes = b""
    class_b64: str = ""
    bcel_code: str = ""
    serialized_b64: Optional[str] = None
    source: str = ""
    cmd: str = ""
    proof_path: Optional[str] = None
    # echo
    cmd_header: str = ""
    engine: str = ""
    # memshell extras
    memshell_info: Optional[dict[str, Any]] = None
    memshell_connect: Optional[str] = None
    notes: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def as_jar(self, entry_name: Optional[str] = None) -> bytes:
        import io
        import zipfile

        name = entry_name or (f"{self.class_name}.class" if self.class_name else "Payload.class")
        raw = self.class_bytes
        if not raw and self.class_b64:
            import base64

            raw = base64.b64decode(self.class_b64)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(name, raw)
        return buf.getvalue()
