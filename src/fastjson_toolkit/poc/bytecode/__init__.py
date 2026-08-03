"""预设字节码：custom / touch / exec / echo / memshell。"""

from __future__ import annotations

from fastjson_toolkit.poc.bytecode.client import (
    encode_bcel_via_jar,
    generate_touch_exec,
    resolve_jar_path,
    serialize_via_jar,
)
from fastjson_toolkit.poc.bytecode.compile import (
    PresetArtifact,
    PresetChoice,
    build_preset_artifact,
)
from fastjson_toolkit.poc.bytecode.models import (
    BytecodeArtifact,
    BytecodePresetOptions,
    PresetKind,
    ResolvedKind,
)
from fastjson_toolkit.poc.bytecode.resolve import (
    default_proof_content,
    default_proof_path,
    has_user_bytecode,
    normalize_preset_choice,
    normalize_preset_kind,
    resolve_bytecode_payload,
    resolve_preset_mode,
    wrap_user_bytecode,
)
from fastjson_toolkit.poc.bytecode.source import (
    DEFAULT_SER_CLASS,
    DEFAULT_STATIC_CLASS,
    PresetMode,
    build_serializable_payload_source,
    build_static_payload_source,
)

__all__ = [
    "DEFAULT_SER_CLASS",
    "DEFAULT_STATIC_CLASS",
    "BytecodeArtifact",
    "BytecodePresetOptions",
    "PresetArtifact",
    "PresetChoice",
    "PresetKind",
    "PresetMode",
    "ResolvedKind",
    "build_preset_artifact",
    "build_serializable_payload_source",
    "build_static_payload_source",
    "default_proof_content",
    "default_proof_path",
    "encode_bcel_via_jar",
    "generate_touch_exec",
    "has_user_bytecode",
    "normalize_preset_choice",
    "normalize_preset_kind",
    "resolve_bytecode_payload",
    "resolve_jar_path",
    "resolve_preset_mode",
    "serialize_via_jar",
    "wrap_user_bytecode",
]
