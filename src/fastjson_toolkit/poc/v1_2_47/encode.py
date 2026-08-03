"""BCEL / HexAscii 编码（兼容入口；实现在 poc.bytecode.encode）。"""

from __future__ import annotations

from fastjson_toolkit.poc.bytecode.encode import (  # noqa: F401
    bcel_code_from_class_bytes,
    bcel_decode,
    bcel_encode,
    c3p0_user_overrides,
    class_bytes_from_bcel_code,
    ensure_bcel_code,
    ensure_c3p0_user_overrides,
    to_hex_ascii,
)

__all__ = [
    "bcel_code_from_class_bytes",
    "bcel_decode",
    "bcel_encode",
    "c3p0_user_overrides",
    "class_bytes_from_bcel_code",
    "ensure_bcel_code",
    "ensure_c3p0_user_overrides",
    "to_hex_ascii",
]
