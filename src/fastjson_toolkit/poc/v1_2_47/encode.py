"""BCEL / HexAscii 编码（对齐 Apache BCEL Utility 与 c3p0 HexAsciiSerializedMap）。"""

from __future__ import annotations

import gzip


_ESCAPE = "$"
_FREE_CHARS = 48
_CHAR_MAP: list[str] = []
_MAP_CHAR: dict[int, int] = {}


def _init_char_map() -> None:
    if _CHAR_MAP:
        return
    j = 0
    for i in range(ord("A"), ord("Z") + 1):
        _CHAR_MAP.append(chr(i))
        _MAP_CHAR[i] = j
        j += 1
    for i in range(ord("g"), ord("z") + 1):
        _CHAR_MAP.append(chr(i))
        _MAP_CHAR[i] = j
        j += 1
    _CHAR_MAP.append("$")
    _MAP_CHAR[ord("$")] = j
    j += 1
    _CHAR_MAP.append("_")
    _MAP_CHAR[ord("_")] = j


def _is_java_identifier_part(ch: int) -> bool:
    return (
        (ord("a") <= ch <= ord("z"))
        or (ord("A") <= ch <= ord("Z"))
        or (ord("0") <= ch <= ord("9"))
        or ch == ord("_")
    )


def bcel_encode(data: bytes, *, compress: bool = True) -> str:
    """Apache BCEL ``Utility.encode`` 的 Python 移植；返回不含 ``$$BCEL$$`` 前缀的编码串。"""
    _init_char_map()
    # 对齐 Java GZIPOutputStream：mtime=0，便于与 javap/工具互操作。
    raw = gzip.compress(data, mtime=0) if compress else data

    out: list[str] = []
    for b in raw:
        if _is_java_identifier_part(b) and b != ord(_ESCAPE):
            out.append(chr(b))
            continue
        out.append(_ESCAPE)
        if 0 <= b < _FREE_CHARS:
            out.append(_CHAR_MAP[b])
        else:
            hx = format(b, "x")
            if len(hx) == 1:
                out.append("0")
            out.append(hx)
    return "".join(out)


def bcel_code_from_class_bytes(data: bytes, *, compress: bool = True) -> str:
    """生成 ``$$BCEL$$...`` 形式的 driverClassName / driver。"""
    return "$$BCEL$$" + bcel_encode(data, compress=compress)


def ensure_bcel_code(value: str) -> str:
    """接受裸编码或已带 ``$$BCEL$$`` 前缀的字符串。"""
    v = value.strip()
    if not v:
        raise ValueError("bcel_code 不能为空")
    if v.startswith("$$BCEL$$"):
        return v
    return "$$BCEL$$" + v


def to_hex_ascii(data: bytes) -> str:
    """c3p0 ``HexAsciiSerializedMap`` 用的大写十六进制串。"""
    return "".join(f"{b:02X}" for b in data)


def c3p0_user_overrides(data: bytes) -> str:
    return f"HexAsciiSerializedMap:{to_hex_ascii(data)};"


def ensure_c3p0_user_overrides(value: str) -> str:
    v = value.strip()
    if not v:
        raise ValueError("user_overrides / serialized 不能为空")
    if v.startswith("HexAsciiSerializedMap:"):
        return v if v.endswith(";") else v + ";"
    # 纯 hex 或 hex+分号
    hx = v[:-1] if v.endswith(";") else v
    if all(c in "0123456789abcdefABCDEF" for c in hx) and len(hx) % 2 == 0:
        return f"HexAsciiSerializedMap:{hx.upper()};"
    raise ValueError("期望 HexAsciiSerializedMap:...; 或偶数长度 hex")
