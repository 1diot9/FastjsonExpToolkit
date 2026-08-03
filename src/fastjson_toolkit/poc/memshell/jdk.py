"""JDK 版本映射（MemShellParty targetJreVersion）。"""

from __future__ import annotations

# 对外 JDK 大版本 -> class 文件版本
MSHELL_JDK_MAP: dict[str, str] = {
    "6": "50",
    "8": "52",
    "9": "53",
    "11": "55",
    "17": "61",
    "21": "65",
}


def resolve_memshell_jdk(jdk: str) -> tuple[str, str, bool]:
    """返回 (对外版本, targetJreVersion, byPassJavaModule)。JDK>=9 自动开 module bypass。"""
    key = (jdk or "8").strip().lower()
    if key.startswith("java"):
        key = key[4:]
    if key.startswith("jdk"):
        key = key[3:]
    key = key.strip()
    if key not in MSHELL_JDK_MAP:
        raise ValueError(
            f"不支持的 ms_jdk={jdk!r}，可选: {', '.join(sorted(MSHELL_JDK_MAP, key=int))}"
        )
    class_ver = MSHELL_JDK_MAP[key]
    bypass = int(key) >= 9
    return key, class_ver, bypass
