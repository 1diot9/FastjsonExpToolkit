"""内存马生成与投递（内置 MemShellParty fat jar，无需常驻 boot 进程）。"""

from __future__ import annotations

from fastjson_toolkit.poc.memshell.auth import (
    format_memshell_connect_info,
    randomize_memshell_auth,
)
from fastjson_toolkit.poc.memshell.client import (
    DEFAULT_MSHELL_BACKEND,
    fetch_config,
    generate_memshell,
    memshell_generate,
)
from fastjson_toolkit.poc.memshell.delivery import (
    MemShellDelivery,
    build_memshell_delivery,
    write_spring_memshell_attack_files,
)
from fastjson_toolkit.poc.memshell.jdk import MSHELL_JDK_MAP, resolve_memshell_jdk
from fastjson_toolkit.poc.memshell.models import MemShellOptions, MemShellResult
from fastjson_toolkit.poc.memshell.support import (
    MEMSHELL_GADGETS_1247,
    MEMSHELL_GADGETS_1268,
    MEMSHELL_GADGETS_1280,
    supports_1247_memshell,
    supports_1268_memshell,
    supports_1280_memshell,
)

__all__ = [
    "DEFAULT_MSHELL_BACKEND",
    "MEMSHELL_GADGETS_1247",
    "MEMSHELL_GADGETS_1268",
    "MEMSHELL_GADGETS_1280",
    "MSHELL_JDK_MAP",
    "MemShellDelivery",
    "MemShellOptions",
    "MemShellResult",
    "build_memshell_delivery",
    "fetch_config",
    "format_memshell_connect_info",
    "generate_memshell",
    "memshell_generate",
    "randomize_memshell_auth",
    "resolve_memshell_jdk",
    "supports_1247_memshell",
    "supports_1268_memshell",
    "supports_1280_memshell",
    "write_spring_memshell_attack_files",
]
