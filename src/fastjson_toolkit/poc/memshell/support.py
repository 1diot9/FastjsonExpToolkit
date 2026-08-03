"""支持内存马的 gadget 目录。"""

from __future__ import annotations

from fastjson_toolkit.poc.echo.engines import (
    BYTECODE_ECHO_GADGETS_1247,
    GROOVY_ECHO_GADGETS_1280,
    SPRING_XML_ECHO_GADGETS_1268,
    SPRING_XML_ECHO_GADGETS_1280,
)

# 与回显同一批「可投递任意字节码」的链（不含 jdbc_rowset JNDI）
MEMSHELL_GADGETS_1247: frozenset[str] = frozenset(BYTECODE_ECHO_GADGETS_1247)
MEMSHELL_GADGETS_1268: frozenset[str] = frozenset(SPRING_XML_ECHO_GADGETS_1268)
MEMSHELL_GADGETS_1280: frozenset[str] = frozenset(
    SPRING_XML_ECHO_GADGETS_1280 | GROOVY_ECHO_GADGETS_1280
)


def supports_1247_memshell(gadget: str) -> bool:
    return gadget in MEMSHELL_GADGETS_1247


def supports_1268_memshell(gadget: str) -> bool:
    return gadget in MEMSHELL_GADGETS_1268


def supports_1280_memshell(gadget: str) -> bool:
    return gadget in MEMSHELL_GADGETS_1280
