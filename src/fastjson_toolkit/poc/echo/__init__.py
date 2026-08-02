"""通用命令回显（多中间件 / 高版本 JDK）。

参考：pen4uin/java-echo-generator
适配：Unsafe setAccessible（JDK12+）、javax/jakarta DFS、Tomcat WRAP 兜底。
"""

from __future__ import annotations

from fastjson_toolkit.poc.echo.assets import (
    build_groovy_echo_jar,
    build_spring_echo_xml,
    write_echo_attack_files,
)
from fastjson_toolkit.poc.echo.compile import EchoArtifact, build_echo_artifact, compile_java_source
from fastjson_toolkit.poc.echo.engines import (
    BYTECODE_ECHO_GADGETS_1247,
    ECHO_ENGINES,
    EchoEngine,
    GROOVY_ECHO_GADGETS_1280,
    SPRING_XML_ECHO_GADGETS_1268,
    SPRING_XML_ECHO_GADGETS_1280,
    list_engines,
    normalize_engine,
    supports_1268_echo,
    supports_1280_echo,
    supports_bytecode_echo,
)
from fastjson_toolkit.poc.echo.source import (
    DEFAULT_CLASS_NAME,
    DEFAULT_CMD_HEADER,
    build_echo_java_source,
    gen_cmd_header,
    java_string_literal,
)

__all__ = [
    "BYTECODE_ECHO_GADGETS_1247",
    "DEFAULT_CLASS_NAME",
    "DEFAULT_CMD_HEADER",
    "ECHO_ENGINES",
    "EchoArtifact",
    "EchoEngine",
    "GROOVY_ECHO_GADGETS_1280",
    "SPRING_XML_ECHO_GADGETS_1268",
    "SPRING_XML_ECHO_GADGETS_1280",
    "build_echo_artifact",
    "build_echo_java_source",
    "build_groovy_echo_jar",
    "build_spring_echo_xml",
    "compile_java_source",
    "gen_cmd_header",
    "java_string_literal",
    "list_engines",
    "normalize_engine",
    "supports_1268_echo",
    "supports_1280_echo",
    "supports_bytecode_echo",
    "write_echo_attack_files",
]
