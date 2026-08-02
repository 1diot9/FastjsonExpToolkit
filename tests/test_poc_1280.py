"""Fastjson ≤1.2.80 RCE 写文件 payload 单测。"""

from __future__ import annotations

from fastjson_toolkit.poc import Poc1280GenerateOptions
from fastjson_toolkit.poc.v1_2_80.catalog import list_gadgets
from fastjson_toolkit.poc.v1_2_80.payloads import (
    build_aspectj_write,
    build_groovy_step1,
    build_groovy_step2,
    build_io_write,
    build_jackson_cache_steps,
    build_postgresql,
    build_steps,
)
from fastjson_toolkit.poc.v1_2_80.service import generate_poc_1280


def test_all_gadgets_are_file_write_rce():
    gadgets = list_gadgets()
    ids = {g["id"] for g in gadgets}
    assert ids == {
        "io_write",
        "io_copy_write",
        "postgresql",
        "mysql_jdbc",
        "groovy",
        "jython",
        "aspectj_write",
    }
    for g in gadgets:
        assert g["marker_file"].startswith("/tmp/fj1280_")
        assert g["marker_content"].startswith("FJ1280_")


def test_jackson_cache_two_steps():
    steps = build_jackson_cache_steps()
    assert len(steps) == 2
    assert "InputCoercionException" in steps[0]
    assert "UTF8StreamJsonParser" in steps[1]


def test_io_write_shape():
    p = build_io_write("/tmp/fj1280_io_write", "FJ1280_IO_WRITE")
    assert "LazyFileOutputStream" in p
    assert '"$ref":"$.abc.bOM"' in p
    assert "java.io.InputStream" in p


def test_io_write_steps():
    steps = build_steps("io_write")
    assert len(steps) == 3
    assert "LazyFileOutputStream" in steps[-1]


def test_aspectj_write_uses_safefile():
    p = build_aspectj_write("/tmp/x", "AB")
    assert "SafeFileOutputStream" in p
    # BufferedOutputStream 8KiB：未 close 时需 pad 落盘
    assert p.count("a") >= 8000


def test_groovy_and_pg():
    assert "CompilationFailedException" in build_groovy_step1()
    assert "evil.jar" in build_groovy_step2()
    assert "PGCopyInputStream" in build_postgresql()
    assert "bean-postgresql.xml" in build_postgresql()


def test_mysql_ends_with_write():
    steps = build_steps("mysql_jdbc")
    assert "CompressedInputStream" in steps[2]
    assert "LazyFileOutputStream" in steps[-1]


def test_generate_service_notes_marker():
    r = generate_poc_1280(Poc1280GenerateOptions(gadget="io_write"))
    assert r.ok
    assert any("写文件证明" in n for n in r.notes)


def test_wrap_currency_on_1280_steps():
    r = generate_poc_1280(
        Poc1280GenerateOptions(gadget="io_write", wrap_currency=True)
    )
    assert r.wrap_currency is True
    assert all("java.util.Currency" in s for s in r.steps)
    assert "java.util.Currency" in r.payload
