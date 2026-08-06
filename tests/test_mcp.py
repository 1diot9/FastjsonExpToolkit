"""MCP docs loader + tool handler unit tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from fastjson_toolkit.detect.models import DetectResult, LibraryGuess
from fastjson_toolkit.expect.models import ExpectClassResult
from fastjson_toolkit.mcp import docs_loader, tools_impl
from fastjson_toolkit.mcp.server import create_mcp
from fastjson_toolkit.version.models import VersionResult


def test_docs_list_and_get_from_repo() -> None:
    docs = docs_loader.list_docs()
    assert len(docs) >= 7
    slugs = {d.slug for d in docs}
    assert "fastjson-detect" in slugs
    assert "fastjson-1.2.47" in slugs

    listed = tools_impl.docs_list()
    assert listed["ok"] is True
    d68 = next(d for d in listed["docs"] if d["slug"] == "fastjson-1.2.68")
    assert set(d68) == {"slug", "title"}

    parent = tools_impl.docs_get("fastjson-1.2.68")
    assert parent["ok"] is True
    assert "sections" in parent and parent["sections"]
    assert "content" not in parent
    mysql = next(s for s in parent["sections"] if s["slug"] == "fastjson-1.2.68/13-mysqljdbc")
    assert mysql.get("has_payload") is True
    outbound = next(s for s in parent["sections"] if s["slug"] == "fastjson-1.2.68/13-1-出网")
    assert outbound.get("parent") == "fastjson-1.2.68/13-mysqljdbc"

    body = tools_impl.docs_get("fastjson-1.2.68/13-1-出网")
    assert body["ok"] is True
    assert body["title"] == "13.1 出网"
    assert "JDBC4Connection" in body["content"]
    assert "### 13.2" not in body["content"]
    assert "sections" not in body


def test_docs_get_unknown_slug() -> None:
    out = tools_impl.docs_get("no-such-doc")
    assert out["ok"] is False
    assert "不存在" in out["error"]

    out2 = tools_impl.docs_get("fastjson-1.2.68/no-such-section")
    assert out2["ok"] is False
    assert "章节不存在" in out2["error"]


def test_docs_loader_env_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    md = tmp_path / "sample.md"
    md.write_text(
        "---\ntitle: 样例\ndescription: 摘要\norder: 1\n---\n\n"
        "# Hello\n\nintro\n\n## Payload A\n\n```json\n{\"@type\":\"x\"}\n```\n\n"
        "### Detail\n\nmore\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("FASTJSON_DOCS_DIR", str(tmp_path))
    items = docs_loader.list_docs()
    assert items == [
        docs_loader.DocMeta(
            slug="sample", title="样例", description="摘要", order=1
        )
    ]
    doc = docs_loader.get_doc("sample")
    assert doc.content.startswith("# Hello")

    indexed = docs_loader.list_docs_with_sections()
    assert len(indexed) == 1
    _meta, preamble, sections = indexed[0]
    assert "intro" in preamble
    assert [s.slug for s in sections] == [
        "sample/payload-a",
        "sample/detail",
    ]
    assert sections[0].has_payload is True

    top = docs_loader.get_doc_or_section("sample")
    assert "content" not in top
    assert [s["slug"] for s in top["sections"]] == ["sample/payload-a", "sample/detail"]

    sec = docs_loader.get_doc_or_section("sample/payload-a")
    assert "## Payload A" in sec["content"]
    assert "### Detail" in sec["content"]


def test_detect_pipeline_skips_when_not_fastjson() -> None:
    fake = DetectResult(
        target="http://example/",
        is_fastjson=False,
        confidence=0.1,
        primary_guess=LibraryGuess.GSON,
        summary="not fastjson",
    )
    with patch("tools._lib.handlers.FastjsonDetector") as Det:
        inst = Det.return_value
        inst.detect.return_value = fake
        out = tools_impl.detect_pipeline("http://example/")
    assert out["ok"] is True
    assert out["skipped"] == ["version", "expect"]
    assert "version" not in out
    assert "expect" not in out
    assert "evidence" not in (out.get("detect") or {})
    assert "raw" not in (out.get("detect") or {})
    inst.close.assert_called()


def test_detect_pipeline_runs_version_and_expect() -> None:
    detect = DetectResult(
        target="http://example/",
        is_fastjson=True,
        confidence=0.9,
        primary_guess=LibraryGuess.FASTJSON,
        summary="fastjson",
    )
    version = VersionResult(
        target="http://example/",
        version_range="<=1.2.80",
        summary="<=1.2.80",
    )
    expect = ExpectClassResult(
        target="http://example/",
        has_expect_class=True,
        summary="has expect",
    )
    with (
        patch("tools._lib.handlers.FastjsonDetector") as Det,
        patch("tools._lib.handlers.FastjsonVersionDetector") as Ver,
        patch("tools._lib.handlers.FastjsonExpectClassDetector") as Exp,
    ):
        Det.return_value.detect.return_value = detect
        Ver.return_value.detect.return_value = version
        Exp.return_value.detect.return_value = expect
        out = tools_impl.detect_pipeline("http://example/")

    assert out["ok"] is True
    assert "skipped" not in out
    assert out["version"]["version_range"] == "<=1.2.80"
    assert out["expect"]["has_expect_class"] is True
    assert set(out["detect"]) <= {"is_fastjson", "confidence"}
    assert "summary" not in out["version"]
    assert "evidence" not in out["version"]
    assert any("poc_get" in a for a in out["next"])
    assert not any("poc_run" in a for a in out["next"])


def test_probe_catalog_index_without_payload() -> None:
    out = tools_impl.probe_catalog("all")
    assert out["ok"] is True
    assert out["detect"]
    assert out["version"]
    assert out["expect"]
    assert "payload" not in out["detect"][0]
    assert "templates" in out["deps"]
    assert "${clazz}" in out["deps"]["templates"]["class"]
    assert "classes" not in out["deps"]
    assert out["doc"] == "fastjson-detect"

    with_payload = tools_impl.probe_catalog("detect", include_payload=True)
    assert "payload" in with_payload["detect"][0]


def test_probe_get_returns_payload() -> None:
    cat = tools_impl.probe_catalog("detect")
    pid = cat["detect"][0]["id"]
    got = tools_impl.probe_get("detect", pid)
    assert got["ok"] is True
    assert got["id"] == pid
    assert got["payload"]


def test_poc_get_1247_expect_bypass() -> None:
    fake = MagicMock()
    fake.model_dump = lambda mode="json": {
        "ok": True,
        "gadget": "jdbc_rowset",
        "title": "JdbcRowSet",
        "payload": '{"@type":"x"}',
        "getter_trigger": "currency",
        "requires": ["JDK"],
        "jdk": "any",
        "notes": ["noise"],
        "waf_techniques": [],
    }
    with patch(
        "tools._lib.handlers.generate_poc_1247", return_value=fake
    ) as gen:
        out = tools_impl.poc_get(
            "1.2.47",
            "jdbc_rowset",
            expect_bypass=True,
            options={"jndi_url": "ldap://x"},
        )
    assert out == '{"@type":"x"}'
    kwargs = gen.call_args.args[0]
    assert kwargs.getter_trigger == "currency"


def test_poc_get_1280_expect_bypass() -> None:
    fake = MagicMock()
    fake.model_dump = lambda mode="json": {
        "ok": True,
        "gadget": "io_write",
        "payload": "{}",
        "steps": ["{}"],
        "wrap_currency": True,
    }
    with patch(
        "tools._lib.handlers.generate_poc_1280", return_value=fake
    ) as gen:
        out = tools_impl.poc_get("1.2.80", "io_write", expect_bypass=True)
    assert out == "{}"
    assert gen.call_args.args[0].wrap_currency is True


def test_poc_get_1280_multi_steps() -> None:
    fake = MagicMock()
    fake.model_dump = lambda mode="json": {
        "payload": "step3",
        "steps": ["step1", "step2", "step3"],
    }
    with patch(
        "tools._lib.handlers.generate_poc_1280", return_value=fake
    ):
        out = tools_impl.poc_get("1.2.80", "io_write")
    assert out == ["step1", "step2", "step3"]


def test_poc_get_cve_docs_only() -> None:
    out = tools_impl.poc_get("cve-2026-16723", "cve-2026-16723")
    assert out["ok"] is False
    assert "不生成" in out["error"]
    assert out["doc"] == "fastjson-1.2.83"


def test_poc_meta_mysql_jdbc_args() -> None:
    out = tools_impl.poc_meta("1.2.68", "mysql_jdbc")
    assert out["ok"] is True
    assert out["gadget"] == "mysql_jdbc"
    flags = {a["flag"] for a in out["args"]}
    assert "host" in flags
    assert "outbound" in flags
    assert "mysql_version" in flags
    host = next(a for a in out["args"] if a["flag"] == "host")
    assert host["required"] is False
    assert host["arg_type"] == "str"
    assert "help" in host and host["help"]
    outbound = next(a for a in out["args"] if a["flag"] == "outbound")
    assert outbound["default"] is True
    assert any(a["flag"] == "expect_bypass" for a in out["tool_args"])


def test_poc_meta_unknown_gadget() -> None:
    out = tools_impl.poc_meta("1.2.68", "nope")
    assert out["ok"] is False


def test_poc_catalog_and_mcp_tools_registered() -> None:
    cat = tools_impl.poc_catalog("1.2.47")
    assert cat["ok"] is True
    assert "1.2.47" in cat["gadgets"]
    g0 = cat["gadgets"]["1.2.47"][0]
    assert "id" in g0
    assert "title" in g0
    assert "description" not in g0
    assert "doc" in g0
    assert "echo_engines" not in cat
    assert "expect_bypass_hint" not in cat
    assert "waf_techniques" not in cat

    waf = tools_impl.waf_catalog()
    assert waf["ok"] is True
    assert waf["techniques"]
    assert "description" not in waf["techniques"][0]
    assert set(waf["techniques"][0]) <= {"id", "title"}

    mcp = create_mcp()
    names = sorted(mcp._tool_manager._tools.keys())  # noqa: SLF001
    assert names == [
        "deps_probe",
        "detect_pipeline",
        "docs_get",
        "docs_list",
        "poc_catalog",
        "poc_get",
        "poc_meta",
        "poc_script",
        "probe_catalog",
        "probe_get",
        "waf_apply",
        "waf_catalog",
    ]


def test_mcp_tool_parameters_have_descriptions() -> None:
    """每个带参工具的 JSON Schema 字段都应有 description，便于 LLM 选型。"""
    mcp = create_mcp()
    tools = mcp._tool_manager._tools  # noqa: SLF001
    expected = {
        "detect_pipeline": {
            "target",
            "include_dns_detect",
            "include_dns_version",
            "timeout",
            "headers",
            "proxy",
            "insecure",
            "base_body",
        },
        "deps_probe": {
            "target",
            "method",
            "classes",
            "timeout",
            "concurrency",
            "headers",
            "proxy",
            "insecure",
        },
        "probe_catalog": {
            "kind",
            "dnslog_host",
            "base_body",
            "include_deps_classes",
            "include_payload",
        },
        "probe_get": {"kind", "probe_id", "dnslog_host", "base_body"},
        "poc_catalog": {"family"},
        "poc_meta": {"family", "gadget"},
        "poc_get": {"family", "gadget", "expect_bypass", "options"},
        "poc_script": {"family", "gadget"},
        "waf_catalog": set(),
        "waf_apply": {"payload", "techniques", "mode", "options"},
        "docs_get": {"slug"},
        "docs_list": set(),
    }
    for name, props in expected.items():
        schema = tools[name].parameters
        assert schema.get("type") == "object"
        actual = set(schema.get("properties") or {})
        assert actual == props, f"{name}: {actual} != {props}"
        for prop, meta in (schema.get("properties") or {}).items():
            desc = meta.get("description")
            assert isinstance(desc, str) and desc.strip(), f"{name}.{prop} 缺少 description"


def test_waf_apply_stack() -> None:
    raw = '{"@type":"java.lang.String","val":"a"}'
    out = tools_impl.waf_apply(raw, techniques=["unicode"], mode="stack")
    assert isinstance(out, str)
    assert out != raw or "\\u" in out.lower()


def test_poc_script_lists_and_returns_fixed_template() -> None:
    listed = tools_impl.poc_script()
    assert listed["ok"] is True
    assert any(
        s["family"] == "1.2.68" and s["gadget"] == "io_read_error"
        for s in listed["scripts"]
    )
    assert "summary" not in listed["scripts"][0]

    out = tools_impl.poc_script("1.2.68", "io_read_error")
    assert out["ok"] is True
    assert out["filename"] == "1.2.68_io_read_error.py"
    script = out["script"]
    assert "ERROR_MARKERS" in script
    assert "TARGET =" in script
    assert "FILE_URL =" in script
    compile(script, out["filename"], "exec")

    got = tools_impl.poc_get(
        "1.2.68",
        "io_read_error",
        options={"url": "file:///etc/passwd", "guess_byte": 70},
    )
    assert isinstance(got, str)
    assert "@type" in got


def test_poc_script_unknown() -> None:
    out = tools_impl.poc_script("1.2.47", "nope")
    assert out["ok"] is False
    assert "scripts" in out
