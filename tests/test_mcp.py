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
    assert any(d["slug"] == "waf-bypass" for d in listed["docs"])

    body = tools_impl.docs_get("getter-trigger")
    assert body["ok"] is True
    assert body["title"]
    assert "Getter" in body["content"] or "getter" in body["content"].lower()
    assert not body["content"].lstrip().startswith("---")


def test_docs_get_unknown_slug() -> None:
    out = tools_impl.docs_get("no-such-doc")
    assert out["ok"] is False
    assert "不存在" in out["error"]


def test_docs_loader_env_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    md = tmp_path / "sample.md"
    md.write_text(
        "---\ntitle: 样例\ndescription: 摘要\norder: 1\n---\n\n# Hello\n",
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


def test_detect_pipeline_skips_when_not_fastjson() -> None:
    fake = DetectResult(
        target="http://example/",
        is_fastjson=False,
        confidence=0.1,
        primary_guess=LibraryGuess.GSON,
        summary="not fastjson",
    )
    with patch("fastjson_toolkit.mcp.tools_impl.FastjsonDetector") as Det:
        inst = Det.return_value
        inst.detect.return_value = fake
        out = tools_impl.detect_pipeline("http://example/")
    assert out["ok"] is True
    assert out["skipped"] == ["version", "expect"]
    assert out["version"] is None
    assert out["expect"] is None
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
        patch("fastjson_toolkit.mcp.tools_impl.FastjsonDetector") as Det,
        patch("fastjson_toolkit.mcp.tools_impl.FastjsonVersionDetector") as Ver,
        patch("fastjson_toolkit.mcp.tools_impl.FastjsonExpectClassDetector") as Exp,
    ):
        Det.return_value.detect.return_value = detect
        Ver.return_value.detect.return_value = version
        Exp.return_value.detect.return_value = expect
        out = tools_impl.detect_pipeline("http://example/")

    assert out["ok"] is True
    assert out["skipped"] == []
    assert out["version"]["version_range"] == "<=1.2.80"
    assert out["expect"]["has_expect_class"] is True
    assert any("expect_bypass" in a for a in out["next_actions"])


def test_poc_run_expect_bypass_maps_1247() -> None:
    captured: dict = {}

    def fake_run(opts):  # noqa: ANN001
        captured["getter_trigger"] = opts.getter_trigger
        captured["send"] = opts.send
        return MagicMock(model_dump=lambda mode="json": {"payload": "{}"})

    with (
        patch("fastjson_toolkit.mcp.tools_impl.get_poc_1247_gadget"),
        patch("fastjson_toolkit.mcp.tools_impl.run_poc_1247", side_effect=fake_run),
    ):
        out = tools_impl.poc_run(
            "1.2.47",
            send=False,
            expect_bypass=True,
            options={"gadget": "jdbc_rowset"},
        )
    assert out["ok"] is True
    assert captured["getter_trigger"] == "currency"
    assert captured["send"] is False


def test_poc_run_expect_bypass_maps_1280() -> None:
    captured: dict = {}

    def fake_run(opts):  # noqa: ANN001
        captured["wrap_currency"] = opts.wrap_currency
        return MagicMock(model_dump=lambda mode="json": {"steps": []})

    with (
        patch("fastjson_toolkit.mcp.tools_impl.get_poc_1280_gadget"),
        patch("fastjson_toolkit.mcp.tools_impl.run_poc_1280", side_effect=fake_run),
    ):
        out = tools_impl.poc_run(
            "1.2.80",
            expect_bypass=True,
            options={"gadget": "io_write"},
        )
    assert out["ok"] is True
    assert captured["wrap_currency"] is True


def test_poc_catalog_and_mcp_tools_registered() -> None:
    cat = tools_impl.poc_catalog("1.2.47")
    assert cat["ok"] is True
    assert "1.2.47" in cat["gadgets"]
    assert cat["echo_engines"]
    assert cat["waf_techniques"]

    mcp = create_mcp()
    # FastMCP keeps tools in _tool_manager
    names = sorted(mcp._tool_manager._tools.keys())  # noqa: SLF001
    assert names == [
        "deps_probe",
        "detect_pipeline",
        "docs_get",
        "docs_list",
        "poc_catalog",
        "poc_run",
        "poc_script",
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
            "categories",
            "timeout",
            "concurrency",
            "headers",
            "proxy",
            "insecure",
        },
        "poc_catalog": {"family"},
        "poc_run": {
            "family",
            "send",
            "target",
            "expect_bypass",
            "waf_techniques",
            "waf_options",
            "options",
        },
        "poc_script": {"family", "gadget"},
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


def test_poc_script_lists_and_returns_fixed_template() -> None:
    listed = tools_impl.poc_script()
    assert listed["ok"] is True
    assert any(
        s["family"] == "1.2.68" and s["gadget"] == "io_read_error"
        for s in listed["scripts"]
    )

    out = tools_impl.poc_script("1.2.68", "io_read_error")
    assert out["ok"] is True
    assert out["filename"] == "1.2.68_io_read_error.py"
    script = out["script"]
    assert "ERROR_MARKERS" in script
    assert "TARGET =" in script
    assert "FILE_URL =" in script
    compile(script, out["filename"], "exec")


def test_poc_script_unknown() -> None:
    out = tools_impl.poc_script("1.2.47", "nope")
    assert out["ok"] is False
    assert "scripts" in out
