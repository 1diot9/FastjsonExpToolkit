"""Smoke tests for portable tools/*.py CLI (MCP-aligned)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def test_docs_list_cli_json() -> None:
    proc = _run(str(TOOLS / "docs_list.py"))
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["ok"] is True
    assert any(d["slug"] == "fastjson-detect" for d in data["docs"])


def test_poc_catalog_cli_json() -> None:
    proc = _run(str(TOOLS / "poc_catalog.py"), "--family", "1.2.68")
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["ok"] is True
    assert "1.2.68" in data["gadgets"]
    assert data["gadgets"]["1.2.68"]


def test_detect_pipeline_help() -> None:
    proc = _run(str(TOOLS / "detect_pipeline.py"), "-h")
    assert proc.returncode == 0
    assert "target" in proc.stdout


def test_docs_get_cli_unknown_exits_1() -> None:
    proc = _run(str(TOOLS / "docs_get.py"), "no-such-doc")
    assert proc.returncode == 1
    data = json.loads(proc.stdout)
    assert data["ok"] is False


@pytest.mark.parametrize(
    "name",
    [
        "detect_pipeline",
        "deps_probe",
        "probe_catalog",
        "probe_get",
        "poc_catalog",
        "poc_meta",
        "poc_get",
        "poc_script",
        "waf_catalog",
        "waf_apply",
        "docs_list",
        "docs_get",
    ],
)
def test_tool_script_exists(name: str) -> None:
    assert (TOOLS / f"{name}.py").is_file()
    assert (TOOLS / f"{name}.sh").is_file()
