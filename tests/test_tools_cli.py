"""Smoke tests for portable tools/fjtool.py CLI (MCP-aligned)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FJTOOL = ROOT / "tools" / "fjtool.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(FJTOOL), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def test_top_level_help_lists_commands() -> None:
    proc = _run("-h")
    assert proc.returncode == 0
    assert "detect_pipeline" in proc.stdout
    assert "docs_list" in proc.stdout


def test_docs_list_cli_json() -> None:
    proc = _run("docs_list")
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["ok"] is True
    assert any(d["slug"] == "fastjson-detect" for d in data["docs"])


def test_poc_catalog_cli_json() -> None:
    proc = _run("poc_catalog", "--family", "1.2.68")
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["ok"] is True
    assert "1.2.68" in data["gadgets"]
    assert data["gadgets"]["1.2.68"]


def test_detect_pipeline_help() -> None:
    proc = _run("detect_pipeline", "-h")
    assert proc.returncode == 0
    assert "target" in proc.stdout


def test_docs_get_cli_unknown_exits_1() -> None:
    proc = _run("docs_get", "no-such-doc")
    assert proc.returncode == 1
    data = json.loads(proc.stdout)
    assert data["ok"] is False


def test_single_entry_files() -> None:
    assert FJTOOL.is_file()
    assert (ROOT / "tools" / "fjtool.sh").is_file()
    # no per-tool scripts
    assert not (ROOT / "tools" / "docs_list.py").exists()
    assert not (ROOT / "tools" / "detect_pipeline.py").exists()
