"""Fixed PoC reference scripts for Agent / MCP (LLM adapts them)."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from typing import Optional


@dataclass(frozen=True)
class ScriptMeta:
    family: str
    gadget: str
    filename: str
    title: str
    summary: str


# Only scripts that need LLM-side edits. Use poc_run for one-shot payloads.
SCRIPTS: tuple[ScriptMeta, ...] = (
    ScriptMeta(
        family="1.2.68",
        gadget="io_read_error",
        filename="1.2.68_io_read_error.py",
        title="commons-io 报错读文件",
        summary=(
            "逐字节 BOM 爆破读文件/目录。请按目标响应自行修改脚本内 "
            "ERROR_MARKERS / MATCH_STATUS_GE / MATCH_BOM / TARGET / FILE_URL。"
        ),
    ),
)


def list_scripts() -> list[ScriptMeta]:
    return list(SCRIPTS)


def get_script(family: str, gadget: str) -> tuple[ScriptMeta, str]:
    fam = (family or "").strip()
    gid = (gadget or "").strip()
    for meta in SCRIPTS:
        if meta.family == fam and meta.gadget == gid:
            pkg = resources.files("fastjson_toolkit.poc.scripts") / "templates"
            text = (pkg / meta.filename).read_text(encoding="utf-8")
            return meta, text
    known = ", ".join(f"{m.family}/{m.gadget}" for m in SCRIPTS) or "(none)"
    raise FileNotFoundError(f"no fixed script: {fam}/{gid}; available: {known}")


def find_script(family: Optional[str] = None, gadget: Optional[str] = None) -> list[ScriptMeta]:
    items = list_scripts()
    if family:
        items = [m for m in items if m.family == family.strip()]
    if gadget:
        items = [m for m in items if m.gadget == gadget.strip()]
    return items


__all__ = [
    "SCRIPTS",
    "ScriptMeta",
    "find_script",
    "get_script",
    "list_scripts",
]
