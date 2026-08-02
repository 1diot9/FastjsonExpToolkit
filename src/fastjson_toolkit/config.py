"""Runtime config helpers."""

from __future__ import annotations

import os
import re
from pathlib import Path

_CEYE_SUFFIX = ".ceye.io"


def project_root() -> Path:
    """.../FastjsonExpToolkit"""
    return Path(__file__).resolve().parents[2]


def dotenv_candidates(path: Path | None = None) -> list[Path]:
    if path is not None:
        return [path]
    return [Path.cwd() / ".env", project_root() / ".env"]


def find_dotenv(path: Path | None = None) -> Path | None:
    for env_path in dotenv_candidates(path):
        if env_path.is_file():
            return env_path
    return None


def resolve_dotenv_path(path: Path | None = None) -> Path:
    """Prefer an existing .env; otherwise write to project root."""
    found = find_dotenv(path)
    if found is not None:
        return found
    if path is not None:
        return path
    return project_root() / ".env"


def load_dotenv(path: Path | None = None, *, override: bool = False) -> Path | None:
    """Minimal .env loader (no external dependency)."""
    env_path = find_dotenv(path)
    if env_path is None:
        return None

    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if override or key not in os.environ:
            os.environ[key] = value
    return env_path


def update_dotenv(updates: dict[str, str], path: Path | None = None) -> Path:
    """Upsert keys in .env and sync os.environ. Preserves comments/other keys."""
    env_path = resolve_dotenv_path(path)
    lines: list[str] = []
    if env_path.is_file():
        lines = env_path.read_text(encoding="utf-8").splitlines()

    remaining = dict(updates)
    new_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            new_lines.append(line)
            continue
        key, _ = line.split("=", 1)
        key = key.strip()
        if key in remaining:
            new_lines.append(f"{key}={remaining.pop(key)}")
        else:
            new_lines.append(line)

    if remaining:
        if new_lines and new_lines[-1].strip():
            new_lines.append("")
        for key, value in remaining.items():
            new_lines.append(f"{key}={value}")

    env_path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(new_lines)
    if text and not text.endswith("\n"):
        text += "\n"
    env_path.write_text(text, encoding="utf-8")

    for key, value in updates.items():
        os.environ[key] = value
    return env_path


def normalize_ceye_identifier(value: str) -> tuple[str, str]:
    """
    Accept identifier (`hpdth2`) or full domain (`hpdth2.ceye.io`).
    Returns (identifier, domain).
    """
    raw = value.strip().lower().rstrip(".")
    if not raw:
        raise ValueError("CEYE Identifier 不能为空")

    if raw.endswith(_CEYE_SUFFIX):
        domain = raw
        identifier = raw[: -len(_CEYE_SUFFIX)]
    elif "." in raw:
        # Allow custom dnslog-like host; treat whole string as domain.
        domain = raw
        identifier = raw.split(".", 1)[0]
    else:
        if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", raw):
            raise ValueError("CEYE Identifier 格式无效（字母数字连字符）")
        identifier = raw
        domain = f"{identifier}{_CEYE_SUFFIX}"

    if not identifier:
        raise ValueError("CEYE Identifier 不能为空")
    return identifier, domain


def mask_secret(value: str, visible: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= visible:
        return "*" * len(value)
    return "*" * (len(value) - visible) + value[-visible:]
