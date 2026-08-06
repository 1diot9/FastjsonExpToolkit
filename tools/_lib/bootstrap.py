"""Ensure repo ``src/`` is importable when running tools/*.py without install."""

from __future__ import annotations

import sys
from pathlib import Path

_BOOTSTRAPPED = False


def ensure_src_path() -> Path:
    """Insert ``<repo>/src`` into ``sys.path`` if needed. Returns repo root."""
    global _BOOTSTRAPPED
    # tools/_lib/bootstrap.py → tools/_lib → tools → repo
    repo_root = Path(__file__).resolve().parents[2]
    src = repo_root / "src"
    src_s = str(src)
    if src.is_dir() and src_s not in sys.path:
        sys.path.insert(0, src_s)
    # Allow ``import tools._lib...`` when invoked as a script
    root_s = str(repo_root)
    if root_s not in sys.path:
        sys.path.insert(0, root_s)
    _BOOTSTRAPPED = True
    return repo_root
