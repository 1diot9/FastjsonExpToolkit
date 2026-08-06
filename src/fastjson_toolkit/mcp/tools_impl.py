"""Compatibility re-export: portable handlers live in ``tools/_lib``."""

from __future__ import annotations

from pathlib import Path
import sys

_repo = Path(__file__).resolve().parents[3]
_root = str(_repo)
if _root not in sys.path:
    sys.path.insert(0, _root)

from tools._lib.handlers import *  # noqa: F403, F401
