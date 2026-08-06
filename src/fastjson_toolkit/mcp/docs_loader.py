"""Compatibility re-export: docs loader lives in ``tools/_lib``."""

from __future__ import annotations

from pathlib import Path
import sys

_repo = Path(__file__).resolve().parents[3]
_root = str(_repo)
if _root not in sys.path:
    sys.path.insert(0, _root)

from tools._lib.docs_loader import *  # noqa: F403, F401
from tools._lib.docs_loader import (  # noqa: F401
    Doc,
    DocMeta,
    DocSection,
    get_doc,
    get_doc_or_section,
    list_docs,
    list_docs_with_sections,
    parse_sections,
    resolve_docs_dir,
    section_id,
)
