"""Load vulnerability analysis docs from web/content/docs (or FASTJSON_DOCS_DIR)."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path


_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?", re.DOTALL)


@dataclass(frozen=True)
class DocMeta:
    slug: str
    title: str
    description: str
    order: int


@dataclass(frozen=True)
class Doc(DocMeta):
    content: str


def resolve_docs_dir() -> Path:
    """Resolve knowledge docs directory.

    Order:
    1. ``FASTJSON_DOCS_DIR``
    2. repo ``web/content/docs`` (relative to this package)
    """
    env = (os.environ.get("FASTJSON_DOCS_DIR") or "").strip()
    if env:
        path = Path(env).expanduser().resolve()
        if path.is_dir():
            return path
        raise FileNotFoundError(f"FASTJSON_DOCS_DIR 不是有效目录: {path}")

    # .../src/fastjson_toolkit/mcp/docs_loader.py → repo root
    repo_root = Path(__file__).resolve().parents[3]
    candidate = repo_root / "web" / "content" / "docs"
    if candidate.is_dir():
        return candidate

    raise FileNotFoundError(
        "未找到漏洞分析文档目录。请设置 FASTJSON_DOCS_DIR，"
        f"或在仓库根目录运行（期望路径: {candidate}）"
    )


def _parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return {}, text

    meta: dict[str, str] = {}
    for line in match.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        meta[key.strip()] = value.strip().strip("\"'")
    body = text[match.end() :]
    return meta, body


def list_docs(docs_dir: Path | None = None) -> list[DocMeta]:
    root = docs_dir or resolve_docs_dir()
    items: list[DocMeta] = []
    for path in sorted(root.glob("*.md")):
        raw = path.read_text(encoding="utf-8")
        meta, _ = _parse_frontmatter(raw)
        order_raw = meta.get("order", "999")
        try:
            order = int(order_raw)
        except ValueError:
            order = 999
        items.append(
            DocMeta(
                slug=path.stem,
                title=meta.get("title") or path.stem,
                description=meta.get("description") or "",
                order=order,
            )
        )
    items.sort(key=lambda d: (d.order, d.slug))
    return items


def get_doc(slug: str, docs_dir: Path | None = None) -> Doc:
    root = docs_dir or resolve_docs_dir()
    safe = slug.strip().replace("\\", "/").split("/")[-1]
    if not safe or safe != slug.strip():
        raise FileNotFoundError(f"无效文档 slug: {slug!r}")
    path = root / f"{safe}.md"
    if not path.is_file():
        known = ", ".join(d.slug for d in list_docs(root)) or "(无)"
        raise FileNotFoundError(f"文档不存在: {slug!r}；可用: {known}")
    raw = path.read_text(encoding="utf-8")
    meta, body = _parse_frontmatter(raw)
    order_raw = meta.get("order", "999")
    try:
        order = int(order_raw)
    except ValueError:
        order = 999
    return Doc(
        slug=safe,
        title=meta.get("title") or safe,
        description=meta.get("description") or "",
        order=order,
        content=body.lstrip("\n"),
    )
