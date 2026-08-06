"""Load vulnerability analysis docs from web/content/docs (or FASTJSON_DOCS_DIR).

Docs are split by ``##`` / ``###`` headings so tools / MCP can return a single
payload section instead of the full markdown file.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path


_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?", re.DOTALL)
_HEADING_RE = re.compile(r"^(#{2,3})\s+(.+?)\s*$", re.MULTILINE)
_CODE_FENCE_RE = re.compile(r"```")


@dataclass(frozen=True)
class DocMeta:
    slug: str
    title: str
    description: str
    order: int


@dataclass(frozen=True)
class Doc(DocMeta):
    content: str


@dataclass(frozen=True)
class DocSection:
    """One ``##`` / ``###`` block under a parent doc."""

    slug: str  # parent/section-id
    title: str
    level: int  # 2 or 3
    content: str
    has_payload: bool
    parent_section: str | None = None  # relative section id of enclosing ##


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

    # .../tools/_lib/docs_loader.py → repo root
    repo_root = Path(__file__).resolve().parents[2]
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


def section_id(title: str) -> str:
    """Stable id from a heading title (keeps CJK; ascii lowercased)."""
    t = title.strip()
    t = re.sub(r"[`*_~\[\]()（）]+", "", t)
    # keep numbered headings readable: "13.1 出网" → "13-1-出网"
    t = re.sub(r"(\d)\.(\d)", r"\1-\2", t)
    t = t.replace(".", "-")
    t = re.sub(r"\s+", "-", t)
    t = re.sub(r"[^\w\u4e00-\u9fff-]+", "", t, flags=re.UNICODE)
    t = re.sub(r"-{2,}", "-", t)
    t = t.lower().strip("-")
    return t or "section"


def _has_json_payload(block: str) -> bool:
    """True if the section contains a fenced block that looks like JSON payload."""
    parts = _CODE_FENCE_RE.split(block)
    # odd indices are fenced bodies when starting outside a fence
    for i in range(1, len(parts), 2):
        body = parts[i]
        # drop optional language tag on first line
        if "\n" in body:
            lang, _, rest = body.partition("\n")
            lang = lang.strip().lower()
            content = rest if lang in ("", "json", "javascript", "js", "text") else body
        else:
            content = body
        sample = content.lstrip()[:80]
        if sample.startswith(("{", "[")) or '"@type"' in content or "'@type'" in content:
            return True
    return False


def parse_sections(doc_slug: str, body: str) -> tuple[str, list[DocSection]]:
    """Split markdown body into preamble + ``##``/``###`` sections.

    Returns ``(preamble, sections)``. Section slugs are ``{doc}/{section_id}``.
    A ``##`` section's ``content`` includes nested ``###`` until the next ``##``.
    A ``###`` entry's ``content`` is only that subsection.
    """
    matches = list(_HEADING_RE.finditer(body))
    if not matches:
        return body.lstrip("\n"), []

    preamble = body[: matches[0].start()].lstrip("\n").rstrip() + ("\n" if body[: matches[0].start()].strip() else "")

    # Build raw blocks: each heading → content until next heading of any level
    raw: list[tuple[int, str, int, int]] = []  # level, title, start, end
    for i, m in enumerate(matches):
        level = len(m.group(1))
        title = m.group(2).strip()
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        raw.append((level, title, start, end))

    used_ids: dict[str, int] = {}
    sections: list[DocSection] = []
    current_h2_id: str | None = None

    for idx, (level, title, start, end) in enumerate(raw):
        sid = section_id(title)
        if sid in used_ids:
            used_ids[sid] += 1
            sid = f"{sid}-{used_ids[sid]}"
        else:
            used_ids[sid] = 1

        if level == 2:
            current_h2_id = sid
            # include following ### until next ##
            block_end = end
            for j in range(idx + 1, len(raw)):
                if raw[j][0] == 2:
                    break
                block_end = raw[j][3]
            content = body[start:block_end].strip() + "\n"
            parent = None
        else:
            content = body[start:end].strip() + "\n"
            parent = f"{doc_slug}/{current_h2_id}" if current_h2_id else None

        sections.append(
            DocSection(
                slug=f"{doc_slug}/{sid}",
                title=title,
                level=level,
                content=content,
                has_payload=_has_json_payload(content),
                parent_section=parent,
            )
        )

    return preamble, sections


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


def list_docs_with_sections(docs_dir: Path | None = None) -> list[tuple[DocMeta, str, list[DocSection]]]:
    """Return ``(meta, preamble, sections)`` for each doc, sorted by order."""
    root = docs_dir or resolve_docs_dir()
    out: list[tuple[DocMeta, str, list[DocSection]]] = []
    for meta in list_docs(root):
        path = root / f"{meta.slug}.md"
        raw = path.read_text(encoding="utf-8")
        _, body = _parse_frontmatter(raw)
        preamble, sections = parse_sections(meta.slug, body.lstrip("\n"))
        out.append((meta, preamble, sections))
    return out


def get_doc(slug: str, docs_dir: Path | None = None) -> Doc:
    """Load a whole doc by parent slug (no ``/`` section suffix)."""
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


def get_doc_or_section(slug: str, docs_dir: Path | None = None) -> dict:
    """Resolve parent doc or ``parent/section`` to a content dict.

    Parent slug → section index only (no full body/preamble).
    Section slug → that section's markdown only.
    """
    root = docs_dir or resolve_docs_dir()
    raw_slug = (slug or "").strip().replace("\\", "/")
    if not raw_slug or ".." in raw_slug.split("/"):
        raise FileNotFoundError(f"无效文档 slug: {slug!r}")

    if "/" not in raw_slug:
        doc = get_doc(raw_slug, root)
        _, sections = parse_sections(doc.slug, doc.content)
        return {
            "slug": doc.slug,
            "title": doc.title,
            "sections": [
                {
                    "slug": s.slug,
                    "title": s.title,
                    **({"has_payload": True} if s.has_payload else {}),
                    **({"parent": s.parent_section} if s.parent_section else {}),
                }
                for s in sections
            ],
        }

    parent, _, section_part = raw_slug.partition("/")
    if not parent or not section_part:
        raise FileNotFoundError(f"无效章节 slug: {slug!r}")

    doc = get_doc(parent, root)
    _, sections = parse_sections(doc.slug, doc.content)
    for s in sections:
        if s.slug == raw_slug or s.slug.endswith("/" + section_part):
            return {
                "slug": s.slug,
                "title": s.title,
                "content": s.content,
                **({"has_payload": True} if s.has_payload else {}),
            }

    known = ", ".join(s.slug for s in sections) or "(无章节)"
    raise FileNotFoundError(f"章节不存在: {slug!r}；可用: {known}")
