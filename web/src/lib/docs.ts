import fs from "node:fs";
import path from "node:path";

import matter from "gray-matter";

const DOCS_DIR = path.join(process.cwd(), "content", "docs");

export type DocMeta = {
  slug: string;
  title: string;
  description: string;
  order: number;
};

export type Doc = DocMeta & {
  content: string;
};

export type DocHeading = {
  id: string;
  text: string;
  level: 1 | 2 | 3 | 4 | 5 | 6;
};

/** GitHub-style heading slug; keeps uniqueness with a counter. */
export function slugifyHeading(text: string, used: Map<string, number>): string {
  const base =
    text
      .trim()
      .toLowerCase()
      .replace(/[^\p{L}\p{N}\s_-]/gu, "")
      .replace(/[\s_]+/g, "-")
      .replace(/-+/g, "-")
      .replace(/^-|-$/g, "") || "section";

  const count = used.get(base) ?? 0;
  used.set(base, count + 1);
  return count === 0 ? base : `${base}-${count}`;
}

function stripInlineMarkdown(text: string): string {
  return text
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/\*([^*]+)\*/g, "$1")
    .replace(/~~([^~]+)~~/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .trim();
}

/** Extract ATX headings (`#` … `######`), skipping fenced code blocks. */
export function extractHeadings(markdown: string): DocHeading[] {
  const headings: DocHeading[] = [];
  const used = new Map<string, number>();
  let inFence = false;

  for (const line of markdown.split(/\r?\n/)) {
    if (/^(`{3,}|~{3,})/.test(line.trim())) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;

    const match = /^(#{1,6})\s+(.+?)\s*#*\s*$/.exec(line);
    if (!match) continue;

    const level = match[1].length as DocHeading["level"];
    const text = stripInlineMarkdown(match[2]);
    if (!text) continue;

    headings.push({
      id: slugifyHeading(text, used),
      text,
      level,
    });
  }

  return headings;
}

function ensureDocsDir(): void {
  if (!fs.existsSync(DOCS_DIR)) {
    fs.mkdirSync(DOCS_DIR, { recursive: true });
  }
}

function parseDocFile(filename: string): Doc {
  const slug = filename.replace(/\.md$/i, "");
  const raw = fs.readFileSync(path.join(DOCS_DIR, filename), "utf8");
  const { data, content } = matter(raw);

  return {
    slug,
    title: typeof data.title === "string" ? data.title : slug,
    description:
      typeof data.description === "string" ? data.description : "",
    order: typeof data.order === "number" ? data.order : 999,
    content,
  };
}

export function listDocs(): DocMeta[] {
  ensureDocsDir();
  return fs
    .readdirSync(DOCS_DIR)
    .filter((name) => name.toLowerCase().endsWith(".md"))
    .map((filename) => {
      const doc = parseDocFile(filename);
      return {
        slug: doc.slug,
        title: doc.title,
        description: doc.description,
        order: doc.order,
      };
    })
    .sort((a, b) => a.order - b.order || a.title.localeCompare(b.title, "zh-CN"));
}

export function getDoc(slug: string): Doc | null {
  ensureDocsDir();
  const filename = `${slug}.md`;
  const fullPath = path.join(DOCS_DIR, filename);
  if (!fs.existsSync(fullPath)) {
    return null;
  }
  return parseDocFile(filename);
}

export function getDocSlugs(): string[] {
  return listDocs().map((doc) => doc.slug);
}
