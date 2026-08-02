import Link from "next/link";
import { FileText } from "lucide-react";

import type { DocMeta } from "@/lib/docs";
import { cn } from "@/lib/utils";

type DocTreeProps = {
  docs: DocMeta[];
  activeSlug?: string;
};

export function DocTree({ docs, activeSlug }: DocTreeProps) {
  if (docs.length === 0) {
    return (
      <p className="px-3 text-xs text-muted-foreground">
        暂无文档。在 <code>content/docs/</code> 添加 Markdown 即可。
      </p>
    );
  }

  return (
    <nav className="flex flex-col gap-0.5 px-2">
      {docs.map((doc) => {
        const active = doc.slug === activeSlug;
        return (
          <Link
            key={doc.slug}
            href={`/docs/${doc.slug}`}
            title={doc.description || doc.title}
            className={cn(
              "flex items-start gap-2 rounded-md px-2.5 py-2 text-sm transition-colors",
              active
                ? "bg-secondary font-medium text-secondary-foreground"
                : "text-muted-foreground hover:bg-muted hover:text-foreground",
            )}
          >
            <FileText className="mt-0.5 size-3.5 shrink-0 opacity-70" />
            <span className="min-w-0 leading-snug">
              <span className="block truncate">{doc.title}</span>
              {doc.description ? (
                <span className="mt-0.5 block truncate text-[11px] font-normal opacity-70">
                  {doc.description}
                </span>
              ) : null}
            </span>
          </Link>
        );
      })}
    </nav>
  );
}
