"use client";

import type { ReactNode } from "react";
import { useParams } from "next/navigation";

import { DocTree } from "@/components/doc-tree";
import type { DocMeta } from "@/lib/docs";

type DocsShellProps = {
  docs: DocMeta[];
  children: ReactNode;
};

export function DocsShell({ docs, children }: DocsShellProps) {
  const params = useParams<{ slug?: string }>();
  const activeSlug =
    typeof params.slug === "string" ? params.slug : undefined;

  return (
    <div className="flex h-[calc(100dvh-3.5rem)] w-full min-h-0 overflow-hidden">
      <aside className="flex w-64 shrink-0 flex-col border-r bg-muted/20 md:w-72">
        <div className="shrink-0 border-b px-4 py-3">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            文档
          </p>
          <p className="mt-0.5 text-sm font-semibold tracking-tight">
            漏洞分析
          </p>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto py-3">
          <DocTree docs={docs} activeSlug={activeSlug} />
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 overflow-hidden">{children}</div>
    </div>
  );
}
