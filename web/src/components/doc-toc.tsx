import type { DocHeading } from "@/lib/docs";
import { cn } from "@/lib/utils";

/** Font size / weight by markdown heading level. */
const LEVEL_TEXT: Record<DocHeading["level"], string> = {
  1: "text-sm font-semibold text-foreground",
  2: "text-[13px] font-medium text-foreground",
  3: "text-xs font-normal text-muted-foreground",
  4: "text-[11px] font-normal text-muted-foreground",
  5: "text-[11px] font-normal text-muted-foreground/90",
  6: "text-[10px] font-normal text-muted-foreground/80",
};

type DocTocProps = {
  headings: DocHeading[];
  className?: string;
};

export function DocToc({ headings, className }: DocTocProps) {
  if (headings.length === 0) {
    return (
      <p className="px-3 text-xs text-muted-foreground">本文暂无章节标题</p>
    );
  }

  const minLevel = Math.min(...headings.map((h) => h.level));

  return (
    <nav className={cn("flex flex-col gap-0.5", className)}>
      {headings.map((heading) => {
        const depth = Math.max(0, heading.level - minLevel);
        return (
          <a
            key={heading.id}
            href={`#${heading.id}`}
            className={cn(
              "block truncate py-1.5 leading-snug transition-colors hover:text-foreground",
              LEVEL_TEXT[heading.level],
            )}
            style={{ paddingLeft: `${0.75 + depth * 0.75}rem` }}
            title={heading.text}
          >
            {heading.text}
          </a>
        );
      })}
    </nav>
  );
}
