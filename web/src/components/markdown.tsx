import Link from "next/link";
import type { ReactNode } from "react";
import type { Components } from "react-markdown";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import type { DocHeading } from "@/lib/docs";
import { slugifyHeading } from "@/lib/docs";
import { cn } from "@/lib/utils";

function childrenToText(children: ReactNode): string {
  if (children == null || typeof children === "boolean") return "";
  if (typeof children === "string" || typeof children === "number") {
    return String(children);
  }
  if (Array.isArray(children)) {
    return children.map(childrenToText).join("");
  }
  if (typeof children === "object" && "props" in children) {
    return childrenToText(
      (children as { props?: { children?: ReactNode } }).props?.children,
    );
  }
  return "";
}

function createHeadingComponents(
  headings: DocHeading[] | undefined,
): Pick<Components, "h1" | "h2" | "h3" | "h4" | "h5" | "h6"> {
  let index = 0;
  const usedIds = new Map<string, number>();

  const make =
    (
      Tag: "h1" | "h2" | "h3" | "h4" | "h5" | "h6",
      className: string,
    ): NonNullable<Components["h1"]> =>
    ({ children }) => {
      const fromToc = headings?.[index++];
      const id =
        fromToc?.id ?? slugifyHeading(childrenToText(children), usedIds);
      return (
        <Tag id={id} className={className}>
          {children}
        </Tag>
      );
    };

  return {
    h1: make(
      "h1",
      "mb-4 mt-8 scroll-m-20 text-3xl font-semibold tracking-tight first:mt-0",
    ),
    h2: make(
      "h2",
      "mb-3 mt-10 scroll-m-20 border-b pb-2 text-2xl font-semibold tracking-tight",
    ),
    h3: make(
      "h3",
      "mb-2 mt-8 scroll-m-20 text-xl font-semibold tracking-tight",
    ),
    h4: make(
      "h4",
      "mb-2 mt-6 scroll-m-20 text-lg font-semibold tracking-tight",
    ),
    h5: make(
      "h5",
      "mb-2 mt-4 scroll-m-20 text-base font-semibold tracking-tight",
    ),
    h6: make(
      "h6",
      "mb-2 mt-4 scroll-m-20 text-sm font-semibold tracking-tight",
    ),
  };
}

const baseComponents: Components = {
  p: ({ children }) => (
    <p className="my-4 leading-7 text-foreground/90">{children}</p>
  ),
  a: ({ href, children }) => {
    const className =
      "font-medium text-foreground underline underline-offset-4 hover:text-foreground/80";
    if (href?.startsWith("/")) {
      return (
        <Link href={href} className={className}>
          {children}
        </Link>
      );
    }
    return (
      <a href={href} className={className} target="_blank" rel="noreferrer">
        {children}
      </a>
    );
  },
  ul: ({ children }) => (
    <ul className="my-4 ml-6 list-disc space-y-2">{children}</ul>
  ),
  ol: ({ children }) => (
    <ol className="my-4 ml-6 list-decimal space-y-2">{children}</ol>
  ),
  li: ({ children }) => <li className="leading-7">{children}</li>,
  blockquote: ({ children }) => (
    <blockquote className="my-4 border-l-2 border-border pl-4 text-muted-foreground">
      {children}
    </blockquote>
  ),
  hr: () => <hr className="my-8 border-border" />,
  table: ({ children }) => (
    <div className="my-6 w-full overflow-x-auto rounded-lg border">
      <table className="w-full border-collapse text-sm">{children}</table>
    </div>
  ),
  thead: ({ children }) => <thead className="bg-muted/50">{children}</thead>,
  tbody: ({ children }) => <tbody>{children}</tbody>,
  tr: ({ children }) => (
    <tr className="border-b last:border-0">{children}</tr>
  ),
  th: ({ children }) => (
    <th className="px-3 py-2 text-left font-medium">{children}</th>
  ),
  td: ({ children }) => (
    <td className="px-3 py-2 align-top text-foreground/90">{children}</td>
  ),
  code: ({ className, children }) => {
    const isBlock = Boolean(className?.includes("language-"));
    if (isBlock) {
      return (
        <code className={cn("font-mono text-[0.85rem]", className)}>
          {children}
        </code>
      );
    }
    return (
      <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[0.85em]">
        {children}
      </code>
    );
  },
  pre: ({ children }) => (
    <pre className="my-4 overflow-x-auto rounded-lg border bg-muted/40 p-4 font-mono text-[0.85rem] leading-6">
      {children}
    </pre>
  ),
  strong: ({ children }) => (
    <strong className="font-semibold text-foreground">{children}</strong>
  ),
};

type MarkdownProps = {
  content: string;
  headings?: DocHeading[];
  className?: string;
};

export function Markdown({ content, headings, className }: MarkdownProps) {
  const components: Components = {
    ...baseComponents,
    ...createHeadingComponents(headings),
  };

  return (
    <div className={cn("max-w-none", className)}>
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
        {content}
      </ReactMarkdown>
    </div>
  );
}
