import { notFound } from "next/navigation";

import { DocToc } from "@/components/doc-toc";
import { Markdown } from "@/components/markdown";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { extractHeadings, getDoc, getDocSlugs } from "@/lib/docs";

type PageProps = {
  params: Promise<{ slug: string }>;
};

export async function generateStaticParams() {
  return getDocSlugs().map((slug) => ({ slug }));
}

export async function generateMetadata({ params }: PageProps) {
  const { slug } = await params;
  const doc = getDoc(slug);
  if (!doc) {
    return { title: "文档未找到" };
  }
  return {
    title: `${doc.title} · 文档`,
    description: doc.description,
  };
}

export default async function DocDetailPage({ params }: PageProps) {
  const { slug } = await params;
  const doc = getDoc(slug);
  if (!doc) {
    notFound();
  }

  const headings = extractHeadings(doc.content);

  return (
    <>
      <article className="min-w-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-3xl px-6 py-8 lg:px-10">
          <div className="space-y-3">
            <Badge variant="secondary">分析文档</Badge>
            <h1 className="text-3xl font-semibold tracking-tight">
              {doc.title}
            </h1>
            {doc.description ? (
              <p className="text-muted-foreground">{doc.description}</p>
            ) : null}
          </div>

          <Separator className="my-6" />

          <Markdown content={doc.content} headings={headings} />
        </div>
      </article>

      <aside className="hidden w-60 shrink-0 flex-col border-l bg-muted/10 xl:flex 2xl:w-72">
        <div className="shrink-0 border-b px-4 py-3">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            本页目录
          </p>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-2 py-3">
          <DocToc headings={headings} />
        </div>
      </aside>
    </>
  );
}
