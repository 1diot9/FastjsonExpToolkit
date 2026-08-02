import { redirect } from "next/navigation";

import { listDocs } from "@/lib/docs";

export const metadata = {
  title: "文档 · FastjsonExpToolkit",
  description: "漏洞分析与探测方法文档",
};

export default function DocsIndexPage() {
  const docs = listDocs();
  if (docs.length === 0) {
    return (
      <div className="flex flex-1 items-center justify-center px-6 text-sm text-muted-foreground">
        暂无文档。请在 <code className="mx-1">web/content/docs/</code>{" "}
        添加 Markdown 文件。
      </div>
    );
  }
  redirect(`/docs/${docs[0].slug}`);
}
