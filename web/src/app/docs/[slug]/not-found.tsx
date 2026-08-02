import Link from "next/link";

import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export default function DocNotFound() {
  return (
    <div className="flex flex-1 flex-col items-start justify-center gap-4 px-8">
      <h1 className="text-2xl font-semibold tracking-tight">文档不存在</h1>
      <p className="text-muted-foreground">
        未找到对应的 Markdown 文档，请从左侧目录选择其他文档。
      </p>
      <Link href="/docs" className={cn(buttonVariants())}>
        返回文档
      </Link>
    </div>
  );
}
