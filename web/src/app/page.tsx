import Link from "next/link";
import { ArrowRight, ScanSearch, Settings } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { cn } from "@/lib/utils";

export default function Home() {
  return (
    <main className="mx-auto flex w-full max-w-3xl flex-1 flex-col justify-center gap-8 px-6 py-16">
      <div className="space-y-3">
        <Badge variant="secondary">Phase 1</Badge>
        <h1 className="text-3xl font-semibold tracking-tight">
          FastjsonExpToolkit
        </h1>
        <p className="max-w-xl text-muted-foreground">
          Fastjson 识别 / 版本探测 / PoC 工具箱。当前已打通识别能力的 Web
          前后端；UI 基于{" "}
          <a
            className="underline underline-offset-4"
            href="https://ui.shadcn.com/"
            target="_blank"
            rel="noreferrer"
          >
            shadcn/ui
          </a>
          。
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ScanSearch className="size-5" />
              Fastjson 识别
            </CardTitle>
            <CardDescription>
              对接 <code>/api/detect</code>，输出置信度、证据与下一步建议。
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/detect" className={cn(buttonVariants())}>
              打开识别页
              <ArrowRight className="size-4" data-icon="inline-end" />
            </Link>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Settings className="size-5" />
              设置
            </CardTitle>
            <CardDescription>
              配置 CEYE Token 与 Identifier 子域名。
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Link
              href="/settings"
              className={cn(buttonVariants({ variant: "outline" }))}
            >
              打开设置
              <ArrowRight className="size-4" data-icon="inline-end" />
            </Link>
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
