import Link from "next/link";
import {
  ArrowRight,
  BookOpen,
  Bomb,
  Container,
  Library,
  PackageSearch,
  ScanSearch,
  Settings,
  ShieldOff,
} from "lucide-react";

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
        <Badge variant="secondary">Phase 3</Badge>
        <h1 className="text-3xl font-semibold tracking-tight">
          FastjsonExpToolkit
        </h1>
        <p className="max-w-xl text-muted-foreground">
          Fastjson 探测 / 依赖 / PoC / WAF 绕过工具箱。识别、版本、期望类已合并为按序探测；另含依赖、
          PoC 与 WAF 变换；UI 基于{" "}
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
              Fastjson 探测
            </CardTitle>
            <CardDescription>
              识别 → 版本 → 期望类按序执行，对接{" "}
              <code>/api/detect</code>、<code>/api/version</code>、
              <code>/api/expect</code>。
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/detect" className={cn(buttonVariants())}>
              打开探测页
              <ArrowRight className="size-4" data-icon="inline-end" />
            </Link>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <PackageSearch className="size-5" />
              依赖探测
            </CardTitle>
            <CardDescription>
              对接 <code>/api/deps</code>，Character 报错 / DNS 探测 classpath。
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/deps" className={cn(buttonVariants())}>
              打开依赖页
              <ArrowRight className="size-4" data-icon="inline-end" />
            </Link>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Bomb className="size-5" />
              1.2.83 PoC
            </CardTitle>
            <CardDescription>
              ≤1.2.47 缓存绕过、≤1.2.68 AutoCloseable、1.2.83 CVE-2026-16723。
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/poc" className={cn(buttonVariants())}>
              打开 PoC 页
              <ArrowRight className="size-4" data-icon="inline-end" />
            </Link>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldOff className="size-5" />
              WAF 绕过
            </CardTitle>
            <CardDescription>
              unicode/hex、多逗号、key _/-、填充等本地 payload 变换。
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/waf" className={cn(buttonVariants())}>
              打开 WAF 页
              <ArrowRight className="size-4" data-icon="inline-end" />
            </Link>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Container className="size-5" />
              Docker 靶场
            </CardTitle>
            <CardDescription>
              识别 Docker 环境与端口占用，按需启动{" "}
              <code>lab/</code> 下复现环境。
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/lab" className={cn(buttonVariants())}>
              打开靶场页
              <ArrowRight className="size-4" data-icon="inline-end" />
            </Link>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Library className="size-5" />
              漏洞分析文档
            </CardTitle>
            <CardDescription>
              Markdown 渲染的探测 / 版本 / 依赖分析笔记。
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/docs" className={cn(buttonVariants())}>
              打开文档
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

        <Card className="sm:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BookOpen className="size-5" />
              API 文档
            </CardTitle>
            <CardDescription>
              基于{" "}
              <a
                className="underline underline-offset-4"
                href="https://github.com/scalar/scalar"
                target="_blank"
                rel="noreferrer"
              >
                Scalar
              </a>
              ，也可切换 Swagger / ReDoc。
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            <a
              href="/api/docs"
              target="_blank"
              rel="noreferrer"
              className={cn(buttonVariants())}
            >
              Scalar
              <ArrowRight className="size-4" data-icon="inline-end" />
            </a>
            <a
              href="/api/swagger"
              target="_blank"
              rel="noreferrer"
              className={cn(buttonVariants({ variant: "outline" }))}
            >
              Swagger UI
            </a>
            <a
              href="/api/redoc"
              target="_blank"
              rel="noreferrer"
              className={cn(buttonVariants({ variant: "outline" }))}
            >
              ReDoc
            </a>
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
