import Link from "next/link";

import { ThemeToggle } from "@/components/theme-toggle";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";

const links = [
  { href: "/", label: "首页" },
  { href: "/detect", label: "识别" },
  { href: "/version", label: "版本" },
  { href: "/deps", label: "依赖" },
  { href: "/settings", label: "设置" },
];

export function SiteHeader() {
  return (
    <header className="border-b">
      <div className="mx-auto flex h-14 w-full max-w-5xl items-center gap-4 px-6">
        <Link href="/" className="font-semibold tracking-tight">
          FastjsonExpToolkit
        </Link>
        <Badge variant="secondary">Web</Badge>
        <Separator orientation="vertical" className="mx-1 h-5" />
        <nav className="flex items-center gap-1">
          {links.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className={cn(buttonVariants({ variant: "ghost", size: "sm" }))}
            >
              {item.label}
            </Link>
          ))}
          <a
            href="/api/docs"
            target="_blank"
            rel="noreferrer"
            className={cn(buttonVariants({ variant: "ghost", size: "sm" }))}
          >
            API 文档
          </a>
        </nav>
        <div className="ml-auto">
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
