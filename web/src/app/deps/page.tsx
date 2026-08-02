"use client";

import { useEffect, useMemo, useState } from "react";
import { Loader2, Play, RefreshCw } from "lucide-react";
import { toast } from "sonner";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import {
  detectDeps,
  fetchDepsCatalog,
  fetchHealth,
  type DepCatalogEntry,
  type DepMethod,
  type DepsResult,
  type HealthResponse,
} from "@/lib/api";

const PRESETS = [
  { label: "1.2.83", value: "http://127.0.0.1:18080/api/fastjson" },
  { label: "1.2.80", value: "http://127.0.0.1:18082/api/fastjson" },
  { label: "1.2.68", value: "http://127.0.0.1:18068/api/fastjson" },
  { label: "1.2.47", value: "http://127.0.0.1:18047/api/fastjson" },
  {
    label: "1.2.83 (autoType)",
    value: "http://127.0.0.1:18080/api/fastjson/autotype",
  },
];

function statusBadgeVariant(
  status: string,
): "default" | "secondary" | "outline" | "destructive" {
  if (status === "present") return "default";
  if (status === "error") return "destructive";
  if (status === "absent") return "secondary";
  return "outline";
}

export default function DepsPage() {
  const [target, setTarget] = useState(PRESETS[0].value);
  const [method, setMethod] = useState<DepMethod>("character");
  const [useCeye, setUseCeye] = useState(true);
  const [dnslog, setDnslog] = useState("");
  const [ceyeWait, setCeyeWait] = useState("10");
  const [timeoutSec, setTimeoutSec] = useState("10");
  const [concurrency, setConcurrency] = useState("6");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [customClasses, setCustomClasses] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<DepsResult | null>(null);
  const [catalog, setCatalog] = useState<DepCatalogEntry[]>([]);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [healthLoading, setHealthLoading] = useState(false);
  const [mounted, setMounted] = useState(false);

  const categories = useMemo(() => {
    const set = new Set(catalog.map((c) => c.category));
    return Array.from(set).sort();
  }, [catalog]);

  async function refreshHealth() {
    setHealthLoading(true);
    try {
      const data = await fetchHealth();
      setHealth(data);
      setHealthError(null);
    } catch (err) {
      setHealth(null);
      setHealthError(err instanceof Error ? err.message : String(err));
    } finally {
      setHealthLoading(false);
    }
  }

  useEffect(() => {
    setMounted(true);
    void refreshHealth();
    void fetchDepsCatalog()
      .then(setCatalog)
      .catch(() => setCatalog([]));
    const timer = window.setInterval(() => {
      void refreshHealth();
    }, 5000);
    return () => window.clearInterval(timer);
  }, []);

  async function onDetect() {
    if (!target.trim()) {
      toast.error("请填写目标 URL");
      return;
    }
    if (method === "dns" && !useCeye && !dnslog.trim()) {
      toast.error("DNS 方法请启用 CEYE，或填写自定义 DNSLog 域名");
      return;
    }
    setLoading(true);
    try {
      const classes = customClasses
        .split(/[\n,;]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const data = await detectDeps({
        target: target.trim(),
        method,
        classes,
        categories:
          categoryFilter === "all" ? [] : [categoryFilter],
        use_ceye: method === "dns" && useCeye,
        dnslog: method === "dns" && !useCeye ? dnslog.trim() : null,
        ceye_wait: Number(ceyeWait) || 10,
        timeout: Number(timeoutSec) || 10,
        concurrency: Number(concurrency) || 6,
      });
      setResult(data);
      if (data.present_count > 0) {
        toast.success("依赖探测完成", { description: data.summary });
      } else {
        toast.message("未发现命中依赖", { description: data.summary });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      toast.error("依赖探测失败", { description: msg });
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-6 px-6 py-10">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-2">
          <h1 className="text-2xl font-semibold tracking-tight">依赖探测</h1>
          <p className="text-sm text-muted-foreground">
            Character 转换报错探测 classpath；可选 DNS Locale（版本敏感）。对接{" "}
            <code>/api/deps</code>。
          </p>
        </div>
        <div className="flex items-center gap-2">
          {!mounted || (healthLoading && !health) ? (
            <Badge variant="outline">API 检测中...</Badge>
          ) : health ? (
            <Badge variant={health.ceye_configured ? "default" : "secondary"}>
              API v{health.version}
              {health.ceye_configured ? " · CEYE OK" : " · CEYE 未配置"}
            </Badge>
          ) : (
            <Badge variant="outline">API 未连接</Badge>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => void refreshHealth()}
            disabled={!mounted || healthLoading}
          >
            <RefreshCw className={`size-4 ${healthLoading ? "animate-spin" : ""}`} />
            刷新
          </Button>
        </div>
      </div>

      {healthError ? (
        <Alert variant="destructive">
          <AlertTitle>后端不可用</AlertTitle>
          <AlertDescription>
            {healthError}。请先执行{" "}
            <code className="rounded bg-muted px-1">fjtoolkit serve</code>（默认
            :8000）。
          </AlertDescription>
        </Alert>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>探测参数</CardTitle>
          <CardDescription>
            推荐 Character：类存在 →{" "}
            <code>can not cast to char</code>；不存在常见{" "}
            <code>No message available</code>。DNS 方法本地常失效。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>靶场预设</Label>
            <Select
              value={target}
              onValueChange={(v) => {
                if (v) setTarget(v);
              }}
            >
              <SelectTrigger className="w-full">
                <SelectValue placeholder="选择预设" />
              </SelectTrigger>
              <SelectContent>
                {PRESETS.map((p) => (
                  <SelectItem key={p.value} value={p.value}>
                    {p.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="target">目标 URL</Label>
            <Input
              id="target"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="http://127.0.0.1:18080/api/fastjson"
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>方法</Label>
              <Select
                value={method}
                onValueChange={(v) => {
                  if (v === "character" || v === "dns") setMethod(v);
                }}
              >
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="character">character（报错回显）</SelectItem>
                  <SelectItem value="dns">dns（Locale+Inet4）</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>类别过滤</Label>
              <Select
                value={categoryFilter}
                onValueChange={(v) => {
                  if (v) setCategoryFilter(v);
                }}
              >
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="全部" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部内置类</SelectItem>
                  {categories.map((c) => (
                    <SelectItem key={c} value={c}>
                      {c}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-3">
            <div className="space-y-2">
              <Label htmlFor="timeout">超时（秒）</Label>
              <Input
                id="timeout"
                value={timeoutSec}
                onChange={(e) => setTimeoutSec(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="concurrency">并发</Label>
              <Input
                id="concurrency"
                value={concurrency}
                onChange={(e) => setConcurrency(e.target.value)}
                disabled={method !== "character"}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="ceye-wait">CEYE 等待（秒）</Label>
              <Input
                id="ceye-wait"
                value={ceyeWait}
                onChange={(e) => setCeyeWait(e.target.value)}
                disabled={method !== "dns" || !useCeye}
              />
            </div>
          </div>

          {method === "dns" ? (
            <div className="space-y-3">
              <Button
                type="button"
                size="sm"
                variant={useCeye ? "default" : "outline"}
                onClick={() => setUseCeye((v) => !v)}
              >
                CEYE 确认：{useCeye ? "开" : "关"}
              </Button>
              {!useCeye ? (
                <div className="space-y-2">
                  <Label htmlFor="dnslog">自定义 DNSLog 域名</Label>
                  <Input
                    id="dnslog"
                    value={dnslog}
                    onChange={(e) => setDnslog(e.target.value)}
                    placeholder="xxxx.ceye.io 或 xxx.dnslog.cn"
                  />
                </div>
              ) : null}
              <Alert>
                <AlertTitle>DNS 方法说明</AlertTitle>
                <AlertDescription>
                  Locale+Class+Inet4 链对 Fastjson 版本 / autoType
                  极敏感，本地靶场经常无 DNS。优先用 character。
                </AlertDescription>
              </Alert>
            </div>
          ) : null}

          <div className="space-y-2">
            <Label htmlFor="custom-classes">自定义类名（可选）</Label>
            <Textarea
              id="custom-classes"
              className="min-h-24 font-mono text-xs"
              value={customClasses}
              onChange={(e) => setCustomClasses(e.target.value)}
              placeholder={
                "留空则扫描内置目录；每行一个全限定类名，例如：\norg.springframework.web.bind.annotation.RequestMapping"
              }
            />
          </div>

          <Separator />

          <Button onClick={() => void onDetect()} disabled={loading}>
            {loading ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <Play className="size-4" />
            )}
            开始依赖探测
          </Button>
        </CardContent>
      </Card>

      {result ? (
        <Card>
          <CardHeader className="gap-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <CardTitle>探测结果</CardTitle>
              <div className="flex flex-wrap gap-2">
                <Badge variant={result.present_count ? "default" : "secondary"}>
                  命中 {result.present_count}/{result.scanned}
                </Badge>
                <Badge variant="outline">{result.method}</Badge>
                {result.absent_count ? (
                  <Badge variant="outline">absent {result.absent_count}</Badge>
                ) : null}
                {result.unknown_count ? (
                  <Badge variant="outline">unknown {result.unknown_count}</Badge>
                ) : null}
                {result.error_count ? (
                  <Badge variant="destructive">error {result.error_count}</Badge>
                ) : null}
              </div>
            </div>
            <CardDescription className="break-all">{result.target}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Alert>
              <AlertTitle>摘要</AlertTitle>
              <AlertDescription>{result.summary}</AlertDescription>
            </Alert>
            {result.notes.length ? (
              <Alert>
                <AlertTitle>说明</AlertTitle>
                <AlertDescription>
                  <ul className="list-disc space-y-1 pl-4">
                    {result.notes.map((n) => (
                      <li key={n}>{n}</li>
                    ))}
                  </ul>
                </AlertDescription>
              </Alert>
            ) : null}

            <Tabs defaultValue="present">
              <TabsList>
                <TabsTrigger value="present">命中</TabsTrigger>
                <TabsTrigger value="all">全部</TabsTrigger>
                <TabsTrigger value="actions">建议</TabsTrigger>
                <TabsTrigger value="raw">JSON</TabsTrigger>
              </TabsList>

              <TabsContent value="present" className="mt-4">
                {result.present.length === 0 ? (
                  <p className="text-sm text-muted-foreground">无命中依赖</p>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>依赖</TableHead>
                        <TableHead>类名</TableHead>
                        <TableHead>类别</TableHead>
                        <TableHead>匹配</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {result.present.map((hit) => (
                        <TableRow key={hit.clazz}>
                          <TableCell className="font-medium">
                            {hit.description}
                          </TableCell>
                          <TableCell className="max-w-xs truncate font-mono text-xs">
                            {hit.clazz}
                          </TableCell>
                          <TableCell>{hit.category}</TableCell>
                          <TableCell>
                            {hit.matched.join(", ") || "-"}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </TabsContent>

              <TabsContent value="all" className="mt-4">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>状态</TableHead>
                      <TableHead>依赖</TableHead>
                      <TableHead>类名</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>耗时</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {result.results.map((hit) => (
                      <TableRow key={`${hit.clazz}-${hit.status}`}>
                        <TableCell>
                          <Badge variant={statusBadgeVariant(hit.status)}>
                            {hit.status}
                          </Badge>
                        </TableCell>
                        <TableCell>{hit.description}</TableCell>
                        <TableCell className="max-w-xs truncate font-mono text-xs">
                          {hit.clazz}
                        </TableCell>
                        <TableCell>{hit.status_code || "-"}</TableCell>
                        <TableCell>
                          {hit.elapsed_ms ? `${hit.elapsed_ms}ms` : "-"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TabsContent>

              <TabsContent value="actions" className="mt-4 space-y-2">
                {result.next_actions.length === 0 ? (
                  <p className="text-sm text-muted-foreground">无额外建议</p>
                ) : (
                  <ol className="list-decimal space-y-1 pl-5 text-sm">
                    {result.next_actions.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ol>
                )}
              </TabsContent>

              <TabsContent value="raw" className="mt-4">
                <Textarea
                  className="min-h-72 font-mono text-xs"
                  readOnly
                  value={JSON.stringify(result, null, 2)}
                />
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      ) : null}
    </main>
  );
}
