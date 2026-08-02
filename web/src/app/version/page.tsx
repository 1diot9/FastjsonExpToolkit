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
  detectVersion,
  fetchHealth,
  type HealthResponse,
  type VersionResult,
} from "@/lib/api";

const PRESETS = [
  { label: "1.2.83 silent+DNS", value: "http://127.0.0.1:18080/api/fastjson/silent" },
  { label: "1.2.80 echo(1.2.76)", value: "http://127.0.0.1:18082/api/fastjson" },
  { label: "1.2.68 echo", value: "http://127.0.0.1:18068/api/fastjson" },
  { label: "1.2.47 silent", value: "http://127.0.0.1:18047/api/fastjson/silent" },
  { label: "1.2.30 silent", value: "http://127.0.0.1:18030/api/fastjson/silent" },
  { label: "1.2.80 silent", value: "http://127.0.0.1:18082/api/fastjson/silent" },
  { label: "1.2.68 silent", value: "http://127.0.0.1:18068/api/fastjson/silent" },
  {
    label: "1.2.83 silent+AT",
    value: "http://127.0.0.1:18080/api/fastjson/silent/autotype",
  },
  { label: "1.2.83 echo", value: "http://127.0.0.1:18080/api/fastjson" },
];

export default function VersionPage() {
  const [target, setTarget] = useState(PRESETS[0].value);
  const [includeDns, setIncludeDns] = useState(true);
  const [useCeye, setUseCeye] = useState(true);
  const [dnslog, setDnslog] = useState("");
  const [ceyeWait, setCeyeWait] = useState("10");
  const [timeoutSec, setTimeoutSec] = useState("10");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VersionResult | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [healthLoading, setHealthLoading] = useState(false);
  const [mounted, setMounted] = useState(false);

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
    const timer = window.setInterval(() => {
      void refreshHealth();
    }, 5000);
    return () => window.clearInterval(timer);
  }, []);

  const evidenceRows = useMemo(() => {
    if (!result) return [];
    return result.evidence;
  }, [result]);

  const dnsHitRows = useMemo(() => {
    if (!result) return [];
    return Object.entries(result.dns_hits);
  }, [result]);

  async function onDetect() {
    if (!target.trim()) {
      toast.error("请填写目标 URL");
      return;
    }
    if (includeDns && !useCeye && !dnslog.trim()) {
      toast.error("开启 DNS 时请启用 CEYE，或填写自定义 DNSLog 域名");
      return;
    }
    setLoading(true);
    try {
      const data = await detectVersion({
        target: target.trim(),
        include_dns: includeDns,
        use_ceye: includeDns && useCeye,
        dnslog: includeDns && !useCeye ? dnslog.trim() : null,
        ceye_wait: Number(ceyeWait) || 10,
        timeout: Number(timeoutSec) || 10,
      });
      setResult(data);
      if (data.version_range) {
        toast.success("版本探测完成", { description: data.summary });
      } else {
        toast.message("未能收敛版本", { description: data.summary });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      toast.error("版本探测失败", { description: msg });
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-6 px-6 py-10">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-2">
          <h1 className="text-2xl font-semibold tracking-tight">Fastjson 版本探测</h1>
          <p className="text-sm text-muted-foreground">
            稳定区分四档：{" "}
            <code>&lt;=1.2.47</code> / <code>&lt;=1.2.68</code> /{" "}
            <code>&lt;=1.2.80</code> / <code>1.2.83</code>
            。主路径为 silent + AutoType 关 + offline（DNS 辅助）；对接{" "}
            <code>/api/version</code>。
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
            建议开启 DNSLog：双 DNS 区分 1.2.83；报错回显区分 1.2.68 / 1.2.76(≤80)；不出网二分区分
            ≤1.2.47。
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
              <Label htmlFor="timeout">超时（秒）</Label>
              <Input
                id="timeout"
                value={timeoutSec}
                onChange={(e) => setTimeoutSec(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="ceye-wait">CEYE 等待（秒）</Label>
              <Input
                id="ceye-wait"
                value={ceyeWait}
                onChange={(e) => setCeyeWait(e.target.value)}
                disabled={!includeDns || !useCeye}
              />
            </div>
          </div>

          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              size="sm"
              variant={includeDns ? "default" : "outline"}
              onClick={() => setIncludeDns((v) => !v)}
            >
              DNS 版本探针：{includeDns ? "开" : "关"}
            </Button>
            <Button
              type="button"
              size="sm"
              variant={useCeye ? "default" : "outline"}
              disabled={!includeDns}
              onClick={() => setUseCeye((v) => !v)}
            >
              CEYE 确认：{useCeye ? "开" : "关"}
            </Button>
          </div>

          {includeDns && !useCeye ? (
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

          <Separator />

          <Button onClick={() => void onDetect()} disabled={loading}>
            {loading ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <Play className="size-4" />
            )}
            开始版本探测
          </Button>
        </CardContent>
      </Card>

      {result ? (
        <Card>
          <CardHeader className="gap-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <CardTitle>版本结果</CardTitle>
              <div className="flex flex-wrap gap-2">
                <Badge variant={result.version_range ? "default" : "secondary"}>
                  {result.version_range ?? "未知区间"}
                </Badge>
                <Badge variant="outline">
                  置信度 {(result.confidence * 100).toFixed(0)}%
                </Badge>
                {result.reported_version ? (
                  <Badge variant="outline">回显 {result.reported_version}</Badge>
                ) : null}
                {result.autotype_enabled != null ? (
                  <Badge variant="outline">
                    AutoType {result.autotype_enabled ? "开" : "关"}
                  </Badge>
                ) : null}
                {result.is_1_2_83_hint != null ? (
                  <Badge variant="outline">
                    1.2.83 探针 {result.is_1_2_83_hint ? "不报错" : "报错"}
                  </Badge>
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

            {result.reported_version_note ? (
              <Alert>
                <AlertTitle>回显说明</AlertTitle>
                <AlertDescription>{result.reported_version_note}</AlertDescription>
              </Alert>
            ) : null}

            <Tabs defaultValue="evidence">
              <TabsList>
                <TabsTrigger value="evidence">证据</TabsTrigger>
                <TabsTrigger value="dns">DNS</TabsTrigger>
                <TabsTrigger value="actions">建议</TabsTrigger>
                <TabsTrigger value="raw">JSON</TabsTrigger>
              </TabsList>

              <TabsContent value="evidence" className="mt-4">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Probe</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>结果</TableHead>
                      <TableHead>解读</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {evidenceRows.map((ev) => (
                      <TableRow key={`${ev.probe_id}-${ev.status_code}-${ev.elapsed_ms}`}>
                        <TableCell className="font-medium">{ev.probe_id}</TableCell>
                        <TableCell>{ev.category}</TableCell>
                        <TableCell>{ev.status_code || "-"}</TableCell>
                        <TableCell>
                          {ev.errored == null
                            ? "-"
                            : ev.errored
                              ? "报错"
                              : "不报错"}
                        </TableCell>
                        <TableCell className="max-w-md truncate">
                          {ev.interpretation || ev.matched.slice(0, 2).join(", ") || "-"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TabsContent>

              <TabsContent value="dns" className="mt-4 space-y-3">
                {dnsHitRows.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    本次未启用 DNS，或尚无命中记录。
                  </p>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Tag</TableHead>
                        <TableHead>命中</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {dnsHitRows.map(([tag, hit]) => (
                        <TableRow key={tag}>
                          <TableCell>{tag}</TableCell>
                          <TableCell>{hit ? "是" : "否"}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
                {result.dns_filter ? (
                  <p className="text-sm text-muted-foreground">
                    CEYE filter: <code>{result.dns_filter}</code>
                  </p>
                ) : null}
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
                <p className="text-sm text-muted-foreground">
                  方法：{result.methods_used.join(" / ") || "-"}
                </p>
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
