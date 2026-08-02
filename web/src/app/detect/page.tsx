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
  detectFastjson,
  fetchHealth,
  type DetectResult,
  type HealthResponse,
} from "@/lib/api";

const PRESETS = [
  { label: "Fastjson", value: "http://127.0.0.1:18080/api/fastjson" },
  {
    label: "Fastjson (autoType)",
    value: "http://127.0.0.1:18080/api/fastjson/autotype",
  },
  { label: "Jackson", value: "http://127.0.0.1:18080/api/jackson" },
  { label: "Gson", value: "http://127.0.0.1:18080/api/gson" },
  { label: "Hutool", value: "http://127.0.0.1:18080/api/hutool" },
  { label: "org.json", value: "http://127.0.0.1:18080/api/orgjson" },
];

export default function DetectPage() {
  const [target, setTarget] = useState(PRESETS[0].value);
  const [includeDns, setIncludeDns] = useState(false);
  const [useCeye, setUseCeye] = useState(true);
  const [ceyeWait, setCeyeWait] = useState("8");
  const [timeoutSec, setTimeoutSec] = useState("10");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<DetectResult | null>(null);
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

  const scoreRows = useMemo(() => {
    if (!result) return [];
    return Object.entries(result.scores).sort((a, b) => b[1] - a[1]);
  }, [result]);

  const evidenceRows = useMemo(() => {
    if (!result) return [];
    return result.evidence.filter((e) => e.matched.length > 0 || e.score_delta > 0);
  }, [result]);

  async function onDetect() {
    if (!target.trim()) {
      toast.error("请填写目标 URL");
      return;
    }
    setLoading(true);
    try {
      const data = await detectFastjson({
        target: target.trim(),
        include_dns: includeDns,
        use_ceye: includeDns && useCeye,
        ceye_wait: Number(ceyeWait) || 8,
        timeout: Number(timeoutSec) || 10,
      });
      setResult(data);
      if (data.is_fastjson) {
        toast.success("判定为 Fastjson", {
          description: data.summary,
        });
      } else {
        toast.message("未判定为 Fastjson", {
          description: data.summary,
        });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      toast.error("探测失败", { description: msg });
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-6 px-6 py-10">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-2">
          <h1 className="text-2xl font-semibold tracking-tight">Fastjson 识别</h1>
          <p className="text-sm text-muted-foreground">
            通过后端 API 下发指纹探针；界面组件全部来自 shadcn。
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
            可直接选择本地 Docker 靶场预设，或填写任意反序列化端点。
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
              DNS 探针：{includeDns ? "开" : "关"}
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

          <Separator />

          <Button onClick={() => void onDetect()} disabled={loading}>
            {loading ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <Play className="size-4" />
            )}
            开始识别
          </Button>
        </CardContent>
      </Card>

      {result ? (
        <Card>
          <CardHeader className="gap-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <CardTitle>识别结果</CardTitle>
              <div className="flex flex-wrap gap-2">
                <Badge variant={result.is_fastjson ? "default" : "secondary"}>
                  {result.is_fastjson ? "Fastjson" : "非 Fastjson"}
                </Badge>
                <Badge variant="outline">
                  置信度 {(result.confidence * 100).toFixed(0)}%
                </Badge>
                <Badge variant="outline">guess={result.primary_guess}</Badge>
                {result.dns_confirmed != null ? (
                  <Badge variant={result.dns_confirmed ? "default" : "outline"}>
                    DNS {result.dns_confirmed ? "已确认" : "无记录"}
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

            <Tabs defaultValue="scores">
              <TabsList>
                <TabsTrigger value="scores">得分</TabsTrigger>
                <TabsTrigger value="evidence">证据</TabsTrigger>
                <TabsTrigger value="actions">建议</TabsTrigger>
                <TabsTrigger value="raw">JSON</TabsTrigger>
              </TabsList>

              <TabsContent value="scores" className="mt-4">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Library</TableHead>
                      <TableHead className="text-right">Score</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {scoreRows.map(([name, score]) => (
                      <TableRow key={name}>
                        <TableCell>{name}</TableCell>
                        <TableCell className="text-right">{score.toFixed(3)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TabsContent>

              <TabsContent value="evidence" className="mt-4">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Probe</TableHead>
                      <TableHead>Hint</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Matched</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {evidenceRows.map((ev) => (
                      <TableRow key={`${ev.probe_id}-${ev.status_code}-${ev.elapsed_ms}`}>
                        <TableCell className="font-medium">{ev.probe_id}</TableCell>
                        <TableCell>{ev.library_hint ?? "-"}</TableCell>
                        <TableCell>{ev.status_code}</TableCell>
                        <TableCell className="max-w-md truncate">
                          {ev.matched.slice(0, 3).join(", ") || "-"}
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
                {result.dns_filter ? (
                  <p className="text-sm text-muted-foreground">
                    CEYE filter: <code>{result.dns_filter}</code>
                  </p>
                ) : null}
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
