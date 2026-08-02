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
  detectExpectClass,
  fetchHealth,
  type ExpectClassResult,
  type HealthResponse,
} from "@/lib/api";

const PRESETS = [
  {
    label: "Fastjson 无期望类",
    value: "http://127.0.0.1:18080/api/fastjson",
    body: '{"age":20,"name":"Bob"}',
  },
  {
    label: "Fastjson Person（有期望类）",
    value: "http://127.0.0.1:18080/api/fastjson/person",
    body: '{"age":20,"name":"Bob"}',
  },
  {
    label: "Fastjson autoType",
    value: "http://127.0.0.1:18080/api/fastjson/autotype",
    body: '{"age":20,"name":"Bob"}',
  },
  {
    label: "笔记示例账号参数",
    value: "http://127.0.0.1:18080/api/fastjson/person",
    body: '{"username":"admin","password":"123456"}',
  },
];

function boolLabel(v: boolean | null | undefined): string {
  if (v === true) return "是";
  if (v === false) return "否";
  return "未知";
}

export default function ExpectPage() {
  const [preset, setPreset] = useState(PRESETS[1].value + "|" + PRESETS[1].body);
  const [target, setTarget] = useState(PRESETS[1].value);
  const [baseBody, setBaseBody] = useState(PRESETS[1].body);
  const [timeoutSec, setTimeoutSec] = useState("10");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ExpectClassResult | null>(null);
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

  const evidenceRows = useMemo(() => result?.evidence ?? [], [result]);

  async function onDetect() {
    if (!target.trim()) {
      toast.error("请填写目标 URL");
      return;
    }
    setLoading(true);
    try {
      const data = await detectExpectClass({
        target: target.trim(),
        base_body: baseBody.trim() || null,
        timeout: Number(timeoutSec) || 10,
      });
      setResult(data);
      if (data.has_expect_class === true) {
        toast.success("判定存在期望类", { description: data.summary });
      } else if (data.has_expect_class === false) {
        toast.message("判定无期望类（或 Map）", { description: data.summary });
      } else {
        toast.message("未能判定", { description: data.summary });
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
          <h1 className="text-2xl font-semibold tracking-tight">期望类探测</h1>
          <p className="text-sm text-muted-foreground">
            判断反序列化点是否绑定期望类（如{" "}
            <code>parseObject(payload, T.class)</code>
            ），并附带 &lt;1.2.68 版本提示。
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
            在原始请求参数上注入 Feature @type 与空键语法；报错组合用于判定期望类。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>靶场预设</Label>
            <Select
              value={preset}
              onValueChange={(v) => {
                if (!v) return;
                setPreset(v);
                const item = PRESETS.find((p) => `${p.value}|${p.body}` === v);
                if (item) {
                  setTarget(item.value);
                  setBaseBody(item.body);
                }
              }}
            >
              <SelectTrigger className="w-full">
                <SelectValue placeholder="选择预设" />
              </SelectTrigger>
              <SelectContent>
                {PRESETS.map((p) => (
                  <SelectItem key={`${p.value}|${p.body}`} value={`${p.value}|${p.body}`}>
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
              placeholder="http://127.0.0.1:18080/api/fastjson/person"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="base-body">原始请求 JSON（base_body）</Label>
            <Textarea
              id="base-body"
              className="min-h-28 font-mono text-xs"
              value={baseBody}
              onChange={(e) => setBaseBody(e.target.value)}
              placeholder='{"age":20,"name":"Bob"}'
            />
          </div>

          <div className="space-y-2 sm:max-w-xs">
            <Label htmlFor="timeout">超时（秒）</Label>
            <Input
              id="timeout"
              value={timeoutSec}
              onChange={(e) => setTimeoutSec(e.target.value)}
            />
          </div>

          <Separator />

          <Button onClick={() => void onDetect()} disabled={loading}>
            {loading ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <Play className="size-4" />
            )}
            开始探测
          </Button>
        </CardContent>
      </Card>

      {result ? (
        <Card>
          <CardHeader className="gap-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <CardTitle>探测结果</CardTitle>
              <div className="flex flex-wrap gap-2">
                <Badge
                  variant={
                    result.has_expect_class === true
                      ? "default"
                      : result.has_expect_class === false
                        ? "secondary"
                        : "outline"
                  }
                >
                  期望类 {boolLabel(result.has_expect_class)}
                </Badge>
                <Badge variant="outline">
                  非 Map {boolLabel(result.expect_not_map)}
                </Badge>
                <Badge variant="outline">
                  &lt;1.2.68 {boolLabel(result.version_lt_1_2_68_hint)}
                </Badge>
                <Badge variant="outline">
                  置信度 {(result.confidence * 100).toFixed(0)}%
                </Badge>
              </div>
            </div>
            <CardDescription className="break-all">{result.target}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Alert>
              <AlertTitle>摘要</AlertTitle>
              <AlertDescription>{result.summary}</AlertDescription>
            </Alert>

            {result.notes.length > 0 ? (
              <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
                {result.notes.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            ) : null}

            <Tabs defaultValue="evidence">
              <TabsList>
                <TabsTrigger value="evidence">证据</TabsTrigger>
                <TabsTrigger value="actions">建议</TabsTrigger>
                <TabsTrigger value="raw">JSON</TabsTrigger>
              </TabsList>

              <TabsContent value="evidence" className="mt-4">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Probe</TableHead>
                      <TableHead>Errored</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Interpretation</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {evidenceRows.map((ev) => (
                      <TableRow key={`${ev.probe_id}-${ev.status_code}-${ev.elapsed_ms}`}>
                        <TableCell className="font-medium">{ev.probe_id}</TableCell>
                        <TableCell>{boolLabel(ev.errored)}</TableCell>
                        <TableCell>{ev.status_code}</TableCell>
                        <TableCell className="max-w-md truncate">
                          {ev.interpretation || "-"}
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
