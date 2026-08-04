"use client";

import { useEffect, useMemo, useState } from "react";
import { Check, Loader2, Play, RefreshCw, X } from "lucide-react";
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
  detectExpectClass,
  detectFastjson,
  detectVersion,
  fetchDepsCatalog,
  fetchHealth,
  type DepCatalogEntry,
  type DepMethod,
  type DepsResult,
  type DetectResult,
  type ExpectClassResult,
  type HealthResponse,
  type VersionResult,
} from "@/lib/api";
import { cn } from "@/lib/utils";

type StepId = "detect" | "version" | "expect" | "deps";
type PipelineStepId = "detect" | "version" | "expect";
type StepStatus = "idle" | "running" | "done" | "error" | "skipped";

const PIPELINE_STEPS: { id: PipelineStepId; label: string }[] = [
  { id: "detect", label: "识别" },
  { id: "version", label: "版本" },
  { id: "expect", label: "期望类" },
];
const PRESETS = [
  {
    label: "Fastjson echo",
    value: "http://127.0.0.1:18080/api/fastjson",
    body: '{"age":20,"name":"Bob"}',
  },
  {
    label: "Fastjson silent+DNS",
    value: "http://127.0.0.1:18080/api/fastjson/silent",
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
    label: "1.2.80 echo",
    value: "http://127.0.0.1:18082/api/fastjson",
    body: '{"age":20,"name":"Bob"}',
  },
  {
    label: "1.2.68 echo",
    value: "http://127.0.0.1:18068/api/fastjson",
    body: '{"age":20,"name":"Bob"}',
  },
  {
    label: "1.2.47 silent",
    value: "http://127.0.0.1:18047/api/fastjson/silent",
    body: '{"age":20,"name":"Bob"}',
  },
  {
    label: "Jackson",
    value: "http://127.0.0.1:18080/api/jackson",
    body: '{"age":20,"name":"Bob"}',
  },
];

function boolLabel(v: boolean | null | undefined): string {
  if (v === true) return "是";
  if (v === false) return "否";
  return "未知";
}

function depsStatusBadgeVariant(
  status: string,
): "default" | "secondary" | "outline" | "destructive" {
  if (status === "present") return "default";
  if (status === "error") return "destructive";
  if (status === "absent") return "secondary";
  return "outline";
}

function StepBadge({
  label,
  status,
  enabled,
}: {
  label: string;
  status: StepStatus;
  enabled: boolean;
}) {
  const variant =
    status === "done"
      ? "default"
      : status === "error"
        ? "destructive"
        : status === "running"
          ? "secondary"
          : "outline";

  return (
    <Badge
      variant={variant}
      className={cn("gap-1", !enabled && status === "idle" && "opacity-50")}
    >
      {status === "running" ? (
        <Loader2 className="size-3 animate-spin" />
      ) : status === "done" ? (
        <Check className="size-3" />
      ) : status === "error" ? (
        <X className="size-3" />
      ) : null}
      {label}
      {status === "skipped" ? " · 跳过" : null}
      {!enabled && status === "idle" ? " · 关" : null}
    </Badge>
  );
}

export default function DetectPage() {
  const [preset, setPreset] = useState(
    `${PRESETS[0].value}|${PRESETS[0].body}`,
  );
  const [target, setTarget] = useState(PRESETS[0].value);
  const [baseBody, setBaseBody] = useState(PRESETS[0].body);
  const [includeDns, setIncludeDns] = useState(true);
  const [useCeye, setUseCeye] = useState(true);
  const [dnslog, setDnslog] = useState("");
  const [ceyeWait, setCeyeWait] = useState("10");
  const [timeoutSec, setTimeoutSec] = useState("10");
  const [runDetect, setRunDetect] = useState(true);
  const [runVersion, setRunVersion] = useState(true);
  const [runExpect, setRunExpect] = useState(true);
  const [depsMethod, setDepsMethod] = useState<DepMethod>("character");
  const [concurrency, setConcurrency] = useState("6");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [customClasses, setCustomClasses] = useState("");

  const [pipelineLoading, setPipelineLoading] = useState(false);
  const [depsLoading, setDepsLoading] = useState(false);
  const loading = pipelineLoading || depsLoading;
  const [stepStatus, setStepStatus] = useState<Record<StepId, StepStatus>>({
    detect: "idle",
    version: "idle",
    expect: "idle",
    deps: "idle",
  });
  const [detectResult, setDetectResult] = useState<DetectResult | null>(null);
  const [versionResult, setVersionResult] = useState<VersionResult | null>(null);
  const [expectResult, setExpectResult] = useState<ExpectClassResult | null>(
    null,
  );
  const [depsResult, setDepsResult] = useState<DepsResult | null>(null);
  const [resultTab, setResultTab] = useState<StepId>("detect");
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

  const detectScoreRows = useMemo(() => {
    if (!detectResult) return [];
    return Object.entries(detectResult.scores).sort((a, b) => b[1] - a[1]);
  }, [detectResult]);

  const detectEvidenceRows = useMemo(() => {
    if (!detectResult) return [];
    return detectResult.evidence.filter(
      (e) => e.matched.length > 0 || e.score_delta > 0,
    );
  }, [detectResult]);

  const versionDnsHitRows = useMemo(() => {
    if (!versionResult) return [];
    return Object.entries(versionResult.dns_hits);
  }, [versionResult]);

  const enabledSteps = useMemo(
    () => ({
      detect: runDetect,
      version: runVersion,
      expect: runExpect,
    }),
    [runDetect, runVersion, runExpect],
  );

  async function onPipeline() {
    if (!target.trim()) {
      toast.error("请填写目标 URL");
      return;
    }
    if (!runDetect && !runVersion && !runExpect) {
      toast.error("请至少开启一个探测步骤");
      return;
    }
    if ((runDetect || runVersion) && includeDns && !useCeye && !dnslog.trim()) {
      toast.error("开启 DNS 时请启用 CEYE，或填写自定义 DNSLog 域名");
      return;
    }

    setPipelineLoading(true);
    setDetectResult(null);
    setVersionResult(null);
    setExpectResult(null);
    setStepStatus((s) => ({
      ...s,
      detect: runDetect ? "idle" : "skipped",
      version: runVersion ? "idle" : "skipped",
      expect: runExpect ? "idle" : "skipped",
    }));

    const timeout = Number(timeoutSec) || 10;
    const wait = Number(ceyeWait) || 10;
    const dnsOpts = {
      include_dns: includeDns,
      use_ceye: includeDns && useCeye,
      dnslog: includeDns && !useCeye ? dnslog.trim() : null,
      ceye_wait: wait,
      timeout,
    };

    let isFastjson: boolean | null = null;
    let firstTab: PipelineStepId | null = null;

    try {
      if (runDetect) {
        setStepStatus((s) => ({ ...s, detect: "running" }));
        setResultTab("detect");
        try {
          const data = await detectFastjson({
            target: target.trim(),
            ...dnsOpts,
          });
          setDetectResult(data);
          setStepStatus((s) => ({ ...s, detect: "done" }));
          isFastjson = data.is_fastjson;
          firstTab ??= "detect";
          if (data.is_fastjson) {
            toast.success("识别：Fastjson", { description: data.summary });
          } else {
            toast.message("识别：非 Fastjson", { description: data.summary });
          }
        } catch (err) {
          setStepStatus((s) => ({ ...s, detect: "error" }));
          const msg = err instanceof Error ? err.message : String(err);
          toast.error("识别失败", { description: msg });
          return;
        }
      }

      if (runVersion) {
        if (isFastjson === false) {
          setStepStatus((s) => ({ ...s, version: "skipped" }));
        } else {
          setStepStatus((s) => ({ ...s, version: "running" }));
          setResultTab("version");
          try {
            const data = await detectVersion({
              target: target.trim(),
              ...dnsOpts,
            });
            setVersionResult(data);
            setStepStatus((s) => ({ ...s, version: "done" }));
            firstTab ??= "version";
            if (data.version_range) {
              toast.success("版本探测完成", { description: data.summary });
            } else {
              toast.message("未能收敛版本", { description: data.summary });
            }
          } catch (err) {
            setStepStatus((s) => ({ ...s, version: "error" }));
            const msg = err instanceof Error ? err.message : String(err);
            toast.error("版本探测失败", { description: msg });
            // 继续期望类
          }
        }
      }

      if (runExpect) {
        if (isFastjson === false) {
          setStepStatus((s) => ({ ...s, expect: "skipped" }));
        } else {
          setStepStatus((s) => ({ ...s, expect: "running" }));
          setResultTab("expect");
          try {
            const data = await detectExpectClass({
              target: target.trim(),
              base_body: baseBody.trim() || null,
              timeout,
            });
            setExpectResult(data);
            setStepStatus((s) => ({ ...s, expect: "done" }));
            firstTab ??= "expect";
            if (data.has_expect_class === true) {
              toast.success("判定存在期望类", { description: data.summary });
            } else if (data.has_expect_class === false) {
              toast.message("判定无期望类（或 Map）", {
                description: data.summary,
              });
            } else {
              toast.message("期望类未能判定", { description: data.summary });
            }
          } catch (err) {
            setStepStatus((s) => ({ ...s, expect: "error" }));
            const msg = err instanceof Error ? err.message : String(err);
            toast.error("期望类探测失败", { description: msg });
          }
        }
      }

      if (isFastjson === false && (runVersion || runExpect)) {
        toast.message("已跳过后续步骤", {
          description: "识别结果非 Fastjson，未执行版本 / 期望类探测。",
        });
      }

      if (firstTab) setResultTab(firstTab);
    } finally {
      setPipelineLoading(false);
    }
  }

  async function onDeps() {
    if (!target.trim()) {
      toast.error("请填写目标 URL");
      return;
    }
    if (depsMethod === "dns" && !useCeye && !dnslog.trim()) {
      toast.error("DNS 方法请启用 CEYE，或填写自定义 DNSLog 域名");
      return;
    }

    setDepsLoading(true);
    setDepsResult(null);
    setStepStatus((s) => ({ ...s, deps: "running" }));
    setResultTab("deps");

    try {
      const classes = customClasses
        .split(/[\n,;]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const data = await detectDeps({
        target: target.trim(),
        method: depsMethod,
        classes,
        categories: categoryFilter === "all" ? [] : [categoryFilter],
        use_ceye: depsMethod === "dns" && useCeye,
        dnslog: depsMethod === "dns" && !useCeye ? dnslog.trim() : null,
        ceye_wait: Number(ceyeWait) || 10,
        timeout: Number(timeoutSec) || 10,
        concurrency: Number(concurrency) || 6,
      });
      setDepsResult(data);
      setStepStatus((s) => ({ ...s, deps: "done" }));
      if (data.present_count > 0) {
        toast.success("依赖探测完成", { description: data.summary });
      } else {
        toast.message("未发现命中依赖", { description: data.summary });
      }
    } catch (err) {
      setStepStatus((s) => ({ ...s, deps: "error" }));
      const msg = err instanceof Error ? err.message : String(err);
      toast.error("依赖探测失败", { description: msg });
    } finally {
      setDepsLoading(false);
    }
  }

  const hasAnyResult =
    detectResult || versionResult || expectResult || depsResult;

  return (
    <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-6 px-6 py-10">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-2">
          <h1 className="text-2xl font-semibold tracking-tight">Fastjson 探测</h1>
          <p className="text-sm text-muted-foreground">
            识别 → 版本 → 期望类可按序执行；依赖为独立阶段，可单独发起，不依赖前三步结果。
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
            <RefreshCw
              className={`size-4 ${healthLoading ? "animate-spin" : ""}`}
            />
            刷新
          </Button>
        </div>
      </div>

      {healthError ? (
        <Alert variant="destructive">
          <AlertTitle>后端不可用</AlertTitle>
          <AlertDescription>
            {healthError}。请先执行{" "}
            <code className="rounded bg-muted px-1">./scripts/start.sh</code>{" "}
            或{" "}
            <code className="rounded bg-muted px-1">fjtoolkit serve</code>
            （端口占用时会自动换口，见启动输出）。
          </AlertDescription>
        </Alert>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>识别 / 版本 / 期望类</CardTitle>
          <CardDescription>
            按序执行；识别非 Fastjson 时自动跳过版本与期望类。
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
                  <SelectItem
                    key={`${p.value}|${p.body}`}
                    value={`${p.value}|${p.body}`}
                  >
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

          <div className="space-y-2">
            <Label htmlFor="base-body">原始请求 JSON（期望类 base_body）</Label>
            <Textarea
              id="base-body"
              className="min-h-24 font-mono text-xs"
              value={baseBody}
              onChange={(e) => setBaseBody(e.target.value)}
              placeholder='{"age":20,"name":"Bob"}'
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

          <div className="space-y-2">
            <Label>执行步骤</Label>
            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                size="sm"
                variant={runDetect ? "default" : "outline"}
                onClick={() => setRunDetect((v) => !v)}
                disabled={loading}
              >
                识别：{runDetect ? "开" : "关"}
              </Button>
              <Button
                type="button"
                size="sm"
                variant={runVersion ? "default" : "outline"}
                onClick={() => setRunVersion((v) => !v)}
                disabled={loading}
              >
                版本：{runVersion ? "开" : "关"}
              </Button>
              <Button
                type="button"
                size="sm"
                variant={runExpect ? "default" : "outline"}
                onClick={() => setRunExpect((v) => !v)}
                disabled={loading}
              >
                期望类：{runExpect ? "开" : "关"}
              </Button>
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

          <div className="flex flex-wrap items-center gap-3">
            <Button onClick={() => void onPipeline()} disabled={loading}>
              {pipelineLoading ? (
                <Loader2 className="size-4 animate-spin" />
              ) : (
                <Play className="size-4" />
              )}
              按序探测
            </Button>
            <div className="flex flex-wrap gap-2">
              {PIPELINE_STEPS.map((step) => (
                <StepBadge
                  key={step.id}
                  label={step.label}
                  status={stepStatus[step.id]}
                  enabled={enabledSteps[step.id]}
                />
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>依赖探测</CardTitle>
          <CardDescription>
            独立阶段，不依赖上方识别结果。默认 Character 报错回显；与上方共用目标
            URL。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="deps-target">目标 URL</Label>
            <Input
              id="deps-target"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="http://127.0.0.1:18080/api/fastjson"
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>方法</Label>
              <Select
                value={depsMethod}
                onValueChange={(v) => {
                  if (v === "character" || v === "dns") setDepsMethod(v);
                }}
              >
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="character">
                    character（报错回显）
                  </SelectItem>
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
              <Label htmlFor="deps-timeout">超时（秒）</Label>
              <Input
                id="deps-timeout"
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
                disabled={depsMethod !== "character"}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="deps-ceye-wait">CEYE 等待（秒）</Label>
              <Input
                id="deps-ceye-wait"
                value={ceyeWait}
                onChange={(e) => setCeyeWait(e.target.value)}
                disabled={depsMethod !== "dns" || !useCeye}
              />
            </div>
          </div>

          {depsMethod === "dns" ? (
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
                  <Label htmlFor="deps-dnslog">自定义 DNSLog 域名</Label>
                  <Input
                    id="deps-dnslog"
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

          <div className="flex flex-wrap items-center gap-3">
            <Button onClick={() => void onDeps()} disabled={loading}>
              {depsLoading ? (
                <Loader2 className="size-4 animate-spin" />
              ) : (
                <Play className="size-4" />
              )}
              开始依赖探测
            </Button>
            <StepBadge label="依赖" status={stepStatus.deps} enabled />
          </div>
        </CardContent>
      </Card>

      {hasAnyResult ? (
        <Card>
          <CardHeader className="gap-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <CardTitle>探测结果</CardTitle>
              <div className="flex flex-wrap gap-2">
                {detectResult ? (
                  <Badge
                    variant={detectResult.is_fastjson ? "default" : "secondary"}
                  >
                    {detectResult.is_fastjson ? "Fastjson" : "非 Fastjson"}
                  </Badge>
                ) : null}
                {versionResult?.version_range ? (
                  <Badge variant="outline">
                    {versionResult.version_detail &&
                    versionResult.version_detail !== versionResult.version_range
                      ? `${versionResult.version_range} · ${versionResult.version_detail}`
                      : versionResult.version_range}
                  </Badge>
                ) : null}
                {expectResult ? (
                  <Badge variant="outline">
                    期望类 {boolLabel(expectResult.has_expect_class)}
                  </Badge>
                ) : null}
                {depsResult ? (
                  <Badge
                    variant={
                      depsResult.present_count ? "default" : "secondary"
                    }
                  >
                    依赖 {depsResult.present_count}/{depsResult.scanned}
                  </Badge>
                ) : null}
              </div>
            </div>
            <CardDescription className="break-all">{target}</CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs
              value={resultTab}
              onValueChange={(v) => {
                if (
                  v === "detect" ||
                  v === "version" ||
                  v === "expect" ||
                  v === "deps"
                ) {
                  setResultTab(v);
                }
              }}
            >
              <TabsList>
                <TabsTrigger value="detect" disabled={!detectResult}>
                  识别
                </TabsTrigger>
                <TabsTrigger value="version" disabled={!versionResult}>
                  版本
                </TabsTrigger>
                <TabsTrigger value="expect" disabled={!expectResult}>
                  期望类
                </TabsTrigger>
                <TabsTrigger value="deps" disabled={!depsResult}>
                  依赖
                </TabsTrigger>
              </TabsList>

              <TabsContent value="detect" className="mt-4 space-y-4">
                {detectResult ? (
                  <>
                    <div className="flex flex-wrap gap-2">
                      <Badge
                        variant={
                          detectResult.is_fastjson ? "default" : "secondary"
                        }
                      >
                        {detectResult.is_fastjson ? "Fastjson" : "非 Fastjson"}
                      </Badge>
                      <Badge variant="outline">
                        置信度 {(detectResult.confidence * 100).toFixed(0)}%
                      </Badge>
                      <Badge variant="outline">
                        guess={detectResult.primary_guess}
                      </Badge>
                      {detectResult.dns_confirmed != null ? (
                        <Badge
                          variant={
                            detectResult.dns_confirmed ? "default" : "outline"
                          }
                        >
                          DNS{" "}
                          {detectResult.dns_confirmed ? "已确认" : "无记录"}
                        </Badge>
                      ) : null}
                    </div>
                    <Alert>
                      <AlertTitle>摘要</AlertTitle>
                      <AlertDescription>{detectResult.summary}</AlertDescription>
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
                            {detectScoreRows.map(([name, score]) => (
                              <TableRow key={name}>
                                <TableCell>{name}</TableCell>
                                <TableCell className="text-right">
                                  {score.toFixed(3)}
                                </TableCell>
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
                            {detectEvidenceRows.map((ev) => (
                              <TableRow
                                key={`${ev.probe_id}-${ev.status_code}-${ev.elapsed_ms}`}
                              >
                                <TableCell className="font-medium">
                                  {ev.probe_id}
                                </TableCell>
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
                        {detectResult.next_actions.length === 0 ? (
                          <p className="text-sm text-muted-foreground">
                            无额外建议
                          </p>
                        ) : (
                          <ol className="list-decimal space-y-1 pl-5 text-sm">
                            {detectResult.next_actions.map((item) => (
                              <li key={item}>{item}</li>
                            ))}
                          </ol>
                        )}
                      </TabsContent>
                      <TabsContent value="raw" className="mt-4">
                        <Textarea
                          className="min-h-72 font-mono text-xs"
                          readOnly
                          value={JSON.stringify(detectResult, null, 2)}
                        />
                      </TabsContent>
                    </Tabs>
                  </>
                ) : (
                  <p className="text-sm text-muted-foreground">暂无识别结果</p>
                )}
              </TabsContent>

              <TabsContent value="version" className="mt-4 space-y-4">
                {versionResult ? (
                  <>
                    <div className="flex flex-wrap gap-2">
                      <Badge
                        variant={
                          versionResult.version_range ? "default" : "secondary"
                        }
                      >
                        {versionResult.version_range ?? "未知区间"}
                      </Badge>
                      {versionResult.version_detail &&
                      versionResult.version_detail !==
                        versionResult.version_range ? (
                        <Badge variant="outline">
                          细分 {versionResult.version_detail}
                        </Badge>
                      ) : null}
                      <Badge variant="outline">
                        置信度 {(versionResult.confidence * 100).toFixed(0)}%
                      </Badge>
                      {versionResult.reported_version ? (
                        <Badge variant="outline">
                          回显 {versionResult.reported_version}
                        </Badge>
                      ) : null}
                      {versionResult.autotype_enabled != null ? (
                        <Badge variant="outline">
                          AutoType{" "}
                          {versionResult.autotype_enabled ? "开" : "关"}
                        </Badge>
                      ) : null}
                      {versionResult.safemode_enabled != null ? (
                        <Badge variant="outline">
                          SafeMode{" "}
                          {versionResult.safemode_enabled ? "开" : "关"}
                        </Badge>
                      ) : null}
                    </div>
                    <Alert>
                      <AlertTitle>摘要</AlertTitle>
                      <AlertDescription>
                        {versionResult.summary}
                      </AlertDescription>
                    </Alert>
                    {versionResult.reported_version_note ? (
                      <Alert>
                        <AlertTitle>回显说明</AlertTitle>
                        <AlertDescription>
                          {versionResult.reported_version_note}
                        </AlertDescription>
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
                            {versionResult.evidence.map((ev) => (
                              <TableRow
                                key={`${ev.probe_id}-${ev.status_code}-${ev.elapsed_ms}`}
                              >
                                <TableCell className="font-medium">
                                  {ev.probe_id}
                                </TableCell>
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
                                  {ev.interpretation ||
                                    ev.matched.slice(0, 2).join(", ") ||
                                    "-"}
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TabsContent>
                      <TabsContent value="dns" className="mt-4 space-y-3">
                        {versionDnsHitRows.length === 0 ? (
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
                              {versionDnsHitRows.map(([tag, hit]) => (
                                <TableRow key={tag}>
                                  <TableCell>{tag}</TableCell>
                                  <TableCell>{hit ? "是" : "否"}</TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        )}
                        {versionResult.dns_filter ? (
                          <p className="text-sm text-muted-foreground">
                            CEYE filter: <code>{versionResult.dns_filter}</code>
                          </p>
                        ) : null}
                      </TabsContent>
                      <TabsContent value="actions" className="mt-4 space-y-2">
                        {versionResult.next_actions.length === 0 ? (
                          <p className="text-sm text-muted-foreground">
                            无额外建议
                          </p>
                        ) : (
                          <ol className="list-decimal space-y-1 pl-5 text-sm">
                            {versionResult.next_actions.map((item) => (
                              <li key={item}>{item}</li>
                            ))}
                          </ol>
                        )}
                        <p className="text-sm text-muted-foreground">
                          方法：{versionResult.methods_used.join(" / ") || "-"}
                        </p>
                      </TabsContent>
                      <TabsContent value="raw" className="mt-4">
                        <Textarea
                          className="min-h-72 font-mono text-xs"
                          readOnly
                          value={JSON.stringify(versionResult, null, 2)}
                        />
                      </TabsContent>
                    </Tabs>
                  </>
                ) : (
                  <p className="text-sm text-muted-foreground">暂无版本结果</p>
                )}
              </TabsContent>

              <TabsContent value="expect" className="mt-4 space-y-4">
                {expectResult ? (
                  <>
                    <div className="flex flex-wrap gap-2">
                      <Badge
                        variant={
                          expectResult.has_expect_class === true
                            ? "default"
                            : expectResult.has_expect_class === false
                              ? "secondary"
                              : "outline"
                        }
                      >
                        期望类 {boolLabel(expectResult.has_expect_class)}
                      </Badge>
                      <Badge variant="outline">
                        非 Map {boolLabel(expectResult.expect_not_map)}
                      </Badge>
                      <Badge variant="outline">
                        &lt;1.2.68{" "}
                        {boolLabel(expectResult.version_lt_1_2_68_hint)}
                      </Badge>
                      <Badge variant="outline">
                        置信度 {(expectResult.confidence * 100).toFixed(0)}%
                      </Badge>
                    </div>
                    <Alert>
                      <AlertTitle>摘要</AlertTitle>
                      <AlertDescription>{expectResult.summary}</AlertDescription>
                    </Alert>
                    {expectResult.notes.length > 0 ? (
                      <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
                        {expectResult.notes.map((n) => (
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
                            {expectResult.evidence.map((ev) => (
                              <TableRow
                                key={`${ev.probe_id}-${ev.status_code}-${ev.elapsed_ms}`}
                              >
                                <TableCell className="font-medium">
                                  {ev.probe_id}
                                </TableCell>
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
                        {expectResult.next_actions.length === 0 ? (
                          <p className="text-sm text-muted-foreground">
                            无额外建议
                          </p>
                        ) : (
                          <ol className="list-decimal space-y-1 pl-5 text-sm">
                            {expectResult.next_actions.map((item) => (
                              <li key={item}>{item}</li>
                            ))}
                          </ol>
                        )}
                      </TabsContent>
                      <TabsContent value="raw" className="mt-4">
                        <Textarea
                          className="min-h-72 font-mono text-xs"
                          readOnly
                          value={JSON.stringify(expectResult, null, 2)}
                        />
                      </TabsContent>
                    </Tabs>
                  </>
                ) : (
                  <p className="text-sm text-muted-foreground">暂无期望类结果</p>
                )}
              </TabsContent>

              <TabsContent value="deps" className="mt-4 space-y-4">
                {depsResult ? (
                  <>
                    <div className="flex flex-wrap gap-2">
                      <Badge
                        variant={
                          depsResult.present_count ? "default" : "secondary"
                        }
                      >
                        命中 {depsResult.present_count}/{depsResult.scanned}
                      </Badge>
                      <Badge variant="outline">{depsResult.method}</Badge>
                      {depsResult.absent_count ? (
                        <Badge variant="outline">
                          absent {depsResult.absent_count}
                        </Badge>
                      ) : null}
                      {depsResult.unknown_count ? (
                        <Badge variant="outline">
                          unknown {depsResult.unknown_count}
                        </Badge>
                      ) : null}
                      {depsResult.error_count ? (
                        <Badge variant="destructive">
                          error {depsResult.error_count}
                        </Badge>
                      ) : null}
                    </div>
                    <Alert>
                      <AlertTitle>摘要</AlertTitle>
                      <AlertDescription>{depsResult.summary}</AlertDescription>
                    </Alert>
                    {depsResult.notes.length ? (
                      <Alert>
                        <AlertTitle>说明</AlertTitle>
                        <AlertDescription>
                          <ul className="list-disc space-y-1 pl-4">
                            {depsResult.notes.map((n) => (
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
                        {depsResult.present.length === 0 ? (
                          <p className="text-sm text-muted-foreground">
                            无命中依赖
                          </p>
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
                              {depsResult.present.map((hit) => (
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
                            {depsResult.results.map((hit) => (
                              <TableRow key={`${hit.clazz}-${hit.status}`}>
                                <TableCell>
                                  <Badge
                                    variant={depsStatusBadgeVariant(hit.status)}
                                  >
                                    {hit.status}
                                  </Badge>
                                </TableCell>
                                <TableCell>{hit.description}</TableCell>
                                <TableCell className="max-w-xs truncate font-mono text-xs">
                                  {hit.clazz}
                                </TableCell>
                                <TableCell>{hit.status_code || "-"}</TableCell>
                                <TableCell>
                                  {hit.elapsed_ms
                                    ? `${hit.elapsed_ms}ms`
                                    : "-"}
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TabsContent>
                      <TabsContent value="actions" className="mt-4 space-y-2">
                        {depsResult.next_actions.length === 0 ? (
                          <p className="text-sm text-muted-foreground">
                            无额外建议
                          </p>
                        ) : (
                          <ol className="list-decimal space-y-1 pl-5 text-sm">
                            {depsResult.next_actions.map((item) => (
                              <li key={item}>{item}</li>
                            ))}
                          </ol>
                        )}
                      </TabsContent>
                      <TabsContent value="raw" className="mt-4">
                        <Textarea
                          className="min-h-72 font-mono text-xs"
                          readOnly
                          value={JSON.stringify(depsResult, null, 2)}
                        />
                      </TabsContent>
                    </Tabs>
                  </>
                ) : (
                  <p className="text-sm text-muted-foreground">暂无依赖结果</p>
                )}
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      ) : null}
    </main>
  );
}
