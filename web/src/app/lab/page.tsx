"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Container,
  Loader2,
  Play,
  RefreshCw,
  Square,
} from "lucide-react";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  getLabCache,
  loadLabs,
  patchCacheFromAction,
} from "@/lib/lab-cache";
import {
  startLab,
  stopLab,
  type DockerEnvironment,
  type LabState,
  type LabStatus,
} from "@/lib/api";

const CATEGORY_LABEL: Record<string, string> = {
  fingerprint: "指纹",
  version: "版本",
  gadget: "Gadget",
  cve: "CVE",
};

function stateBadge(state: LabState) {
  switch (state) {
    case "running":
      return <Badge>运行中</Badge>;
    case "partial":
      return <Badge variant="secondary">部分运行</Badge>;
    case "stopped":
      return <Badge variant="outline">已停止</Badge>;
    default:
      return <Badge variant="outline">未知</Badge>;
  }
}

function DockerPanel({ docker }: { docker: DockerEnvironment | null }) {
  if (!docker) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Container className="size-5" />
          Docker 环境
        </CardTitle>
        <CardDescription>
          首次进入会识别 Docker / Compose；之后复用缓存，点「刷新状态」再重新探测。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap gap-2">
          <Badge variant={docker.ready ? "default" : "destructive"}>
            {docker.ready ? "就绪" : "未就绪"}
          </Badge>
          <Badge variant="outline">
            CLI {docker.docker_installed ? "已安装" : "未安装"}
            {docker.docker_version ? ` · ${docker.docker_version}` : ""}
          </Badge>
          <Badge variant="outline">
            Daemon {docker.docker_running ? "运行中" : "未运行"}
            {docker.engine_info ? ` · ${docker.engine_info}` : ""}
          </Badge>
          <Badge variant="outline">
            Compose {docker.compose_available ? "可用" : "不可用"}
            {docker.compose_backend ? ` · ${docker.compose_backend}` : ""}
          </Badge>
        </div>
        {docker.compose_version ? (
          <p className="text-sm text-muted-foreground">{docker.compose_version}</p>
        ) : null}
        {docker.errors.length > 0 ? (
          <Alert variant="destructive">
            <AlertTitle>环境问题</AlertTitle>
            <AlertDescription>
              <ul className="list-disc space-y-1 pl-4">
                {docker.errors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            </AlertDescription>
          </Alert>
        ) : null}
      </CardContent>
    </Card>
  );
}

type PortDrafts = Record<string, Record<string, string>>;

function syncPortDrafts(labs: LabStatus[], prev: PortDrafts): PortDrafts {
  const next: PortDrafts = { ...prev };
  for (const lab of labs) {
    const existing = next[lab.id] ?? {};
    const row: Record<string, string> = {};
    for (const info of lab.port_infos) {
      // Keep user edits while stopped; refresh from server when running.
      if (lab.state === "stopped" && existing[info.key] !== undefined) {
        row[info.key] = existing[info.key];
      } else {
        row[info.key] = String(info.value);
      }
    }
    next[lab.id] = row;
  }
  return next;
}

function parsePorts(
  lab: LabStatus,
  drafts: PortDrafts,
): Record<string, number> | null {
  const row = drafts[lab.id] ?? {};
  const out: Record<string, number> = {};
  for (const info of lab.port_infos) {
    const raw = (row[info.key] ?? String(info.value)).trim();
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
      toast.error(`${lab.name} ${info.label} 端口无效: ${raw}`);
      return null;
    }
    out[info.key] = n;
  }
  const values = Object.values(out);
  if (new Set(values).size !== values.length) {
    toast.error(`${lab.name} 端口不能重复`);
    return null;
  }
  return out;
}

/** Keep port edits across navigations within the same tab. */
let portDraftMemory: PortDrafts = {};

function formatFetchedAt(ts: number | null): string {
  if (!ts) return "";
  try {
    return new Date(ts).toLocaleTimeString();
  } catch {
    return "";
  }
}

export default function LabPage() {
  const cached = getLabCache();
  const [loading, setLoading] = useState(!cached);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(cached?.error ?? null);
  const [docker, setDocker] = useState<DockerEnvironment | null>(
    cached?.docker ?? null,
  );
  const [labs, setLabs] = useState<LabStatus[]>(cached?.labs ?? []);
  const [fetchedAt, setFetchedAt] = useState<number | null>(
    cached?.fetchedAt ?? null,
  );
  const [portDrafts, setPortDrafts] = useState<PortDrafts>(() =>
    cached ? syncPortDrafts(cached.labs, portDraftMemory) : portDraftMemory,
  );
  const [busyId, setBusyId] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<"start" | "stop" | null>(null);

  const applyCache = useCallback(
    (data: {
      docker: DockerEnvironment;
      labs: LabStatus[];
      fetchedAt: number;
      error: string | null;
    }) => {
      setDocker(data.docker);
      setLabs(data.labs);
      setFetchedAt(data.fetchedAt);
      setError(data.error);
      setPortDrafts((prev) => {
        const next = syncPortDrafts(data.labs, prev);
        portDraftMemory = next;
        return next;
      });
    },
    [],
  );

  const load = useCallback(
    async (force = false) => {
      const hasCached = Boolean(getLabCache());
      if (force) setRefreshing(true);
      else if (!hasCached) setLoading(true);
      try {
        const data = await loadLabs({ force });
        applyCache(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [applyCache],
  );

  useEffect(() => {
    const snap = getLabCache();
    if (snap) {
      applyCache(snap);
      setLoading(false);
      return;
    }
    void load(false);
  }, [applyCache, load]);

  function setPortDraft(labId: string, key: string, value: string) {
    setPortDrafts((prev) => {
      const next = {
        ...prev,
        [labId]: { ...(prev[labId] ?? {}), [key]: value },
      };
      portDraftMemory = next;
      return next;
    });
  }

  async function onStart(lab: LabStatus) {
    const ports = parsePorts(lab, portDrafts);
    if (!ports) return;

    setBusyId(lab.id);
    setBusyAction("start");
    const toastId = toast.loading(`正在启动 ${lab.name}…（首次 build 可能较久）`);
    try {
      const res = await startLab(lab.id, { build: true, ports });
      toast.success(res.message, { id: toastId });
      patchCacheFromAction({ docker: res.docker, status: res.status });
      await load(true);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err), {
        id: toastId,
      });
      await load(true);
    } finally {
      setBusyId(null);
      setBusyAction(null);
    }
  }

  async function onStop(lab: LabStatus) {
    setBusyId(lab.id);
    setBusyAction("stop");
    const toastId = toast.loading(`正在停止 ${lab.name}…`);
    try {
      const res = await stopLab(lab.id);
      toast.success(res.message, { id: toastId });
      patchCacheFromAction({ docker: res.docker, status: res.status });
      await load(true);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err), {
        id: toastId,
      });
      await load(true);
    } finally {
      setBusyId(null);
      setBusyAction(null);
    }
  }

  const busy = loading || refreshing || busyId !== null;
  const fetchedLabel = formatFetchedAt(fetchedAt);

  return (
    <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-6 px-6 py-8">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">Docker 靶场</h1>
          <p className="text-sm text-muted-foreground">
            按需启动本地复现环境；仅用于授权测试与研究。默认端口互不冲突，冲突时可手改。
            {fetchedLabel ? ` 上次探测：${fetchedLabel}` : null}
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => void load(true)}
          disabled={busy}
        >
          {refreshing || (loading && labs.length === 0) ? (
            <Loader2 className="size-4 animate-spin" />
          ) : (
            <RefreshCw className="size-4" />
          )}
          刷新状态
        </Button>
      </div>

      {error ? (
        <Alert variant="destructive">
          <AlertTitle>加载失败</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      <DockerPanel docker={docker} />

      <Card>
        <CardHeader>
          <CardTitle>靶场列表</CardTitle>
          <CardDescription>
            进入本页会复用上次探测结果；需要最新状态时点右上角「刷新状态」。
            停止状态下可改主机端口，启动时按填写端口做占用检测。
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading && labs.length === 0 ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="size-4 animate-spin" />
              正在识别 Docker 与端口…
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>靶场</TableHead>
                  <TableHead>类别</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>主机端口</TableHead>
                  <TableHead>端点</TableHead>
                  <TableHead className="text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {labs.map((lab) => {
                  const starting = busyId === lab.id && busyAction === "start";
                  const stopping = busyId === lab.id && busyAction === "stop";
                  const anyBusy = busyId !== null;
                  const drafts = portDrafts[lab.id] ?? {};
                  return (
                    <TableRow key={lab.id}>
                      <TableCell>
                        <div className="space-y-1">
                          <div className="font-medium">{lab.name}</div>
                          <div className="text-xs text-muted-foreground">
                            {lab.description}
                          </div>
                          {lab.blockers.length > 0 ? (
                            <div className="text-xs text-destructive">
                              {lab.blockers.join("；")}
                            </div>
                          ) : null}
                          {lab.warnings.length > 0 ? (
                            <div className="text-xs text-amber-600 dark:text-amber-400">
                              {lab.warnings.join("；")}
                            </div>
                          ) : null}
                          {lab.notes ? (
                            <div className="text-xs text-muted-foreground">
                              {lab.notes}
                            </div>
                          ) : null}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary">
                          {CATEGORY_LABEL[lab.category] ?? lab.category}
                        </Badge>
                      </TableCell>
                      <TableCell>{stateBadge(lab.state)}</TableCell>
                      <TableCell>
                        <div className="flex min-w-[140px] flex-col gap-2">
                          {lab.port_infos.map((info) => {
                            const check = lab.port_checks.find(
                              (p) =>
                                p.port ===
                                Number(drafts[info.key] ?? info.value),
                            );
                            return (
                              <div key={info.key} className="space-y-1">
                                <div className="flex items-center gap-2">
                                  <span className="w-10 shrink-0 text-xs text-muted-foreground">
                                    {info.label}
                                  </span>
                                  <Input
                                    className="h-8 w-[96px] font-mono text-xs"
                                    inputMode="numeric"
                                    disabled={
                                      !info.editable || anyBusy || starting
                                    }
                                    value={drafts[info.key] ?? String(info.value)}
                                    onChange={(e) =>
                                      setPortDraft(
                                        lab.id,
                                        info.key,
                                        e.target.value.replace(/[^\d]/g, ""),
                                      )
                                    }
                                    aria-label={`${lab.name} ${info.label} 端口`}
                                  />
                                </div>
                                <div className="pl-12 font-mono text-[10px] text-muted-foreground">
                                  默认 {info.default}
                                  {check
                                    ? check.occupied
                                      ? check.owned_by_lab
                                        ? " · 本靶场"
                                        : " · 占用"
                                      : " · 空闲"
                                    : null}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex max-w-[220px] flex-col gap-1">
                          {lab.endpoints.map((ep) => (
                            <a
                              key={ep}
                              href={ep}
                              target="_blank"
                              rel="noreferrer"
                              className="truncate font-mono text-xs underline underline-offset-2"
                            >
                              {ep}
                            </a>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button
                            size="sm"
                            disabled={!lab.can_start || anyBusy}
                            onClick={() => void onStart(lab)}
                          >
                            {starting ? (
                              <Loader2 className="size-4 animate-spin" />
                            ) : (
                              <Play className="size-4" />
                            )}
                            启动
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={!lab.can_stop || anyBusy}
                            onClick={() => void onStop(lab)}
                          >
                            {stopping ? (
                              <Loader2 className="size-4 animate-spin" />
                            ) : (
                              <Square className="size-4" />
                            )}
                            停止
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </main>
  );
}
