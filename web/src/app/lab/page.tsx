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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  fetchLabs,
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
          启动靶场前会校验 Docker / Compose，并检测主机端口占用。
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

export default function LabPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [docker, setDocker] = useState<DockerEnvironment | null>(null);
  const [labs, setLabs] = useState<LabStatus[]>([]);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<"start" | "stop" | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchLabs();
      setDocker(data.docker);
      setLabs(data.labs);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function onStart(lab: LabStatus) {
    setBusyId(lab.id);
    setBusyAction("start");
    const toastId = toast.loading(`正在启动 ${lab.name}…（首次 build 可能较久）`);
    try {
      const res = await startLab(lab.id, { build: true });
      toast.success(res.message, { id: toastId });
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err), {
        id: toastId,
      });
      await load();
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
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err), {
        id: toastId,
      });
      await load();
    } finally {
      setBusyId(null);
      setBusyAction(null);
    }
  }

  return (
    <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-6 px-6 py-8">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">Docker 靶场</h1>
          <p className="text-sm text-muted-foreground">
            按需启动本地复现环境；仅用于授权测试与研究。
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => void load()}
          disabled={loading || busyId !== null}
        >
          {loading ? (
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
            启动前自动检测端口；若端口被非本靶场进程占用会拦截启动。
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
                  <TableHead>端口</TableHead>
                  <TableHead>端点</TableHead>
                  <TableHead className="text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {labs.map((lab) => {
                  const starting = busyId === lab.id && busyAction === "start";
                  const stopping = busyId === lab.id && busyAction === "stop";
                  const anyBusy = busyId !== null;
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
                        <div className="flex flex-col gap-1">
                          {lab.port_checks.map((p) => (
                            <span
                              key={p.port}
                              className="font-mono text-xs text-muted-foreground"
                            >
                              {p.port}
                              <span className="ml-1">
                                {p.occupied
                                  ? p.owned_by_lab
                                    ? "·本靶场"
                                    : "·占用"
                                  : "·空闲"}
                              </span>
                            </span>
                          ))}
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
