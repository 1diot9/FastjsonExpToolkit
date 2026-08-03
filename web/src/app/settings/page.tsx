"use client";

import { useEffect, useState } from "react";
import { Copy, Loader2, PlugZap, Save, Square, Play } from "lucide-react";
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
  fetchSettings,
  startMcpHttp,
  stopMcpHttp,
  testCeye,
  updateMcpHttpSettings,
  updateSettings,
  type McpHttpStatusResponse,
  type SettingsResponse,
} from "@/lib/api";

export default function SettingsPage() {
  const [mounted, setMounted] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [settings, setSettings] = useState<SettingsResponse | null>(null);
  const [token, setToken] = useState("");
  const [identifier, setIdentifier] = useState("");

  const [mcpHost, setMcpHost] = useState("127.0.0.1");
  const [mcpPort, setMcpPort] = useState("8100");
  const [mcpToken, setMcpToken] = useState("");
  const [mcpSaving, setMcpSaving] = useState(false);
  const [mcpStarting, setMcpStarting] = useState(false);
  const [mcpStopping, setMcpStopping] = useState(false);
  const [mcpStatus, setMcpStatus] = useState<McpHttpStatusResponse | null>(null);

  function applyMcpFromSettings(data: SettingsResponse) {
    setMcpHost(data.mcp_http_host || "127.0.0.1");
    setMcpPort(String(data.mcp_http_port || 8100));
    setMcpToken("");
    setMcpStatus({
      ok: true,
      message: "",
      running: data.mcp_http_running,
      host: data.mcp_http_host,
      port: data.mcp_http_port,
      url: data.mcp_http_url,
      token_set: data.mcp_http_token_set,
      token_masked: data.mcp_http_token_masked,
      error: data.mcp_http_error,
      pid: null,
      cursor_config: {},
    });
  }

  async function load() {
    setLoading(true);
    try {
      const data = await fetchSettings();
      setSettings(data);
      setIdentifier(data.ceye_identifier || "");
      setToken("");
      applyMcpFromSettings(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    setMounted(true);
    void load();
  }, []);

  async function onSave() {
    if (!identifier.trim()) {
      toast.error("请填写 Identifier 子域名");
      return;
    }
    if (!token.trim() && !settings?.ceye_token_set) {
      toast.error("请填写 CEYE Token");
      return;
    }

    setSaving(true);
    try {
      const res = await updateSettings({
        ceye_identifier: identifier.trim(),
        ceye_token: token.trim() || null,
      });
      setSettings(res.settings);
      setToken("");
      applyMcpFromSettings(res.settings);
      toast.success(res.message || "已保存");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  }

  async function onTest() {
    setTesting(true);
    try {
      const res = await testCeye();
      toast.success(`${res.message}（domain=${res.domain}，records=${res.record_count}）`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setTesting(false);
    }
  }

  async function onMcpSave() {
    const port = Number(mcpPort);
    if (!mcpHost.trim()) {
      toast.error("请填写 MCP 监听地址");
      return;
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      toast.error("端口须为 1–65535 的整数");
      return;
    }
    setMcpSaving(true);
    try {
      const res = await updateMcpHttpSettings({
        host: mcpHost.trim(),
        port,
        token: mcpToken.trim() || null,
      });
      setMcpStatus(res);
      setMcpToken("");
      setSettings((prev) =>
        prev
          ? {
              ...prev,
              mcp_http_host: res.host,
              mcp_http_port: res.port,
              mcp_http_url: res.url,
              mcp_http_running: res.running,
              mcp_http_token_set: res.token_set,
              mcp_http_token_masked: res.token_masked,
              mcp_http_error: res.error,
            }
          : prev,
      );
      toast.success(res.message || "MCP 配置已保存");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setMcpSaving(false);
    }
  }

  async function onMcpStart() {
    const port = Number(mcpPort);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      toast.error("端口须为 1–65535 的整数");
      return;
    }
    setMcpStarting(true);
    try {
      const res = await startMcpHttp({
        host: mcpHost.trim() || "127.0.0.1",
        port,
        token: mcpToken.trim() || null,
        persist: true,
      });
      setMcpStatus(res);
      setMcpToken("");
      setMcpHost(res.host);
      setMcpPort(String(res.port));
      toast.success(res.message || `已启动 ${res.url}`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setMcpStarting(false);
    }
  }

  async function onMcpStop() {
    setMcpStopping(true);
    try {
      const res = await stopMcpHttp();
      setMcpStatus(res);
      toast.success(res.message || "已停止");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setMcpStopping(false);
    }
  }

  async function onCopyCursorConfig() {
    const url = mcpStatus?.url || `http://${mcpHost}:${mcpPort}/mcp`;
    const entry: Record<string, unknown> = { url };
    const effectiveToken = mcpToken.trim();
    if (effectiveToken) {
      entry.headers = { Authorization: `Bearer ${effectiveToken}` };
    } else if (mcpStatus?.token_set) {
      entry.headers = {
        Authorization: "Bearer <MCP_HTTP_TOKEN>",
      };
    }
    const text = JSON.stringify(
      { mcpServers: { "fastjson-toolkit-http": entry } },
      null,
      2,
    );
    try {
      await navigator.clipboard.writeText(text);
      toast.success(
        mcpStatus?.token_set && !effectiveToken
          ? "已复制（请把 <MCP_HTTP_TOKEN> 换成真实 Token）"
          : "已复制 Cursor mcp.json 片段",
      );
    } catch {
      toast.error("复制失败");
    }
  }

  const domainPreview = (() => {
    const raw = identifier.trim().toLowerCase().replace(/\.$/, "");
    if (!raw) return "";
    if (raw.includes(".")) return raw;
    return `${raw}.ceye.io`;
  })();

  const mcpUrlPreview = `http://${
    mcpHost.trim() === "0.0.0.0" ? "127.0.0.1" : mcpHost.trim() || "127.0.0.1"
  }:${mcpPort || "8100"}/mcp`;

  const mcpBusy = mcpSaving || mcpStarting || mcpStopping || loading;

  return (
    <main className="mx-auto flex w-full max-w-3xl flex-1 flex-col gap-6 px-6 py-8">
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">设置</h1>
        <p className="text-sm text-muted-foreground">
          配置 CEYE DNSLog 与 MCP HTTP 服务，写入项目 <code>.env</code>。
        </p>
      </div>

      {error ? (
        <Alert variant="destructive">
          <AlertTitle>无法加载设置</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>CEYE DNSLog</CardTitle>
          <CardDescription>
            用于出网 DNS 确认。Identifier 即 CEYE 控制台中的子域名前缀。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {loading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="size-4 animate-spin" />
              加载中…
            </div>
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-2">
                {mounted && settings ? (
                  <>
                    <Badge variant={settings.ceye_token_set ? "default" : "secondary"}>
                      {settings.ceye_token_set ? "Token 已配置" : "Token 未配置"}
                    </Badge>
                    {settings.ceye_domain ? (
                      <Badge variant="outline">{settings.ceye_domain}</Badge>
                    ) : null}
                  </>
                ) : (
                  <Badge variant="secondary">…</Badge>
                )}
              </div>

              <div className="space-y-2">
                <Label htmlFor="ceye-token">API Token</Label>
                <Input
                  id="ceye-token"
                  type="password"
                  autoComplete="off"
                  placeholder={
                    settings?.ceye_token_set
                      ? `已配置：${settings.ceye_token_masked}（留空保留）`
                      : "粘贴 CEYE API Token"
                  }
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="ceye-identifier">Identifier 子域名</Label>
                <Input
                  id="ceye-identifier"
                  placeholder="hpdth2"
                  value={identifier}
                  onChange={(e) => setIdentifier(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  填写控制台 Identifier（如 <code>hpdth2</code>
                  ），也可直接填完整域名。
                  {domainPreview ? (
                    <>
                      {" "}
                      当前：<code>{domainPreview}</code>
                    </>
                  ) : null}
                </p>
              </div>

              {settings?.env_path ? (
                <p className="text-xs text-muted-foreground">
                  配置文件：<code>{settings.env_path}</code>
                </p>
              ) : null}

              <div className="flex flex-wrap gap-2">
                <Button onClick={() => void onSave()} disabled={saving || loading}>
                  {saving ? (
                    <Loader2 className="size-4 animate-spin" />
                  ) : (
                    <Save className="size-4" />
                  )}
                  保存
                </Button>
                <Button
                  variant="outline"
                  onClick={() => void onTest()}
                  disabled={testing || loading || !settings?.ceye_token_set}
                >
                  {testing ? (
                    <Loader2 className="size-4 animate-spin" />
                  ) : (
                    <PlugZap className="size-4" />
                  )}
                  测试连接
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => void load()}
                  disabled={loading || saving}
                >
                  重新加载
                </Button>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>MCP HTTP</CardTitle>
          <CardDescription>
            独立 Streamable HTTP 服务，供 Cursor 等 Agent 调用。可自定义监听地址与请求鉴权
            Token（客户端通过 <code>Authorization: Bearer</code> 或{" "}
            <code>X-MCP-Token</code> 传递）。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {loading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="size-4 animate-spin" />
              加载中…
            </div>
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={mcpStatus?.running ? "default" : "secondary"}>
                  {mcpStatus?.running ? "运行中" : "未启动"}
                </Badge>
                <Badge variant={mcpStatus?.token_set ? "outline" : "secondary"}>
                  {mcpStatus?.token_set
                    ? `Token ${mcpStatus.token_masked}`
                    : "无 Token"}
                </Badge>
                {mcpStatus?.url ? (
                  <Badge variant="outline">{mcpStatus.url}</Badge>
                ) : null}
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="mcp-host">服务地址（Host）</Label>
                  <Input
                    id="mcp-host"
                    placeholder="127.0.0.1"
                    value={mcpHost}
                    onChange={(e) => setMcpHost(e.target.value)}
                    disabled={mcpStatus?.running}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="mcp-port">端口</Label>
                  <Input
                    id="mcp-port"
                    inputMode="numeric"
                    placeholder="8100"
                    value={mcpPort}
                    onChange={(e) => setMcpPort(e.target.value)}
                    disabled={mcpStatus?.running}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="mcp-token">请求鉴权 Token</Label>
                <Input
                  id="mcp-token"
                  type="password"
                  autoComplete="off"
                  placeholder={
                    mcpStatus?.token_set
                      ? `已配置：${mcpStatus.token_masked}（留空保留）`
                      : "可选；建议设置后仅授权客户端可访问"
                  }
                  value={mcpToken}
                  onChange={(e) => setMcpToken(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  服务 URL 预览：<code>{mcpUrlPreview}</code>
                  。stdio 形态仍可用 <code>fjtoolkit mcp</code>。
                </p>
              </div>

              {mcpStatus?.error ? (
                <Alert variant="destructive">
                  <AlertTitle>MCP 状态异常</AlertTitle>
                  <AlertDescription>{mcpStatus.error}</AlertDescription>
                </Alert>
              ) : null}

              <div className="flex flex-wrap gap-2">
                <Button
                  onClick={() => void onMcpSave()}
                  disabled={mcpBusy || mcpStatus?.running}
                  variant="outline"
                >
                  {mcpSaving ? (
                    <Loader2 className="size-4 animate-spin" />
                  ) : (
                    <Save className="size-4" />
                  )}
                  保存配置
                </Button>
                {mcpStatus?.running ? (
                  <Button
                    variant="destructive"
                    onClick={() => void onMcpStop()}
                    disabled={mcpBusy}
                  >
                    {mcpStopping ? (
                      <Loader2 className="size-4 animate-spin" />
                    ) : (
                      <Square className="size-4" />
                    )}
                    停止服务
                  </Button>
                ) : (
                  <Button onClick={() => void onMcpStart()} disabled={mcpBusy}>
                    {mcpStarting ? (
                      <Loader2 className="size-4 animate-spin" />
                    ) : (
                      <Play className="size-4" />
                    )}
                    启动服务
                  </Button>
                )}
                <Button
                  variant="ghost"
                  onClick={() => void onCopyCursorConfig()}
                  disabled={loading}
                >
                  <Copy className="size-4" />
                  复制 Cursor 配置
                </Button>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </main>
  );
}
