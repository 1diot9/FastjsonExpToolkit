"use client";

import { useEffect, useState } from "react";
import { Loader2, PlugZap, Save } from "lucide-react";
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
  testCeye,
  updateSettings,
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

  async function load() {
    setLoading(true);
    try {
      const data = await fetchSettings();
      setSettings(data);
      setIdentifier(data.ceye_identifier || "");
      setToken("");
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

  const domainPreview = (() => {
    const raw = identifier.trim().toLowerCase().replace(/\.$/, "");
    if (!raw) return "";
    if (raw.includes(".")) return raw;
    return `${raw}.ceye.io`;
  })();

  return (
    <main className="mx-auto flex w-full max-w-3xl flex-1 flex-col gap-6 px-6 py-8">
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">设置</h1>
        <p className="text-sm text-muted-foreground">
          配置 CEYE DNSLog（Token 与 Identifier 子域名），保存后写入项目{" "}
          <code>.env</code>，立即作用于识别探测。
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
    </main>
  );
}
