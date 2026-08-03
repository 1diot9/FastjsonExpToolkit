"use client";

import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import type { EchoEngine, MemShellConfig } from "@/lib/api";

export type Preset1247Mode =
  | "auto"
  | "custom"
  | "touch"
  | "exec"
  | "echo"
  | "memshell";
export type RcePresetMode =
  | "file"
  | "custom"
  | "exec"
  | "echo"
  | "memshell";

export type MemShellState = {
  api: string;
  server: string;
  tool: string;
  type: string;
  path: string;
  jdk: string;
};

type EchoOptionsProps = {
  engine: EchoEngine;
  setEngine: (v: EchoEngine) => void;
  cmd: string;
  setCmd: (v: string) => void;
  cmdHeader: string;
  setCmdHeader: (v: string) => void;
  engines: readonly EchoEngine[];
};

export function EchoOptions(props: EchoOptionsProps) {
  const { engine, setEngine, cmd, setCmd, cmdHeader, setCmdHeader, engines } =
    props;
  return (
    <div className="grid gap-4 sm:grid-cols-3">
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
            {engines.map((e) => (
              <SelectItem key={e} value={e}>
                {e}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="grid gap-2">
        <Label htmlFor="echo-cmd">默认命令</Label>
        <Input
          id="echo-cmd"
          value={cmd}
          onChange={(e) => setCmd(e.target.value)}
          placeholder="id"
        />
      </div>
      <div className="grid gap-2">
        <Label htmlFor="echo-header">命令请求头</Label>
        <Input
          id="echo-header"
          value={cmdHeader}
          onChange={(e) => setCmdHeader(e.target.value)}
          placeholder="X-Cmd"
        />
      </div>
    </div>
  );
}

type MemShellOptionsProps = {
  value: MemShellState;
  onChange: (v: MemShellState) => void;
  config: MemShellConfig | null;
  servers: string[];
  tools: string[];
  types: string[];
  jdkOptions: string[];
};

export function MemShellOptions(props: MemShellOptionsProps) {
  const { value, onChange, servers, tools, types, jdkOptions } = props;
  const set = (patch: Partial<MemShellState>) =>
    onChange({ ...value, ...patch });
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      <div className="grid gap-2">
        <Label>中间件</Label>
        <Select value={value.server} onValueChange={(v) => set({ server: v })}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {servers.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="grid gap-2">
        <Label>工具</Label>
        <Select value={value.tool} onValueChange={(v) => set({ tool: v })}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {tools.map((t) => (
              <SelectItem key={t} value={t}>
                {t}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="grid gap-2">
        <Label>马类型</Label>
        <Select value={value.type} onValueChange={(v) => set({ type: v })}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {types.map((t) => (
              <SelectItem key={t} value={t}>
                {t}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="grid gap-2">
        <Label htmlFor="ms-path">urlPattern</Label>
        <Input
          id="ms-path"
          value={value.path}
          onChange={(e) => set({ path: e.target.value })}
        />
      </div>
      <div className="grid gap-2">
        <Label>目标 JDK</Label>
        <Select value={value.jdk} onValueChange={(v) => set({ jdk: v })}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {jdkOptions.map((j) => (
              <SelectItem key={j} value={j}>
                {j}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="grid gap-2">
        <Label htmlFor="ms-api">Backend</Label>
        <Input
          id="ms-api"
          value={value.api}
          onChange={(e) => set({ api: e.target.value })}
          placeholder="jar"
        />
      </div>
    </div>
  );
}

type CustomBytecodeFieldsProps = {
  classB64: string;
  setClassB64: (v: string) => void;
  bcelCode?: string;
  setBcelCode?: (v: string) => void;
  serializedB64?: string;
  setSerializedB64?: (v: string) => void;
  showBcel?: boolean;
  showSerialized?: boolean;
};

export function CustomBytecodeFields(props: CustomBytecodeFieldsProps) {
  const {
    classB64,
    setClassB64,
    bcelCode,
    setBcelCode,
    serializedB64,
    setSerializedB64,
    showBcel = true,
    showSerialized = false,
  } = props;
  return (
    <div className="grid gap-4">
      <div className="grid gap-2">
        <Label htmlFor="custom-class-b64">自备 class_b64</Label>
        <Textarea
          id="custom-class-b64"
          className="min-h-20 font-mono text-xs"
          value={classB64}
          onChange={(e) => setClassB64(e.target.value)}
          placeholder="Base64(.class)"
        />
      </div>
      {showBcel && setBcelCode ? (
        <div className="grid gap-2">
          <Label htmlFor="custom-bcel">bcel_code（可空，可由 class 派生）</Label>
          <Textarea
            id="custom-bcel"
            className="min-h-16 font-mono text-xs"
            value={bcelCode || ""}
            onChange={(e) => setBcelCode(e.target.value)}
            placeholder="$$BCEL$$..."
          />
        </div>
      ) : null}
      {showSerialized && setSerializedB64 ? (
        <div className="grid gap-2">
          <Label htmlFor="custom-ser">serialized_b64（C3P0）</Label>
          <Textarea
            id="custom-ser"
            className="min-h-16 font-mono text-xs"
            value={serializedB64 || ""}
            onChange={(e) => setSerializedB64(e.target.value)}
          />
        </div>
      ) : null}
    </div>
  );
}

type BytecodePresetFields1247Props = {
  gadget: string;
  preset: Preset1247Mode;
  setPreset: (v: Preset1247Mode) => void;
  effectivePreset: Preset1247Mode;
  allowEchoMemshell: boolean;
  jdbcOnly?: boolean;
  cmd: string;
  setCmd: (v: string) => void;
  proofPath: string;
  setProofPath: (v: string) => void;
  proofContent: string;
  setProofContent: (v: string) => void;
  engine: EchoEngine;
  setEngine: (v: EchoEngine) => void;
  cmdHeader: string;
  setCmdHeader: (v: string) => void;
  engines: readonly EchoEngine[];
  ms: MemShellState;
  setMs: (v: MemShellState) => void;
  msConfig: MemShellConfig | null;
  msServers: string[];
  msTools: string[];
  msTypes: string[];
  msJdkOptions: string[];
  classB64: string;
  setClassB64: (v: string) => void;
  bcelCode: string;
  setBcelCode: (v: string) => void;
  serializedB64: string;
  setSerializedB64: (v: string) => void;
  showSerialized?: boolean;
};

export function BytecodePresetFields1247(props: BytecodePresetFields1247Props) {
  const p = props.effectivePreset;
  return (
    <div className="space-y-4 rounded-lg border border-border/60 p-3">
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="grid gap-2">
          <Label>预设字节码</Label>
          <Select
            value={props.effectivePreset}
            onValueChange={(v) => props.setPreset(v as Preset1247Mode)}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {props.jdbcOnly ? (
                <>
                  <SelectItem value="custom">custom（仅 JNDI / 自备）</SelectItem>
                  <SelectItem value="echo">
                    echo（生成回显类供托管）
                  </SelectItem>
                </>
              ) : (
                <>
                  <SelectItem value="auto">
                    auto（空字节码 → exec；已填 → custom）
                  </SelectItem>
                  <SelectItem value="custom">custom（自备字节码）</SelectItem>
                  <SelectItem value="exec">exec（自定义命令）</SelectItem>
                  <SelectItem value="touch">touch（写证明文件）</SelectItem>
                  {props.allowEchoMemshell ? (
                    <>
                      <SelectItem value="echo">echo（命令回显）</SelectItem>
                      <SelectItem value="memshell">
                        memshell（内存马）
                      </SelectItem>
                    </>
                  ) : null}
                </>
              )}
            </SelectContent>
          </Select>
        </div>
        {p === "exec" || p === "auto" ? (
          <div className="grid gap-2">
            <Label htmlFor="preset-cmd">执行命令</Label>
            <Input
              id="preset-cmd"
              value={props.cmd}
              onChange={(e) => props.setCmd(e.target.value)}
              placeholder="id"
            />
          </div>
        ) : null}
      </div>
      {p === "touch" || p === "exec" || p === "auto" ? (
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="proof-path">证明文件路径（可选）</Label>
            <Input
              id="proof-path"
              value={props.proofPath}
              onChange={(e) => props.setProofPath(e.target.value)}
              placeholder={`/tmp/fj1247_${props.gadget}`}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="proof-content">证明内容前缀（可选）</Label>
            <Input
              id="proof-content"
              value={props.proofContent}
              onChange={(e) => props.setProofContent(e.target.value)}
              placeholder={`FJ1247_${props.gadget.toUpperCase()}`}
            />
          </div>
        </div>
      ) : null}
      {p === "custom" ? (
        <CustomBytecodeFields
          classB64={props.classB64}
          setClassB64={props.setClassB64}
          bcelCode={props.bcelCode}
          setBcelCode={props.setBcelCode}
          serializedB64={props.serializedB64}
          setSerializedB64={props.setSerializedB64}
          showSerialized={props.showSerialized}
        />
      ) : null}
      {p === "echo" ? (
        <EchoOptions
          engine={props.engine}
          setEngine={props.setEngine}
          cmd={props.cmd}
          setCmd={props.setCmd}
          cmdHeader={props.cmdHeader}
          setCmdHeader={props.setCmdHeader}
          engines={props.engines}
        />
      ) : null}
      {p === "memshell" && props.allowEchoMemshell ? (
        <MemShellOptions
          value={props.ms}
          onChange={props.setMs}
          config={props.msConfig}
          servers={props.msServers}
          tools={props.msTools}
          types={props.msTypes}
          jdkOptions={props.msJdkOptions}
        />
      ) : null}
      <p className="text-xs text-muted-foreground">
        custom / touch / exec / echo / memshell
        均为预设字节码；生成走 bytecode-gen / echo-gen / memshell-gen。
      </p>
    </div>
  );
}

type BytecodePresetFieldsRceProps = {
  preset: RcePresetMode;
  setPreset: (v: RcePresetMode) => void;
  cmd: string;
  setCmd: (v: string) => void;
  engine: EchoEngine;
  setEngine: (v: EchoEngine) => void;
  cmdHeader: string;
  setCmdHeader: (v: string) => void;
  engines: readonly EchoEngine[];
  ms: MemShellState;
  setMs: (v: MemShellState) => void;
  msConfig: MemShellConfig | null;
  msServers: string[];
  msTools: string[];
  msTypes: string[];
  msJdkOptions: string[];
  classB64: string;
  setClassB64: (v: string) => void;
};

export function BytecodePresetFieldsRce(props: BytecodePresetFieldsRceProps) {
  return (
    <div className="space-y-4 rounded-lg border border-border/60 p-3">
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="grid gap-2">
          <Label>RCE 预设</Label>
          <Select
            value={props.preset}
            onValueChange={(v) => props.setPreset(v as RcePresetMode)}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="file">file（写证明文件）</SelectItem>
              <SelectItem value="custom">custom（自备字节码）</SelectItem>
              <SelectItem value="exec">exec（执行命令）</SelectItem>
              <SelectItem value="echo">echo（命令回显）</SelectItem>
              <SelectItem value="memshell">memshell（内存马）</SelectItem>
            </SelectContent>
          </Select>
        </div>
        {props.preset === "exec" ? (
          <div className="grid gap-2">
            <Label htmlFor="rce-cmd">执行命令</Label>
            <Input
              id="rce-cmd"
              value={props.cmd}
              onChange={(e) => props.setCmd(e.target.value)}
              placeholder="id"
            />
          </div>
        ) : null}
      </div>
      {props.preset === "custom" ? (
        <CustomBytecodeFields
          classB64={props.classB64}
          setClassB64={props.setClassB64}
          showBcel={false}
        />
      ) : null}
      {props.preset === "echo" ? (
        <EchoOptions
          engine={props.engine}
          setEngine={props.setEngine}
          cmd={props.cmd}
          setCmd={props.setCmd}
          cmdHeader={props.cmdHeader}
          setCmdHeader={props.setCmdHeader}
          engines={props.engines}
        />
      ) : null}
      {props.preset === "memshell" ? (
        <MemShellOptions
          value={props.ms}
          onChange={props.setMs}
          config={props.msConfig}
          servers={props.msServers}
          tools={props.msTools}
          types={props.msTypes}
          jdkOptions={props.msJdkOptions}
        />
      ) : null}
    </div>
  );
}
