export type LibraryGuess =
  | "fastjson"
  | "jackson"
  | "gson"
  | "org.json"
  | "hutool"
  | "unknown";

export type Evidence = {
  probe_id: string;
  category: string;
  description: string;
  matched: string[];
  score_delta: number;
  library_hint: string | null;
  status_code: number;
  elapsed_ms: number;
  response_excerpt: string;
  payload: string;
};

export type DetectResult = {
  target: string;
  is_fastjson: boolean;
  confidence: number;
  autotype_disabled_hint: boolean | null;
  primary_guess: LibraryGuess;
  scores: Record<string, number>;
  evidence: Evidence[];
  dns_timing_suspicious: boolean | null;
  dns_confirmed: boolean | null;
  dns_filter: string | null;
  dns_records: Array<{
    name?: string;
    remote_addr?: string;
    created_at?: string;
  }>;
  baseline_ms: number | null;
  dns_probe_ms: number | null;
  summary: string;
  next_actions: string[];
  raw: Record<string, unknown>;
};

export type DetectRequest = {
  target: string;
  include_dns?: boolean;
  use_ceye?: boolean;
  dnslog?: string | null;
  ceye_wait?: number;
  timeout?: number;
  insecure?: boolean;
};

export type HealthResponse = {
  status: string;
  version: string;
  ceye_configured: boolean;
  ceye_domain: string | null;
};

export type SettingsResponse = {
  ceye_token_set: boolean;
  ceye_token_masked: string;
  ceye_identifier: string;
  ceye_domain: string;
  env_path: string;
};

export type SettingsUpdateRequest = {
  ceye_token?: string | null;
  ceye_identifier: string;
};

export type SettingsUpdateResponse = {
  ok: boolean;
  message: string;
  settings: SettingsResponse;
};

export type CeyeTestResponse = {
  ok: boolean;
  domain: string;
  record_count: number;
  message: string;
};

/** Same-origin proxy first; fall back to direct backend for local dev. */
const API_CANDIDATES = [
  process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "") ?? "",
  "http://127.0.0.1:8000",
  "http://localhost:8000",
].filter((v, i, arr) => arr.indexOf(v) === i);

async function readError(res: Response): Promise<string> {
  try {
    const data = await res.json();
    if (typeof data?.detail === "string") return data.detail;
    return JSON.stringify(data);
  } catch {
    return res.statusText || `HTTP ${res.status}`;
  }
}

async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const suffix = path.startsWith("/") ? path : `/${path}`;
  let lastError: unknown;

  for (const base of API_CANDIDATES) {
    const url = `${base}${suffix}`;
    try {
      const res = await fetch(url, {
        ...init,
        cache: "no-store",
      });
      // Rewrite miss can return Next HTML 404 — treat as retryable.
      const ct = res.headers.get("content-type") || "";
      if (res.status === 404 && !ct.includes("application/json")) {
        lastError = new Error(`API 404 at ${url || suffix}`);
        continue;
      }
      return res;
    } catch (err) {
      lastError = err;
    }
  }

  throw lastError instanceof Error
    ? lastError
    : new Error("无法连接后端 API（已尝试代理与 127.0.0.1:8000）");
}

export async function fetchHealth(): Promise<HealthResponse> {
  const res = await apiFetch("/api/health");
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export async function detectFastjson(body: DetectRequest): Promise<DetectResult> {
  const res = await apiFetch("/api/detect", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export type VersionEvidence = {
  probe_id: string;
  category: string;
  description: string;
  payload: string;
  status_code: number;
  elapsed_ms: number;
  errored: boolean | null;
  matched: string[];
  response_excerpt: string;
  interpretation: string;
};

export type VersionResult = {
  target: string;
  autotype_enabled: boolean | null;
  safemode_enabled: boolean | null;
  reported_version: string | null;
  reported_version_note: string | null;
  is_1_2_83_hint: boolean | null;
  version_range: string | null;
  confidence: number;
  methods_used: string[];
  evidence: VersionEvidence[];
  dns_filter: string | null;
  dns_records: Array<{
    name?: string;
    remote_addr?: string;
    created_at?: string;
  }>;
  dns_hits: Record<string, boolean>;
  summary: string;
  next_actions: string[];
  raw: Record<string, unknown>;
};

export type VersionRequest = {
  target: string;
  include_dns?: boolean;
  use_ceye?: boolean;
  dnslog?: string | null;
  ceye_wait?: number;
  timeout?: number;
  insecure?: boolean;
};

export async function detectVersion(body: VersionRequest): Promise<VersionResult> {
  const res = await apiFetch("/api/version", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export type DepStatus = "present" | "absent" | "unknown" | "error";
export type DepMethod = "character" | "dns";

export type DepHit = {
  clazz: string;
  description: string;
  category: string;
  status: DepStatus;
  method: DepMethod;
  matched: string[];
  status_code: number;
  elapsed_ms: number;
  response_excerpt: string;
  payload: string;
  dns_filter: string | null;
  dns_hit: boolean | null;
  error: string | null;
};

export type DepsResult = {
  target: string;
  method: DepMethod;
  scanned: number;
  present_count: number;
  absent_count: number;
  unknown_count: number;
  error_count: number;
  present: DepHit[];
  results: DepHit[];
  dns_filter: string | null;
  dns_records: Array<{
    name?: string;
    remote_addr?: string;
    created_at?: string;
  }>;
  summary: string;
  next_actions: string[];
  notes: string[];
  raw: Record<string, unknown>;
};

export type DepsRequest = {
  target: string;
  method?: DepMethod;
  classes?: string[];
  categories?: string[];
  use_ceye?: boolean;
  dnslog?: string | null;
  ceye_wait?: number;
  timeout?: number;
  concurrency?: number;
  insecure?: boolean;
};

export type DepCatalogEntry = {
  class: string;
  description: string;
  category: string;
};

export async function detectDeps(body: DepsRequest): Promise<DepsResult> {
  const res = await apiFetch("/api/deps", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export async function fetchDepsCatalog(): Promise<DepCatalogEntry[]> {
  const res = await apiFetch("/api/deps/catalog");
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export type ExpectEvidence = {
  probe_id: string;
  category: string;
  description: string;
  payload: string;
  status_code: number;
  elapsed_ms: number;
  errored: boolean | null;
  matched: string[];
  response_excerpt: string;
  interpretation: string;
};

export type ExpectClassResult = {
  target: string;
  has_expect_class: boolean | null;
  expect_not_map: boolean | null;
  version_lt_1_2_68_hint: boolean | null;
  confidence: number;
  base_body: string;
  methods_used: string[];
  evidence: ExpectEvidence[];
  summary: string;
  next_actions: string[];
  notes: string[];
  raw: Record<string, unknown>;
};

export type ExpectClassRequest = {
  target: string;
  base_body?: string | null;
  timeout?: number;
  insecure?: boolean;
};

export async function detectExpectClass(
  body: ExpectClassRequest,
): Promise<ExpectClassResult> {
  const res = await apiFetch("/api/expect", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export async function fetchSettings(): Promise<SettingsResponse> {
  const res = await apiFetch("/api/settings");
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export async function updateSettings(
  body: SettingsUpdateRequest,
): Promise<SettingsUpdateResponse> {
  const res = await apiFetch("/api/settings", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export async function testCeye(): Promise<CeyeTestResponse> {
  const res = await apiFetch("/api/settings/ceye-test", {
    method: "POST",
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export type EchoEngine =
  | "auto"
  | "spring"
  | "undertow"
  | "tomcat"
  | "jetty"
  | "weblogic"
  | "websphere"
  | "resin"
  | "struts2"
  | "httpserver"
  | "dfs";

export const ECHO_ENGINES: { id: EchoEngine; label: string }[] = [
  { id: "auto", label: "auto" },
  { id: "spring", label: "spring" },
  { id: "undertow", label: "undertow" },
  { id: "tomcat", label: "tomcat" },
  { id: "jetty", label: "jetty" },
  { id: "weblogic", label: "weblogic" },
  { id: "websphere", label: "websphere" },
  { id: "resin", label: "resin" },
  { id: "struts2", label: "struts2" },
  { id: "httpserver", label: "httpserver" },
  { id: "dfs", label: "dfs" },
];

export type Poc16723Request = {
  target: string;
  mode?: "http" | "fd";
  host?: string;
  port?: number;
  cmd?: string;
  echo?: boolean;
  engine?: EchoEngine;
  json_path?: string;
  docker_container?: string;
  reuse_type?: string | null;
  memshell?: boolean;
  ms_api?: string;
  ms_server?: string;
  ms_tool?: string;
  ms_type?: string;
  ms_path?: string;
  ms_jdk?: string;
};

export type Poc16723Result = {
  ok: boolean;
  exit_code: number;
  cve: string;
  mode: string;
  target: string;
  summary: string;
  logs: string[];
  notes: string[];
  raw: Record<string, unknown>;
};

export type MemShellFieldsValue = {
  memshell: boolean;
  ms_api: string;
  ms_server: string;
  ms_tool: string;
  ms_type: string;
  ms_path: string;
  ms_jdk: string;
};

export type MemShellConfig = Record<string, Record<string, string[]>>;

export async function fetchMemshellConfig(
  backend = "jar",
): Promise<MemShellConfig> {
  const q = new URLSearchParams({ backend });
  const res = await apiFetch(`/api/memshell/config?${q}`);
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export type MemShellGenerateRequest = {
  backend?: string;
  server?: string;
  tool?: string;
  shell_type?: string;
  path?: string;
  jdk?: string;
  static_initialize?: boolean;
};

export type MemShellGenerateResult = {
  ok: boolean;
  memshell_info: Record<string, unknown>;
  memshell_connect: string;
  injector_b64: string;
  injector_class: string;
  shell_class: string;
};

export async function generateMemshell(
  body: MemShellGenerateRequest,
): Promise<MemShellGenerateResult> {
  const res = await apiFetch("/api/memshell/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export async function runPoc16723(
  body: Poc16723Request,
): Promise<Poc16723Result> {
  const res = await apiFetch("/api/poc/cve-2026-16723", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export type WafOptions = {
  encode_keys?: boolean;
  encode_values?: boolean;
  encode_targets?: string[];
  key_targets?: string[];
  include_type_key?: boolean;
  use_single_quote?: boolean;
  comma_count?: number;
  pad_size?: number;
  pad_char?: string;
  pad_key?: string;
};

export type Poc1247Gadget = {
  id: string;
  title: string;
  description: string;
  requires: string[];
  jdk: string;
  input_fields: string[];
  references: string[];
};

export type Poc1247Request = {
  gadget: string;
  jndi_url?: string | null;
  bcel_code?: string | null;
  class_b64?: string | null;
  user_overrides?: string | null;
  serialized_b64?: string | null;
  h2_url?: string | null;
  getter_trigger?: string;
  currency_field?: string;
  json_key_with_type?: boolean;
  json_key_as_array?: boolean;
  preset?: "auto" | "custom" | "off" | "touch" | "exec" | "echo" | "memshell";
  proof_path?: string | null;
  proof_content?: string | null;
  echo?: boolean;
  engine?: EchoEngine;
  cmd?: string;
  cmd_header?: string;
  memshell?: boolean;
  ms_api?: string;
  ms_server?: string;
  ms_tool?: string;
  ms_type?: string;
  ms_path?: string;
  ms_jdk?: string;
  waf_techniques?: string[];
  waf_options?: WafOptions;
  target?: string;
  send?: boolean;
};

export type Poc1247Result = {
  ok: boolean;
  gadget: string;
  title: string;
  payload: string;
  payload_raw?: string | null;
  getter_trigger?: string;
  waf_techniques?: string[];
  sent: boolean;
  status_code: number | null;
  response_preview: string;
  summary: string;
  notes: string[];
  requires: string[];
  jdk: string;
  echo?: boolean;
  engine?: string;
  cmd_header?: string;
  preset?: string;
  class_b64?: string | null;
  bcel_code?: string | null;
  echo_output?: string | null;
  memshell?: boolean;
  memshell_info?: Record<string, unknown> | null;
  memshell_connect?: string | null;
};

export async function listPoc1247Gadgets(): Promise<Poc1247Gadget[]> {
  const res = await apiFetch("/api/poc/1.2.47/gadgets");
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export async function runPoc1247(
  body: Poc1247Request,
): Promise<Poc1247Result> {
  const res = await apiFetch("/api/poc/1.2.47", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export type Poc1268Gadget = Poc1247Gadget & { hidden?: boolean };

export type Poc1268Request = {
  gadget: string;
  file?: string | null;
  content?: string | null;
  source?: string | null;
  url?: string | null;
  guess_byte?: number | null;
  bom_bytes?: number[] | null;
  read_length?: number | null;
  read_charset?: string | null;
  read_charset_bytes?: number[] | null;
  host?: string | null;
  port?: number | null;
  user?: string | null;
  jdbc_url?: string | null;
  socket_factory_arg?: string | null;
  wrap_currency?: boolean;
  currency_field?: string;
  preset?: "file" | "custom" | "exec" | "echo" | "memshell";
  class_b64?: string;
  echo?: boolean;
  engine?: EchoEngine;
  cmd?: string;
  cmd_header?: string;
  attack_base?: string | null;
  memshell?: boolean;
  ms_api?: string;
  ms_server?: string;
  ms_tool?: string;
  ms_type?: string;
  ms_path?: string;
  ms_jdk?: string;
  waf_techniques?: string[];
  waf_options?: WafOptions;
  target?: string;
  send?: boolean;
};

export type Poc1268Result = Poc1247Result & {
  wrap_currency?: boolean;
  attack_jar_b64?: string | null;
  attack_xml_b64?: string | null;
  read_bytes?: number[] | null;
  read_content?: string | null;
};

export async function listPoc1268Gadgets(): Promise<Poc1268Gadget[]> {
  const res = await apiFetch("/api/poc/1.2.68/gadgets");
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export async function runPoc1268(
  body: Poc1268Request,
): Promise<Poc1268Result> {
  const res = await apiFetch("/api/poc/1.2.68", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export type Poc1280Gadget = Poc1247Gadget & { steps?: number };

export type Poc1280Request = {
  gadget: string;
  file?: string | null;
  content?: string | null;
  url?: string | null;
  guess_byte?: number | null;
  host?: string | null;
  port?: number | null;
  user?: string | null;
  socket_factory_arg?: string | null;
  classpath?: string | null;
  wrap_currency?: boolean;
  currency_field?: string;
  preset?: "file" | "custom" | "exec" | "echo" | "memshell";
  class_b64?: string;
  echo?: boolean;
  engine?: EchoEngine;
  cmd?: string;
  cmd_header?: string;
  attack_base?: string | null;
  memshell?: boolean;
  ms_api?: string;
  ms_server?: string;
  ms_tool?: string;
  ms_type?: string;
  ms_path?: string;
  ms_jdk?: string;
  waf_techniques?: string[];
  waf_options?: WafOptions;
  target?: string;
  send?: boolean;
  reset_cache?: boolean;
};

export type Poc1280Result = Poc1247Result & {
  steps?: string[];
  steps_raw?: string[];
  wrap_currency?: boolean;
  status_codes?: number[];
  response_previews?: string[];
  attack_jar_b64?: string | null;
  attack_xml_b64?: string | null;
};

export async function listPoc1280Gadgets(): Promise<Poc1280Gadget[]> {
  const res = await apiFetch("/api/poc/1.2.80/gadgets");
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export async function runPoc1280(
  body: Poc1280Request,
): Promise<Poc1280Result> {
  const res = await apiFetch("/api/poc/1.2.80", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export type WafTechnique = {
  id: string;
  title: string;
  description: string;
  notes: string[];
};

export type WafVariant = {
  technique: string;
  title: string;
  payload: string;
  description: string;
};

export type WafRequest = {
  payload: string;
  techniques?: string[];
  mode?: "stack" | "variants";
  options?: WafOptions;
};

export type WafResult = {
  original: string;
  payload: string;
  techniques: string[];
  variants: WafVariant[];
  notes: string[];
  summary: string;
};

export async function listWafTechniques(): Promise<WafTechnique[]> {
  const res = await apiFetch("/api/waf/techniques");
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export async function runWaf(body: WafRequest): Promise<WafResult> {
  const res = await apiFetch("/api/waf", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export type DockerEnvironment = {
  ready: boolean;
  docker_installed: boolean;
  docker_running: boolean;
  compose_available: boolean;
  compose_backend: string | null;
  docker_version: string | null;
  compose_version: string | null;
  engine_info: string | null;
  errors: string[];
};

export type PortCheck = {
  port: number;
  host: string;
  occupied: boolean;
  owned_by_lab: boolean;
  detail: string;
};

export type LabState = "running" | "partial" | "stopped" | "unknown";

export type LabPortInfo = {
  key: string;
  label: string;
  default: number;
  value: number;
  editable: boolean;
};

export type LabStatus = {
  id: string;
  name: string;
  description: string;
  category: string;
  compose_rel: string;
  services: string[];
  ports: number[];
  default_ports: number[];
  port_infos: LabPortInfo[];
  container_names: string[];
  endpoints: string[];
  notes: string;
  state: LabState;
  containers_running: Record<string, boolean | null>;
  port_checks: PortCheck[];
  can_start: boolean;
  can_stop: boolean;
  blockers: string[];
  warnings: string[];
};

export type LabListResponse = {
  docker: DockerEnvironment;
  labs: LabStatus[];
};

export type LabActionResult = {
  ok: boolean;
  lab_id: string;
  action: string;
  message: string;
  state: LabState | null;
  logs: string[];
  port_checks: PortCheck[];
  docker: DockerEnvironment | null;
  status: LabStatus | null;
  ports: Record<string, number>;
};

export async function fetchLabDocker(): Promise<DockerEnvironment> {
  const res = await apiFetch("/api/lab/docker");
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export async function fetchLabs(): Promise<LabListResponse> {
  const res = await apiFetch("/api/lab");
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export async function startLab(
  labId: string,
  body?: {
    build?: boolean;
    timeout?: number;
    ports?: Record<string, number>;
  },
): Promise<LabActionResult> {
  const res = await apiFetch(`/api/lab/${encodeURIComponent(labId)}/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? { build: true }),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}

export async function stopLab(
  labId: string,
  body?: { remove?: boolean; timeout?: number },
): Promise<LabActionResult> {
  const res = await apiFetch(`/api/lab/${encodeURIComponent(labId)}/stop`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? { remove: true }),
  });
  if (!res.ok) throw new Error(await readError(res));
  return res.json();
}
