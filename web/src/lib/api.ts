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
