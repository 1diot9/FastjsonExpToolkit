import type { DockerEnvironment, LabListResponse, LabStatus } from "@/lib/api";
import { fetchLabs } from "@/lib/api";

type LabCache = {
  docker: DockerEnvironment;
  labs: LabStatus[];
  fetchedAt: number;
  error: string | null;
};

/** Survives client-side navigations away from /lab within the same tab. */
let memory: LabCache | null = null;
let inflight: Promise<LabCache> | null = null;

export function getLabCache(): LabCache | null {
  return memory;
}

export function setLabCache(
  docker: DockerEnvironment,
  labs: LabStatus[],
  error: string | null = null,
): LabCache {
  memory = { docker, labs, fetchedAt: Date.now(), error };
  return memory;
}

export function clearLabCache(): void {
  memory = null;
}

export async function loadLabs(options?: {
  force?: boolean;
}): Promise<LabCache> {
  const force = options?.force ?? false;
  if (!force && memory) {
    return memory;
  }
  if (!force && inflight) {
    return inflight;
  }

  inflight = (async () => {
    try {
      const data: LabListResponse = await fetchLabs();
      return setLabCache(data.docker, data.labs, null);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (memory) {
        // Keep last good snapshot; surface error separately.
        memory = { ...memory, error: message };
        return memory;
      }
      throw err;
    } finally {
      inflight = null;
    }
  })();

  return inflight;
}

export function updateLabInCache(lab: LabStatus): void {
  if (!memory) return;
  memory = {
    ...memory,
    labs: memory.labs.map((item) => (item.id === lab.id ? lab : item)),
    fetchedAt: Date.now(),
    error: null,
  };
}

export function patchCacheFromAction(payload: {
  docker?: DockerEnvironment | null;
  status?: LabStatus | null;
}): void {
  if (!memory) return;
  let labs = memory.labs;
  if (payload.status) {
    labs = labs.map((item) =>
      item.id === payload.status!.id ? payload.status! : item,
    );
  }
  memory = {
    docker: payload.docker ?? memory.docker,
    labs,
    fetchedAt: Date.now(),
    error: null,
  };
}
