import { demoAnalyses, demoFindings, demoRuns } from "../data/demo";
import type {
  CapabilityScore,
  CreateRepositoryAnalysisInput,
  RepositoryAnalysis,
  RepositoryDetailResult,
  RepositoryListResult,
  CollectionResult,
  FindingRecord,
  RunRecord,
  SystemHealth,
} from "../types";

const API_ROOT = (import.meta.env.VITE_API_ROOT || "/v1").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export class ApiContractError extends ApiError {
  readonly code = "API_CONTRACT_INVALID";

  constructor(detail: string) {
    super(`API_CONTRACT_INVALID: ${detail}`);
    this.name = "ApiContractError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function contractString(
  record: Record<string, unknown>,
  keys: string[],
  field: string,
): string {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim()) return value;
  }
  throw new ApiContractError(`repository analysis ${field} is missing or invalid`);
}

function contractRecords(value: unknown, field: string): Record<string, unknown>[] {
  if (!Array.isArray(value) || value.some((item) => !isRecord(item))) {
    throw new ApiContractError(`repository analysis ${field} must be an array of objects`);
  }
  return value;
}

function apiErrorMessage(body: unknown, fallback: string): string {
  if (!body || typeof body !== "object") return fallback;
  const record = body as Record<string, unknown>;
  if (typeof record.message === "string" && record.message.trim()) return record.message;
  if (typeof record.detail === "string" && record.detail.trim()) return record.detail;
  if (!Array.isArray(record.detail)) return fallback;

  const messages = record.detail.flatMap((item) => {
    if (!item || typeof item !== "object") return [];
    const issue = item as Record<string, unknown>;
    if (typeof issue.msg !== "string" || !issue.msg.trim()) return [];
    const field = Array.isArray(issue.loc)
      ? issue.loc.filter((part) => part !== "body").map(String).at(-1)
      : undefined;
    const message = issue.msg.replace(/^Value error,\s*/i, "");
    return [field ? `${field.replaceAll("_", " ")}: ${message}` : message];
  });
  return messages.length ? messages.join("; ") : fallback;
}

async function request(path: string, init?: RequestInit): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(`${API_ROOT}${path}`, {
      ...init,
      credentials: "include",
      headers: {
        Accept: "application/json",
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
        ...init?.headers,
      },
    });
  } catch (error) {
    throw new ApiError(error instanceof Error ? error.message : "Control API is unavailable");
  }

  if (!response.ok) {
    let message = `Control API returned ${response.status}`;
    try {
      message = apiErrorMessage(await response.json(), message);
    } catch {
      // The status code remains the useful error when the body is not JSON.
    }
    throw new ApiError(message, response.status);
  }

  if (response.status === 204) return null;
  return response.json();
}

function numberValue(value: unknown, fallback = 0): number {
  if (typeof value === "number" && Number.isFinite(value)) return Math.max(0, Math.min(100, value));
  if (typeof value === "string") {
    const parsed = Number.parseFloat(value);
    if (Number.isFinite(parsed)) return Math.max(0, Math.min(100, parsed));
  }
  return fallback;
}

function countValue(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? Math.floor(value)
    : fallback;
}

function capability(value: unknown, fallbackLabel: string): CapabilityScore {
  if (typeof value === "number" || typeof value === "string") {
    const score = numberValue(value);
    return { score, label: `${score}%` };
  }
  const record = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  const score = numberValue(record.score ?? record.percent ?? record.value);
  return {
    score,
    label: typeof record.label === "string" ? record.label : fallbackLabel,
    detail: typeof record.detail === "string" ? record.detail : undefined,
  };
}

function list<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

export function normalizeAnalysis(value: unknown): RepositoryAnalysis {
  if (!isRecord(value)) {
    throw new ApiContractError("repository analysis payload must be an object");
  }
  const raw = value;
  const capabilities = isRecord(raw.capabilities)
    ? raw.capabilities
    : (() => {
        throw new ApiContractError("repository analysis capabilities are missing or invalid");
      })();
  const repository = isRecord(raw.repository) ? raw.repository : {};
  const id = contractString(raw, ["id", "analysis_id"], "id");
  const repositoryUrl =
    typeof raw.repository_url === "string" && raw.repository_url.trim()
      ? raw.repository_url
      : contractString(repository, ["url"], "repository_url");
  const commit =
    typeof raw.commit === "string" && raw.commit.trim()
      ? raw.commit
      : contractString(repository, ["commit"], "commit");
  if (!/^[0-9a-f]{40}$/i.test(commit)) {
    throw new ApiContractError("repository analysis commit must be a full 40-character SHA");
  }
  const createdAt = contractString(raw, ["created_at"], "created_at");
  if (Number.isNaN(Date.parse(createdAt))) {
    throw new ApiContractError("repository analysis created_at must be a valid timestamp");
  }
  const name = contractString(raw, ["name"], "name");
  const status = contractString(raw, ["status"], "status");
  for (const field of ["understanding", "runtime", "coverage"] as const) {
    if (!(field in capabilities)) {
      throw new ApiContractError(`repository analysis capability ${field} is missing`);
    }
  }
  const components = contractRecords(raw.components, "components");
  const diagnostics = contractRecords(raw.diagnostics, "diagnostics");
  const agentTasks = contractRecords(raw.agent_tasks, "agent_tasks");
  const claims = contractRecords(raw.claims, "claims");
  const provenance = contractRecords(raw.provenance ?? [], "provenance");
  const snapshotDigest = raw.snapshot_digest;
  if (
    snapshotDigest !== undefined &&
    snapshotDigest !== null &&
    (typeof snapshotDigest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(snapshotDigest))
  ) {
    throw new ApiContractError("repository analysis snapshot_digest is invalid");
  }

  return {
    id,
    name,
    status: status.toLowerCase(),
    repository_url: repositoryUrl,
    commit: commit.toLowerCase(),
    snapshot_digest: typeof snapshotDigest === "string" ? snapshotDigest : null,
    created_at: createdAt,
    updated_at: typeof raw.updated_at === "string" ? raw.updated_at : undefined,
    capabilities: {
      understanding: capability(capabilities.understanding, "Pending"),
      runtime: capability(capabilities.runtime, "Locked"),
      coverage: capability(capabilities.coverage, "0%"),
    },
    components: components.map((item, index) => ({
      id: String(item.id ?? `component-${index}`),
      name: String(item.name ?? "Unnamed component"),
      kind: String(item.kind ?? item.type ?? "Unknown"),
      path: String(item.path ?? "—"),
      language: item.language ? String(item.language) : undefined,
      exposure: item.exposure ? String(item.exposure) : undefined,
      confidence: typeof item.confidence === "number" ? item.confidence : undefined,
    })),
    diagnostics: diagnostics.map((item, index) => ({
      id: String(item.id ?? `diagnostic-${index}`),
      severity: String(item.severity ?? "info"),
      message: String(item.message ?? item.detail ?? "Analysis diagnostic"),
      path: item.path ? String(item.path) : undefined,
    })),
    agent_tasks: agentTasks.map((item, index) => ({
      id: String(item.id ?? `task-${index}`),
      title: String(item.title ?? item.name ?? "Agent task"),
      agent: String(item.agent ?? item.agent_name ?? "Repository analyst"),
      status: String(item.status ?? "pending").toLowerCase(),
      depends_on: list<unknown>(item.depends_on).map(String),
      output: item.output ? String(item.output) : undefined,
      next_actions: list<unknown>(item.next_actions).map(String),
      duration_ms: typeof item.duration_ms === "number" ? item.duration_ms : undefined,
    })),
    claims: claims.map((item, index) => ({
      id: String(item.id ?? `claim-${index}`),
      subject: String(item.subject ?? "Unknown subject"),
      predicate: String(item.predicate ?? "relates to"),
      value: String(item.value ?? item.object ?? "Unknown value"),
      confidence: typeof item.confidence === "number" ? item.confidence : 0,
      source_refs: list<unknown>(item.source_refs).map(String),
      status: String(item.status ?? "unverified").toLowerCase(),
    })),
    provenance: provenance.map((item) => ({
      claim_id: String(item.claim_id ?? ""),
      snapshot_id: String(item.snapshot_id ?? ""),
      repository_url: String(item.repository_url ?? ""),
      commit: String(item.commit ?? ""),
      producer_role: String(item.producer_role ?? ""),
      producer_run_id: String(item.producer_run_id ?? ""),
      tool_name: String(item.tool_name ?? ""),
      tool_version: String(item.tool_version ?? ""),
      sources: contractRecords(item.sources ?? [], "provenance sources").map((source) => ({
        ref_id: String(source.ref_id ?? ""),
        artifact_id: String(source.artifact_id ?? ""),
        sha256: String(source.sha256 ?? ""),
        path: source.path ? String(source.path) : undefined,
        start_line: typeof source.start_line === "number" ? source.start_line : undefined,
        end_line: typeof source.end_line === "number" ? source.end_line : undefined,
      })),
    })),
    component_total: countValue(raw.component_total, components.length),
    diagnostic_total: countValue(raw.diagnostic_total, diagnostics.length),
    claim_total: countValue(raw.claim_total, claims.length),
    conflict_total: countValue(
      raw.conflict_total,
      claims.filter((claim) => claim.status === "conflicted").length,
    ),
    error_code: typeof raw.error_code === "string" ? raw.error_code : undefined,
    error_message: typeof raw.error_message === "string" ? raw.error_message : undefined,
  };
}

function canUseDemo(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    !(error instanceof ApiContractError) &&
    (error.status === undefined || [404, 501, 502, 503, 504].includes(error.status))
  );
}

export async function getRepositoryAnalyses(
  limit = 20,
  offset = 0,
): Promise<RepositoryListResult> {
  try {
    const body = await request(`/repository-analyses?limit=${limit}&offset=${offset}`);
    const raw = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
    const items = Array.isArray(body) ? body : list<unknown>(raw.items);
    return {
      items: items.map(normalizeAnalysis),
      total: typeof raw.total === "number" ? raw.total : items.length,
      source: "api",
    };
  } catch (error) {
    if (!canUseDemo(error)) throw error;
    return { items: demoAnalyses, total: demoAnalyses.length, source: "demo" };
  }
}

export async function getRepositoryAnalysis(id: string): Promise<RepositoryDetailResult> {
  if (id.startsWith("demo-")) {
    const demo = demoAnalyses.find((item) => item.id === id);
    if (!demo) throw new ApiError("Demo repository was not found", 404);
    return { item: demo, source: "demo" };
  }

  try {
    return { item: normalizeAnalysis(await request(`/repository-analyses/${encodeURIComponent(id)}`)), source: "api" };
  } catch (error) {
    if (!canUseDemo(error)) throw error;
    const demo = demoAnalyses.find((item) => item.id === id);
    if (demo) return { item: demo, source: "demo" };
    throw error;
  }
}

export async function createRepositoryAnalysis(
  input: CreateRepositoryAnalysisInput,
): Promise<RepositoryAnalysis> {
  const body = await request("/repository-analyses", {
    method: "POST",
    body: JSON.stringify(input),
  });
  return normalizeAnalysis(body);
}

export async function createSession(token: string): Promise<void> {
  await request("/session", {
    method: "POST",
    body: JSON.stringify({ token }),
  });
}

export async function deleteSession(): Promise<void> {
  await request("/session", { method: "DELETE" });
}

export async function getRuns(): Promise<CollectionResult<RunRecord>> {
  try {
    const body = await request("/runs");
    const raw = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
    const items = Array.isArray(body) ? body : list<Record<string, unknown>>(raw.items);
    return {
      source: "api",
      items: items.map((item, index) => ({
        id: String(item.id ?? `run-${index}`),
        repository: String(item.repository ?? item.repository_name ?? item.engagement_id ?? "Unknown repository"),
        stage: String(item.stage ?? item.status ?? "Queued"),
        status: String(item.status ?? "queued").toLowerCase(),
        started_at: String(item.started_at ?? item.created_at ?? "—"),
        elapsed: String(item.elapsed ?? item.duration ?? "—"),
        policy: String(item.policy ?? item.policy_decision ?? "default-deny"),
      })),
    };
  } catch (error) {
    if (!canUseDemo(error)) throw error;
    return { items: demoRuns, source: "demo" };
  }
}

export async function getFindings(): Promise<CollectionResult<FindingRecord>> {
  try {
    const body = await request("/findings");
    const raw = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
    const items = Array.isArray(body) ? body : list<Record<string, unknown>>(raw.items);
    return {
      source: "api",
      items: items.map((item, index) => {
        const invariant =
          item.invariant && typeof item.invariant === "object"
            ? (item.invariant as Record<string, unknown>)
            : {};
        return {
          id: String(item.id ?? `finding-${index}`),
          title: String(item.title ?? "Untitled finding"),
          repository: String(item.repository ?? item.repository_name ?? item.engagement_id ?? "Unknown repository"),
          status: String(item.status ?? "hypothesis").toLowerCase(),
          confidence: numberValue(item.confidence, 0),
          evidence: Array.isArray(item.evidence_ids) ? item.evidence_ids.length : numberValue(item.evidence, 0),
          invariant: String(invariant.expression ?? item.invariant_expression ?? "Invariant awaiting extraction"),
        };
      }),
    };
  } catch (error) {
    if (!canUseDemo(error)) throw error;
    return { items: demoFindings, source: "demo" };
  }
}

export async function getSystemHealth(): Promise<SystemHealth> {
  try {
    const response = await fetch("/health", {
      credentials: "include",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) throw new ApiError(`Health endpoint returned ${response.status}`, response.status);
    const body = (await response.json()) as Record<string, unknown>;
    return {
      status: String(body.status ?? "ok"),
      version: String(body.version ?? "unknown"),
      database: String(body.database ?? "connected"),
      model_gateway: String(body.model_gateway ?? "not reported"),
      runner: String(body.runner ?? "not reported"),
      policy: String(body.policy ?? "default-deny"),
    };
  } catch {
    return {
      status: "demo",
      version: "0.1.0",
      database: "not connected",
      model_gateway: "local / unverified",
      runner: "static-only",
      policy: "default-deny",
    };
  }
}
