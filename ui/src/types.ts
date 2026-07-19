export type DataSource = "api" | "demo";

export type RepositoryStatus =
  | "queued"
  | "fetching"
  | "analyzing"
  | "ready"
  | "needs_review"
  | "failed"
  | string;

export interface CapabilityScore {
  score: number;
  label: string;
  detail?: string;
}

export interface ComponentRecord {
  id: string;
  name: string;
  kind: string;
  path: string;
  language?: string;
  exposure?: string;
  confidence?: number;
}

export interface DiagnosticRecord {
  id: string;
  severity: "info" | "warning" | "error" | string;
  message: string;
  path?: string;
}

export interface AgentTask {
  id: string;
  title: string;
  agent: string;
  status: "pending" | "running" | "complete" | "blocked" | string;
  depends_on: string[];
  output?: string;
  /** What would unblock this task when it abstained, degraded, or failed. */
  next_actions: string[];
  duration_ms?: number;
}

export interface TwinClaim {
  id: string;
  subject: string;
  predicate: string;
  value: string;
  confidence: number;
  source_refs: string[];
  status: "supported" | "conflicted" | "unverified" | string;
}

export interface EvidenceSourceRecord {
  ref_id: string;
  artifact_id: string;
  sha256: string;
  path?: string;
  start_line?: number;
  end_line?: number;
}

export interface ProvenanceRecord {
  claim_id: string;
  snapshot_id: string;
  repository_url: string;
  commit: string;
  producer_role: string;
  producer_run_id: string;
  tool_name: string;
  tool_version: string;
  sources: EvidenceSourceRecord[];
}

export interface RepositoryAnalysis {
  id: string;
  name: string;
  status: RepositoryStatus;
  repository_url: string;
  commit: string;
  snapshot_digest?: string | null;
  created_at: string;
  updated_at?: string;
  capabilities: {
    understanding: CapabilityScore;
    runtime: CapabilityScore;
    coverage: CapabilityScore;
  };
  components: ComponentRecord[];
  diagnostics: DiagnosticRecord[];
  agent_tasks: AgentTask[];
  claims: TwinClaim[];
  provenance: ProvenanceRecord[];
  component_total: number;
  diagnostic_total: number;
  claim_total: number;
  conflict_total: number;
  error_code?: string;
  error_message?: string;
}

export interface RepositoryListResult {
  items: RepositoryAnalysis[];
  total: number;
  source: DataSource;
}

export interface RepositoryDetailResult {
  item: RepositoryAnalysis;
  source: DataSource;
}

export interface CreateRepositoryAnalysisInput {
  name?: string;
  repository_url: string;
  commit: string;
}

export interface RunRecord {
  id: string;
  repository: string;
  stage: string;
  status: string;
  started_at: string;
  elapsed: string;
  policy: string;
}

export interface FindingRecord {
  id: string;
  title: string;
  repository: string;
  status: string;
  confidence: number;
  evidence: number;
  invariant: string;
}

export interface CollectionResult<T> {
  items: T[];
  source: DataSource;
}

export interface SystemHealth {
  status: string;
  version: string;
  database: string;
  model_gateway: string;
  runner: string;
  policy: string;
}
