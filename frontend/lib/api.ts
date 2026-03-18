// Se NEXT_PUBLIC_API_URL estiver vazio ou não definido, usamos "" para que o browser
// faça requisições à mesma origem; o Next.js faz rewrite de /api/* para o backend.
const API_BASE =
  typeof process.env.NEXT_PUBLIC_API_URL === "string" && process.env.NEXT_PUBLIC_API_URL.trim() !== ""
    ? process.env.NEXT_PUBLIC_API_URL.replace(/\/$/, "")
    : "";

const TOKEN_KEY = "scanner_auth_token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

export function isAuthenticated(): boolean {
  return !!getToken();
}

export async function login(username: string, password: string): Promise<{ token: string; username: string }> {
  const res = await fetch(`${API_BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
    cache: "no-store",
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Login falhou");
  }
  const data = await res.json();
  const token = data?.token;
  if (!token || typeof token !== "string") {
    throw new Error("Resposta invalida do servidor (sem token)");
  }
  setToken(token);
  return data;
}

export function logout(): void {
  clearToken();
  window.location.href = "/";
}

function authHeaders(): Record<string, string> {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function apiFetch<T>(path: string, timeoutMs = 15000): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(`Timeout ${timeoutMs}ms: ${path}`), timeoutMs);
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      cache: "no-store",
      headers: { ...authHeaders() },
      signal: controller.signal,
    });
    if (res.status === 401) {
      clearToken();
      if (typeof window !== "undefined") window.dispatchEvent(new Event("auth:unauthorized"));
      throw new Error("Sessao expirada");
    }
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      const detail = body ? (() => { try { return JSON.parse(body).detail; } catch { return body.slice(0, 200); } })() : "";
      throw new Error(`API ${path}: ${res.status}${detail ? ` – ${detail}` : ""}`);
    }
    return res.json();
  } catch (e: unknown) {
    if (e instanceof DOMException && e.name === "AbortError") {
      throw new Error(`Timeout ao chamar ${path} (${Math.round(timeoutMs / 1000)}s)`);
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

const API_POST = async <T>(path: string, body: Record<string, unknown>): Promise<T> => {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  if (res.status === 401) {
    clearToken();
    if (typeof window !== "undefined") window.location.href = "/";
    throw new Error("Sessao expirada");
  }
  if (!res.ok) throw new Error(`API POST ${path}: ${res.status}`);
  return res.json();
};

// ---------------------------------------------------------------------------
// Health / Circuit Breakers
// ---------------------------------------------------------------------------
export interface ApiBreakerStatus {
  name: string;
  blocked: boolean;
  cooldown: number;
  remaining_seconds: number;
  blocked_since: string;
}

export interface ScanStats {
  tested: number;
  alive: number;
  saved: number;
  dead: number;
}

export interface HealthInfo {
  workers: number;
  scan_interval: number;
  network_scanner_enabled: boolean;
  apis: ApiBreakerStatus[];
  blocked_count: number;
  scan_stats: ScanStats;
}

export const fetchHealth = () => apiFetch<HealthInfo>("/api/health");

// ---------------------------------------------------------------------------
// System Metrics
// ---------------------------------------------------------------------------
export interface SystemMetrics {
  cpu_percent: number;
  memory_percent: number;
  memory_used_mb: number;
  memory_total_mb: number;
  net_in_bytes_sec: number;
  net_out_bytes_sec: number;
  net_total_recv_mb: number;
  net_total_sent_mb: number;
}

export const fetchSystemMetrics = () => apiFetch<SystemMetrics>("/api/system/metrics");

// ---------------------------------------------------------------------------
// DB Activity Log
// ---------------------------------------------------------------------------
export interface DbActivityEntry {
  collection: string;
  action: string;
  summary: string;
  ip: string;
  risk_level: string;
  country: string;
  timestamp: string;
}

export interface DbActivity {
  activity: DbActivityEntry[];
  counts: Record<string, number>;
  error?: string;
}

export const fetchDbActivity = (limit = 30) =>
  apiFetch<DbActivity>(`/api/db/activity?limit=${limit}`);

// ---------------------------------------------------------------------------
// Vuln Scanner (used by VulnPanel)
// ---------------------------------------------------------------------------
export interface VulnResult {
  id: string;
  ip: string;
  scan_result_id?: string;
  tool: "nuclei" | "nmap";
  template_id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  matched_at: string;
  proof: string;
  references: string[];
  port?: number;
  tags: string[];
  timestamp: string;
}

export interface TopVuln {
  template_id: string;
  name: string;
  severity: string;
  count: number;
}

export interface VulnScannerStats {
  queued: number;
  scanning: number;
  completed: number;
  vulns_found: number;
  nuclei_runs: number;
  nmap_runs: number;
  errors: number;
  queue_size: number;
}

export interface VulnStats {
  total_vulns: number;
  unique_ips_scanned: number;
  by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  by_tool: Record<string, number>;
  top_vulns: TopVuln[];
  scanner: VulnScannerStats;
}

export const fetchVulnResults = (limit = 50, severity?: string) => {
  let path = `/api/vulns/results?limit=${limit}`;
  if (severity) path += `&severity=${severity}`;
  return apiFetch<VulnResult[]>(path);
};
export const fetchVulnStats = () => apiFetch<VulnStats>("/api/vulns/stats");
export const fetchVulnsByIp = (ip: string) => apiFetch<VulnResult[]>(`/api/vulns/ip/${ip}`);
export const triggerVulnScan = (ip: string) =>
  API_POST<{ queued: boolean; ip: string }>("/api/vulns/scan", { ip });
export const triggerBatchVulnScan = (minScore = 70) =>
  API_POST<{ queued: number; min_score: number }>("/api/vulns/scan", { min_score: minScore });

// ---------------------------------------------------------------------------
// Bounty
// ---------------------------------------------------------------------------
export interface BountyProgram {
  id: string;
  name: string;
  platform: string;
  url: string;
  in_scope: string[];
  out_of_scope: string[];
  status: string;
  created_at?: string;
  last_recon?: string;
  last_recon_error?: string;
  first_recon_at?: string;
  policy_url?: string;
  has_bounty?: boolean;
  bounty_min?: number;
  bounty_max?: number;
  bounty_currency?: string;
  asset_types?: string[];
  notes?: string;
  priority?: string;
  safe_harbor?: boolean;
  stats?: {
    subdomains?: number;
    resolved?: number;
    alive?: number;
    asns_discovered?: number;
    org_prefixes?: number;
    new_subdomains?: number;
  };
  target_count?: number;
  alive_count?: number;
  vuln_count?: number;
  flow_step?: number;
}

export interface BountyTarget {
  id: string;
  program_id: string;
  domain: string;
  ips: string[];
  alive: boolean;
  status: string;
  httpx?: {
    url?: string;
    status_code?: number;
    title?: string;
    tech?: string[];
    cdn?: boolean;
    webserver?: string;
  };
  http_scanner?: Array<{
    port?: number | string;
    service?: string;
    scheme?: string;
    status_code?: number;
    title?: string;
    banner?: string;
    [key: string]: unknown;
  }>;
  recon_checks?: {
    checked?: boolean;
    risk_score?: number;
    high?: number;
    medium?: number;
    low?: number;
    total_findings?: number;
    findings?: Array<{
      severity: string;
      code: string;
      title: string;
      evidence?: string;
    }>;
  };
  wayback_urls?: string[];
  paramspider?: {
    params?: string[];
    urls_with_params?: string[];
  };
  is_new?: boolean;
  last_recon?: string;
}

export interface BountyReconStats {
  recons_completed: number;
  subdomains_found: number;
  hosts_alive: number;
  errors: number;
  crtsh_subdomains: number;
  asns_discovered: number;
  rdns_subdomains: number;
  new_subdomains_detected: number;
}

export interface BountyStats {
  programs: number;
  programs_with_bounty: number;
  targets: number;
  alive_targets: number;
  new_targets: number;
  total_changes: number;
  bounty_prefixes: number;
  recon: BountyReconStats;
}

export interface BountyChange {
  id: string;
  program_id: string;
  program_name: string;
  timestamp: string;
  new_subdomains: string[];
  removed_subdomains: string[];
  total_current: number;
  total_previous: number;
}

export interface BountyScopeSuggestion {
  source: string;
  handle?: string;
  in_scope: string[];
  out_of_scope: string[];
}

export interface BountyProgramFlowStep {
  n: number;
  label: string;
  done: boolean;
}
export interface BountyProgramFlow {
  steps: BountyProgramFlowStep[];
  current_step: number;
}

export const fetchBountyPrograms = () => apiFetch<BountyProgram[]>("/api/bounty/programs");
export const fetchBountyTargets = (programId: string, aliveOnly = false) =>
  apiFetch<BountyTarget[]>(`/api/bounty/targets/${programId}?alive_only=${aliveOnly}`);
export const fetchBountyStats = () => apiFetch<BountyStats>("/api/bounty/stats");
export const fetchProgramFlow = (programId: string) =>
  apiFetch<BountyProgramFlow>(`/api/bounty/programs/${programId}/flow`);

export const createBountyProgram = (data: {
  name: string;
  platform: string;
  url: string;
  in_scope: string[];
  out_of_scope: string[];
  policy_url?: string;
  has_bounty?: boolean;
  bounty_min?: number | null;
  bounty_max?: number | null;
  bounty_currency?: string;
  asset_types?: string[];
  notes?: string;
  priority?: string;
  safe_harbor?: boolean;
}) => API_POST<{ id: string; created?: boolean; updated?: boolean }>("/api/bounty/programs", data);

export const suggestBountyScope = (data: { url: string; platform: string }) =>
  API_POST<BountyScopeSuggestion>("/api/bounty/scope_suggest", data);

export const triggerBountyRecon = (programId: string) =>
  API_POST<{ status: string }>(`/api/bounty/programs/${programId}/recon`, {});

export const clearBountyProgramError = (programId: string) =>
  API_POST<{ ok: boolean; status: string }>(`/api/bounty/programs/${programId}/clear_error`, {});

export const syncBugScraperPrograms = () =>
  API_POST<{ inserted: number }>("/api/bounty/bugscraper/sync", {});

export const submitBountyToHackerOne = (
  programId: string,
  body?: { title?: string; vulnerability_information?: string; impact?: string; severity_rating?: string }
) =>
  API_POST<{ ok: boolean; report_id?: number; url?: string }>(
    `/api/bounty/programs/${programId}/submit_hackerone`,
    body ?? {}
  );

/** Parâmetros de paginação para listagens HackerOne (reports, earnings, programs). */
export type HackerOnePageParams = {
  page_size?: number;
  page_before?: string;
  page_after?: string;
};

/** Resposta JSON:API da HackerOne (data + links com next/prev). */
export type HackerOneListResponse = {
  data?: unknown[];
  links?: { next?: string; prev?: string; first?: string; last?: string };
};

function buildQuery(params: HackerOnePageParams): string {
  const q = new URLSearchParams();
  if (params.page_size != null) q.set("page_size", String(params.page_size));
  if (params.page_before) q.set("page_before", params.page_before);
  if (params.page_after) q.set("page_after", params.page_after);
  const s = q.toString();
  return s ? `?${s}` : "";
}

/** Lista reports (submissões) do hacker na HackerOne. Requer credenciais no backend. */
export const fetchHackerOneReports = (params: HackerOnePageParams = {}) =>
  apiFetch<HackerOneListResponse>(`/api/hackerone/reports${buildQuery(params)}`, 20000);

/** Lista earnings (bounties recebidos) do hacker na HackerOne. */
export const fetchHackerOneEarnings = (params: HackerOnePageParams = {}) =>
  apiFetch<HackerOneListResponse>(`/api/hackerone/earnings${buildQuery(params)}`, 20000);

/** Lista programas HackerOne disponíveis para o hacker. */
export const fetchHackerOnePrograms = (params: HackerOnePageParams = {}) =>
  apiFetch<HackerOneListResponse>(`/api/hackerone/programs${buildQuery(params)}`);

export const triggerBountyTargetScan = (targetId: string) =>
  API_POST<{ queued: boolean; domain: string }>(`/api/bounty/targets/${targetId}/scan`, {});

export const deleteBountyProgram = async (programId: string): Promise<{ deleted: boolean }> => {
  const res = await fetch(`${API_BASE}/api/bounty/programs/${programId}`, {
    headers: { ...authHeaders() },
    method: "DELETE",
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`DELETE program: ${res.status}`);
  return res.json();
};

export const deleteAllBountyPrograms = async (): Promise<{ deleted_programs: number; deleted_targets: number }> => {
  const res = await fetch(`${API_BASE}/api/bounty/programs`, {
    headers: { ...authHeaders() },
    method: "DELETE",
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`DELETE all programs: ${res.status}`);
  return res.json();
};

export const fetchBountyReport = async (programId: string): Promise<string> => {
  const res = await fetch(`${API_BASE}/api/bounty/report/${programId}`, {
    cache: "no-store",
    headers: { ...authHeaders() },
  });
  if (!res.ok) throw new Error(`Report: ${res.status}`);
  return res.text();
};

export const fetchBountyChanges = (programId: string, limit = 20) =>
  apiFetch<BountyChange[]>(`/api/bounty/programs/${programId}/changes?limit=${limit}`);

export const fetchRecentChanges = (limit = 50) =>
  apiFetch<BountyChange[]>(`/api/bounty/changes/recent?limit=${limit}`);

export const fetchNewTargets = (limit = 100) =>
  apiFetch<BountyTarget[]>(`/api/bounty/targets/new?limit=${limit}`);

// ---------------------------------------------------------------------------
// Submitted Reports (auto-submit to HackerOne)
// ---------------------------------------------------------------------------

export interface SubmittedReport {
  id: string;
  program_id: string;
  program_name: string;
  target_id: string;
  domain: string;
  severity: string;
  findings_count: number;
  title: string;
  timestamp: string;
  status: "submitted" | "error" | "pending";
  h1_report_id?: string | number | null;
  h1_report_url?: string | null;
  error?: string | null;
  report_body?: string;
}

export interface SubmittedReportsStats {
  total: number;
  submitted: number;
  errors: number;
  pending: number;
  by_severity: Record<string, number>;
}

export const fetchSubmittedReports = (limit = 50) =>
  apiFetch<SubmittedReport[]>(`/api/bounty/submitted-reports?limit=${limit}`);

export const fetchSubmittedReportsStats = () =>
  apiFetch<SubmittedReportsStats>("/api/bounty/submitted-reports/stats");

export const submitTargetToH1 = (targetId: string) =>
  API_POST<{ ok: boolean; status: string; h1_report_url?: string; error?: string }>(
    `/api/bounty/targets/${targetId}/submit-h1`,
    {}
  );

// ---------------------------------------------------------------------------
// Program Scorer
// ---------------------------------------------------------------------------

export interface PrioritizedProgram {
  program_id: string;
  name: string;
  score: number;
  tier: string;
  recommendation: string;
  has_bounty: boolean;
  bounty_max: number | null;
  alive_targets: number;
}

export const scoreAllPrograms = () =>
  API_POST<{ scored: number; programs: PrioritizedProgram[] }>("/api/bounty/score-programs", {});

export const fetchPrioritizedPrograms = (minScore = 40) =>
  apiFetch<PrioritizedProgram[]>(`/api/bounty/prioritized-programs?min_score=${minScore}`);

export const discoverH1Programs = () =>
  API_POST<{ new_programs_found: number; auto_imported: number; imported: any[] }>("/api/bounty/h1-discover", {});

// ---------------------------------------------------------------------------
// Bounty Program Search (bounty-targets-data)
// ---------------------------------------------------------------------------

export interface BountySearchParams {
  q?: string;
  platform?: string;
  bounty_only?: boolean;
  limit?: number;
  asset_type?: string;
  min_scope?: number;
  has_wildcards?: boolean;
  sort_by?: "newest" | "name" | "scope_size" | "bounty_changed";
  scope_changed?: boolean;
}

export interface BountySearchProgram {
  id: string;
  name: string;
  handle?: string;
  platform: string;
  url: string;
  in_scope: string[];
  out_of_scope: string[];
  has_bounty: boolean;
  bounty_min?: number | null;
  bounty_max?: number | null;
  asset_types: string[];
  scope_count: number;
  wildcard_count: number;
  scope_preview: string[];
  scope_changed?: boolean;
  scope_change_detected?: string;
  created_at?: string;
  last_data_sync?: string;
}

export interface BountySearchResponse {
  results: BountySearchProgram[];
  total: number;
  summary: {
    platforms: Record<string, number>;
    with_bounty: number;
    with_wildcards: number;
  };
}

export const searchBountyPrograms = (params: BountySearchParams = {}) => {
  const sp = new URLSearchParams();
  if (params.q) sp.set("q", params.q);
  if (params.platform) sp.set("platform", params.platform);
  if (params.bounty_only) sp.set("bounty_only", "true");
  if (params.limit) sp.set("limit", String(params.limit));
  if (params.asset_type) sp.set("asset_type", params.asset_type);
  if (params.min_scope) sp.set("min_scope", String(params.min_scope));
  if (params.has_wildcards) sp.set("has_wildcards", "true");
  if (params.sort_by) sp.set("sort_by", params.sort_by);
  if (params.scope_changed) sp.set("scope_changed", "true");
  return apiFetch<BountySearchResponse>(`/api/bounty-data/search?${sp.toString()}`);
};

export const fetchBountyDataStats = () =>
  apiFetch<{
    last_fetch: string | null;
    programs_fetched: number;
    programs_imported: number;
    programs_updated: number;
    domains_total: number;
    wildcards_total: number;
    errors: number;
    by_platform: Record<string, number>;
  }>("/api/bounty-data/stats");

// ---------------------------------------------------------------------------
// Advanced Scanner Stats
// ---------------------------------------------------------------------------

export interface ScannerStats {
  idor: Record<string, number>;
  ssrf: Record<string, number>;
  graphql: Record<string, number>;
  race_condition: Record<string, number>;
  interactsh: Record<string, number>;
  ct_monitor: Record<string, number>;
  cve_monitor: Record<string, number>;
  scorer: Record<string, any>;
  ai: Record<string, any>;
}

export const fetchScannerStats = () =>
  apiFetch<ScannerStats>("/api/scanners/stats");

// ---------------------------------------------------------------------------
// Blind Vulns (Interactsh)
// ---------------------------------------------------------------------------

export const fetchBlindVulns = () =>
  apiFetch<any[]>("/api/blind-vulns");

// ---------------------------------------------------------------------------
// CT Monitor
// ---------------------------------------------------------------------------

export const triggerCTCheck = () =>
  API_POST<{ programs_checked: number; new_domains_found: number }>("/api/ct/check-all", {});

export const fetchCTStats = () =>
  apiFetch<Record<string, any>>("/api/ct/stats");

// ---------------------------------------------------------------------------
// CVE Monitor
// ---------------------------------------------------------------------------

export const triggerCVECheck = () =>
  API_POST<{ total_cves: number; web_cves: number; templates_created: number }>("/api/cve/check", {});

export const fetchRecentCVEs = () =>
  apiFetch<any[]>("/api/cve/recent");

export const fetchCVEStats = () =>
  apiFetch<Record<string, any>>("/api/cve/stats");

// ---------------------------------------------------------------------------
// ROI Tracker
// ---------------------------------------------------------------------------

export interface ROIDashboard {
  summary: {
    total_earnings: number;
    total_reports_paid: number;
    avg_payout: number;
    highest_payout: number;
  };
  operations: {
    total_programs: number;
    active_programs: number;
    total_targets: number;
    alive_targets: number;
    reports_submitted: number;
    reports_accepted: number;
    reports_failed: number;
    acceptance_rate: number;
  };
  top_programs: {
    name: string;
    earned: number;
    reports: number;
    hourly_rate: number;
    efficiency: string;
  }[];
  most_profitable_vulns: {
    type: string;
    earnings: number;
    count: number;
    avg_payout: number;
  }[];
  monthly_trend: Record<string, { earnings: number; count: number }>;
  recommendations: string[];
  generated_at: string;
}

export const fetchROIDashboard = () =>
  apiFetch<ROIDashboard>("/api/roi/dashboard");

export const fetchEarningsSummary = () =>
  apiFetch<any>("/api/roi/earnings");

export const recordEarning = (data: {
  program_id: string;
  program_name: string;
  amount: number;
  currency?: string;
  vuln_type?: string;
}) => API_POST<{ ok: boolean }>("/api/roi/record-earning", data);

// ---------------------------------------------------------------------------
// Enhanced Report Generation
// ---------------------------------------------------------------------------

export const generateTargetReport = (targetId: string) =>
  API_POST<{
    title: string;
    body?: string;
    vulnerability_information?: string;
    severity: string;
    severity_rating?: string;
    impact: string;
    confidence?: number;
    auto_submit_eligible?: boolean;
    source: "ai" | "template";
    ai_provider?: string;
  }>(`/api/bounty/targets/${targetId}/generate-report`, {});

// ---------------------------------------------------------------------------
// AI Analyzer
// ---------------------------------------------------------------------------

export interface AIStats {
  provider: string;
  model: string;
  enabled: boolean;
  requests: number;
  tokens_used: number;
  errors: number;
  reports_generated: number;
  findings_classified: number;
  responses_analyzed: number;
}

export const fetchAIStats = () =>
  apiFetch<AIStats>("/api/ai/stats");

export interface AIHistoryEntry {
  id: number;
  type: string;
  ts: string;
  status: "success" | "error" | "partial";
  input: string;
  result: Record<string, unknown> | null;
  duration_ms: number;
  model: string;
}

export const fetchAIHistory = (limit = 50) =>
  apiFetch<{ history: AIHistoryEntry[] }>(`/api/ai/history?limit=${limit}`);

export const aiClassifyFinding = (finding: Record<string, unknown>) =>
  API_POST<{
    classification: "true_positive" | "false_positive";
    real_severity: string;
    worth_reporting: boolean;
    confidence: number;
    reasoning: string;
    suggested_title?: string;
  }>("/api/ai/classify-finding", { finding });

export const aiClassifyTarget = (targetId: string) =>
  API_POST<{
    original: number;
    filtered: number;
    removed: number;
    findings: any[];
  }>(`/api/ai/classify-target/${targetId}`, {});

export const aiAnalyzeResponse = (data: { url: string; status_code: number; headers: Record<string, string>; body: string }) =>
  API_POST<{ findings: any[] }>("/api/ai/analyze-response", data);

export const aiParseScope = (data: { description: string; policy?: string }) =>
  API_POST<{
    in_scope: string[];
    out_of_scope: string[];
    priority_vulns: string[];
    restrictions: string[];
    bounty_range: { min: number; max: number; currency: string };
    tips: string[];
  }>("/api/ai/parse-scope", data);

export const aiAnalyzeJS = (data: { code: string; source_url?: string }) =>
  API_POST<{ findings: any[] }>("/api/ai/analyze-js", data);

export const aiFindChains = (targetId: string) =>
  API_POST<{
    chains: { chain_name: string; severity: string; steps: string[]; impact: string; findings_used: string[] }[];
    findings_analyzed: number;
  }>(`/api/ai/find-chains/${targetId}`, {});

// ---------------------------------------------------------------------------
// Intigriti Researcher API
// ---------------------------------------------------------------------------

export const fetchIntigrtiMe = () =>
  apiFetch<{ configured: boolean; ok: boolean; programs_accessible?: number; detail?: string }>("/api/intigriti/me");

export const fetchIntigrtiPrograms = () =>
  apiFetch<any>("/api/intigriti/programs", 20000);

export const fetchIntigrtiActivities = () =>
  apiFetch<any>("/api/intigriti/activities", 20000);

export const importIntigrtiPrograms = () =>
  API_POST<{ imported: number; updated: number; total_programs: number }>("/api/intigriti/import", {});

// ---------------------------------------------------------------------------
// AI Recon Analysis
// ---------------------------------------------------------------------------

export interface AiReport {
  executive_summary: string;
  overall_risk: "critical" | "high" | "medium" | "low";
  total_targets: number;
  total_findings: number;
  critical_assets: string[];
  top_attack_strategies: string[];
  severity_breakdown: Record<string, number>;
  recommended_next_steps: string[];
  generated_at: string;
  targets_analyzed: number;
}

export interface PrioritizedTarget {
  domain: string;
  rank: number | null;
  attack_angle: string;
  reasoning: string;
  risk_score: number;
  finding_count: number;
  chain_count: number;
}

export interface TargetAiAnalysis {
  target_id: string;
  domain: string;
  ai_priority: {
    rank: number;
    attack_angle: string;
    reasoning: string;
    key_findings: string[];
  } | null;
  ai_vuln_chains: {
    chain_name: string;
    severity: string;
    steps: string[];
    impact: string;
    findings_used: string[];
  }[];
  enriched_findings: {
    code: string;
    title: string;
    severity: string;
    ai_impact: string;
    ai_guidance: string;
  }[];
  total_findings: number;
  ai_findings_analyzed: boolean;
}

export const fetchProgramAiAnalysis = (programId: string) =>
  apiFetch<{
    program_id: string;
    program_name: string;
    ai_report: AiReport | null;
    prioritized_targets: PrioritizedTarget[];
    ai_ready: boolean;
  }>(`/api/bounty/programs/${programId}/ai-analysis`);

export const fetchRankedTargets = (programId: string, limit = 20) =>
  apiFetch<any[]>(`/api/bounty/programs/${programId}/ranked-targets?limit=${limit}`);

export const fetchTargetAiAnalysis = (targetId: string) =>
  apiFetch<TargetAiAnalysis>(`/api/bounty/targets/${targetId}/ai-analysis`);

export const triggerProgramAiAnalysis = (programId: string) =>
  API_POST<{ status: string }>(`/api/bounty/programs/${programId}/ai-analyze`, {});

// ---------------------------------------------------------------------------
// Activity Logs (terminal live feed)
// ---------------------------------------------------------------------------
export interface ActivityLogEntry {
  ts: string;
  level: string;
  msg: string;
  tag: string;
}

export interface ActivityLogsResponse {
  logs: ActivityLogEntry[];
  total_buffered: number;
}

export const fetchActivityLogs = (limit = 80, after?: string) => {
  let path = `/api/activity/logs?limit=${limit}`;
  if (after) path += `&after=${encodeURIComponent(after)}`;
  return apiFetch<ActivityLogsResponse>(path);
};

// ---------------------------------------------------------------------------
// Platform Watcher (multi-platform scraping)
// ---------------------------------------------------------------------------

export interface WatcherPlatformInfo {
  name: string;
  configured: boolean;
  enabled: boolean;
}

export interface WatcherStats {
  last_check: string | null;
  total_checks: number;
  programs_found: Record<string, number>;
  new_programs: number;
  scope_changes: number;
  errors: number;
  running: boolean;
}

export interface WatcherStatusResponse {
  stats: WatcherStats;
  platforms: WatcherPlatformInfo[];
  available_scrapers: string[];
}

export interface WatcherCheckResult {
  status: string;
  programs?: number;
  new?: number;
  scope_changed?: number;
  removed?: number;
  imported?: number;
  updated?: number;
  elapsed_seconds?: number;
  error?: string;
  reason?: string;
}

export interface WatcherCheckResponse {
  results: Record<string, WatcherCheckResult>;
}

export const fetchWatcherStatus = () =>
  apiFetch<WatcherStatusResponse>('/api/watcher/status');

export const triggerWatcherCheck = (body?: {
  platforms?: string[];
  bounty_only?: boolean;
  keywords?: string[];
  min_bounty?: number;
}) =>
  API_POST<WatcherCheckResponse>('/api/watcher/check', body || {});

export const triggerWatcherCheckSingle = (platform: string) =>
  API_POST<WatcherCheckResponse>(`/api/watcher/check/${platform}`, {});

export const fetchWatcherPrograms = (platform?: string) => {
  const path = platform
    ? `/api/watcher/programs/${platform}?limit=200`
    : '/api/watcher/programs';
  return apiFetch<{
    platform?: string;
    platforms?: Record<string, number>;
    count?: number;
    total?: number;
    programs?: Array<Record<string, unknown>>;
  }>(path);
};

// ═══════════════════════════════════════════════════════════════
// BugHunt — dedicated endpoints
// ═══════════════════════════════════════════════════════════════

export interface BugHuntStatus {
  configured: boolean;
  email_set: boolean;
  password_set: boolean;
  capsolver_set: boolean;
  programs_cached: number;
  programs_found_total: number;
  last_check: string | null;
  last_error: string | null;
  status: string;
}

export interface BugHuntTestResult {
  ok: boolean;
  error?: string;
  message?: string;
  programs_count?: number;
}

export interface BugHuntScrapeResult {
  ok: boolean;
  fetched: number;
  new: number;
  error?: string | null;
  programs: BugHuntProgram[];
}

export interface BugHuntProgram {
  name: string;
  url: string;
  platform: string;
  program_id: string;
  scope: string[];
  reward_type: string;
  max_bounty: number;
  min_bounty?: number;
}

export const fetchBugHuntStatus = () =>
  apiFetch<BugHuntStatus>('/api/bughunt/status');

export const testBugHuntConnection = () =>
  API_POST<BugHuntTestResult>('/api/bughunt/test', {});

export const triggerBugHuntScrape = () =>
  API_POST<BugHuntScrapeResult>('/api/bughunt/scrape', {});

export const fetchBugHuntPrograms = (params?: { limit?: number; bounty_only?: boolean; search?: string }) => {
  const q = new URLSearchParams();
  if (params?.limit) q.set('limit', String(params.limit));
  if (params?.bounty_only) q.set('bounty_only', 'true');
  if (params?.search) q.set('search', params.search);
  const qs = q.toString();
  return apiFetch<{ count: number; programs: BugHuntProgram[] }>(`/api/bughunt/programs${qs ? `?${qs}` : ''}`);
};

// ── BugHunt AI Report Generator ─────────────────────────────

export interface BugHuntScopeAnalysis {
  ok: boolean;
  error?: string;
  analysis?: {
    programa: string;
    alvos_analisados: number;
    superficie_ataque: string;
    tipo_aplicacao: string;
    tecnologias_provaveis: string[];
    top_5_vulnerabilidades: Array<{ nome: string; severidade: string; justificativa: string }>;
    vetores_especificos: string[];
    subdominios_interessantes: Array<{ dominio?: string; motivo?: string } | string>;
    dicas_recompensa: string[];
    risco_geral: string;
    estimativa_horas: number;
  };
}

export interface BugHuntVulnSuggestions {
  ok: boolean;
  error?: string;
  suggestions?: {
    programa: string;
    quick_wins: Array<{ vulnerabilidade: string; onde_testar: string; ferramenta: string; tempo_estimado: string }>;
    bugs_comuns: Array<{ tipo: string; descricao: string; impacto: string; severidade: string }>;
    cadeias_avancadas: Array<{ cadeia: string; passos: string[]; impacto_final: string; severidade_resultante: string }>;
    checklist: string[];
    ferramentas_recomendadas: Array<{ nome: string; uso: string }>;
    estimativa_recompensa: { minima: number; media: number; maxima: number };
    prioridade_ataque: Array<{ alvo: string; motivo: string }>;
  };
}

export interface BugHuntReport {
  ok: boolean;
  error?: string;
  report?: {
    programa: string;
    tipo_vulnerabilidade: string;
    gerado_em: string;
    titulo: string;
    resumo_executivo: string;
    severidade: string;
    cvss_score?: number;
    cvss_vector?: string;
    passos_reproducao: string[];
    poc: string;
    impacto: string;
    remediacao: string[];
    referencias: string[];
    cwe?: string;
    owasp_category?: string;
    fallback?: boolean;
  };
}

export const bughuntAnalyzeScope = (programId: string) =>
  API_POST<BugHuntScopeAnalysis>('/api/bughunt/ai/analyze-scope', { program_id: programId });

export const bughuntSuggestVulns = (programId: string) =>
  API_POST<BugHuntVulnSuggestions>('/api/bughunt/ai/suggest-vulns', { program_id: programId });

export const bughuntGenerateReport = (programId: string, vulnType: string, details?: string) =>
  API_POST<BugHuntReport>('/api/bughunt/ai/generate-report', { program_id: programId, vuln_type: vulnType, details: details || '' });

// ---------------------------------------------------------------------------
// H1 Auto-Submit Pipeline
// ---------------------------------------------------------------------------

export interface H1Stats {
  total_submissions: number;
  successful: number;
  failed: number;
  h1_credentials_configured: boolean;
  auto_submit_enabled: boolean;
  auto_submit_config?: {
    enabled: boolean;
    interval_seconds: number;
    batch_size: number;
    dry_run: boolean;
  };
}

export interface H1AutoSubmitResult {
  status: string;
  reports_generated: number;
  processed_vulns: number;
  submitted: number;
  duplicates: number;
  errors: number;
  skipped: number;
  details: Array<{ report_id: string; status: string; reason?: string }>;
}

export interface H1QueueItem {
  id: string;
  ip: string;
  title: string;
  severity: string;
  vulnerability_count: number;
}

export const fetchH1Stats = () =>
  apiFetch<H1Stats>('/api/h1/stats');

export const fetchH1Queue = () =>
  apiFetch<{ count: number; reports: H1QueueItem[] }>('/api/h1/queue');

export const triggerH1AutoSubmit = (opts?: { limit?: number; dry_run?: boolean }) =>
  API_POST<H1AutoSubmitResult>('/api/h1/auto-submit-now', opts || {});

export const triggerH1BatchSubmit = (opts?: { limit?: number; auto_only?: boolean; dry_run?: boolean }) =>
  API_POST<H1AutoSubmitResult>('/api/h1/batch-submit', opts || {});

// Local reports management
export interface LocalReport {
  id: string;
  ip: string;
  title: string;
  severity: string;
  vulnerability_count: number;
  status: string;
  auto_submit_eligible: boolean;
  created_at: string | null;
}

export interface ReportStats {
  total: number;
  draft: number;
  submitted: number;
  by_severity: Record<string, number>;
}

export const fetchLocalReports = (limit = 100, status = "draft") =>
  apiFetch<{ count: number; reports: LocalReport[] }>(`/api/reports?limit=${limit}&status=${status}`);

export const fetchReportStats = () =>
  apiFetch<ReportStats>('/api/reports/stats');

export const generateReports = (opts?: { limit?: number; severity_threshold?: string }) =>
  API_POST<{ status: string; processed_vulns: number; reports_generated: number; errors: number }>('/api/reports/generate', opts || {});

export const fetchH1Me = () =>
  apiFetch<{ ok: boolean; username: string; programs: number }>('/api/hackerone/me', 30000);

// ── DB Stats ─────────────────────────────────────────────────────────────────

export interface RedisInfo {
  version: string;
  uptime_seconds: number;
  connected_clients: number;
  used_memory_human: string;
  used_memory_peak_human: string;
  maxmemory_human: string;
  mem_fragmentation_ratio: number;
  total_commands_processed: number;
  instantaneous_ops_per_sec: number;
  keyspace_hits: number;
  keyspace_misses: number;
  total_keys: number;
  error?: string;
}

export interface CollectionStat {
  name: string;
  count: number;
  max_docs: number | null;
  size_bytes: number;
  usage_pct: number | null;
  error?: string;
}

export interface MongoCollectionStat {
  name: string;
  count: number;
  size_bytes: number;
  storage_size_bytes: number;
  avg_obj_size: number;
  indexes: number;
}

export interface MongoStatus {
  connected: boolean;
  database?: string;
  collections?: MongoCollectionStat[];
  error?: string;
}

export interface DbStats {
  redis: RedisInfo;
  collections: CollectionStat[];
  mongo: MongoStatus;
}

export const fetchDbStats = () => apiFetch<DbStats>('/api/db/stats');
