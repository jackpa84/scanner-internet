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
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      cache: "no-store",
      headers: { ...authHeaders() },
      signal: controller.signal,
    });
    if (res.status === 401) {
      clearToken();
      if (typeof window !== "undefined") window.location.href = "/";
      throw new Error("Sessao expirada");
    }
    if (!res.ok) throw new Error(`API ${path}: ${res.status}`);
    return res.json();
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
