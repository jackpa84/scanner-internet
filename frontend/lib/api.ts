const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5001";

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
  setToken(data.token);
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

async function apiFetch<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    cache: "no-store",
    headers: { ...authHeaders() },
  });
  if (res.status === 401) {
    clearToken();
    if (typeof window !== "undefined") window.location.href = "/";
    throw new Error("Sessao expirada");
  }
  if (!res.ok) throw new Error(`API ${path}: ${res.status}`);
  return res.json();
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
