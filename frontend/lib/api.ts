const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000";

export interface GeoInfo {
  city?: string;
  region?: string;
  country?: string;
  lat?: string;
  lon?: string;
  org?: string;
  timezone?: string;
  isp?: string;
  as?: string;
  mobile?: boolean;
  proxy?: boolean;
  hosting?: boolean;
}

export interface ThreatEntry {
  malware: string;
  malware_printable: string;
  threat_type: string;
  confidence: number;
  first_seen: string;
  tags: string[];
}

export interface ThreatIntel {
  known_threat: boolean;
  threats: ThreatEntry[];
}

export interface NetworkInfo {
  isp?: string;
  org?: string;
  as?: string;
  mobile?: boolean;
  proxy?: boolean;
  hosting?: boolean;
}

export interface RiskProfile {
  score: number;
  level: "low" | "medium" | "high";
  reasons: string[];
}

export interface ScanResult {
  id: string;
  ip: string;
  ports: number[];
  vulns: string[];
  hostnames: string[];
  rdns?: string;
  timestamp: string;
  router_count: number;
  router_info?: RouterInfo[];
  geo?: GeoInfo;
  network?: NetworkInfo;
  threat_intel?: ThreatIntel;
  risk?: RiskProfile;
}

export interface RouterInfo {
  port: number;
  service: string;
  banner?: string;
  title?: string;
  server?: string;
}

export interface CountryStat {
  country: string;
  count: number;
}

export interface Stats {
  total: number;
  with_ports: number;
  with_vulns: number;
  with_router_info: number;
  with_high_risk: number;
  with_geo: number;
  top_countries: CountryStat[];
}

async function apiFetch<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`API ${path}: ${res.status}`);
  return res.json();
}

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

export interface FeedStats {
  queue_size: number;
  hosting_cidrs: number;
  discovered_prefixes: number;
  dshield_ips: number;
  blocklist_ips: number;
  abuseipdb_ips: number;
  masscan_ips: number;
  masscan_running: boolean;
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

export interface HealthInfo {
  workers: number;
  scan_interval: number;
  shodan_rps: number;
  apis: ApiBreakerStatus[];
  blocked_count: number;
  scan_stats: ScanStats;
  feeds: FeedStats;
  vuln_scanner?: VulnScannerStats;
}

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

export const fetchHealth = () => apiFetch<HealthInfo>("/api/health");
export const fetchStats = () => apiFetch<Stats>("/api/stats");
export const fetchResults = () => apiFetch<ScanResult[]>("/api/results");
export const fetchRouterInfo = (id: string) => apiFetch<RouterInfo[]>(`/api/router_info/${id}`);
export const fetchPrioritizedFindings = (limit = 20, minScore = 40) =>
  apiFetch<ScanResult[]>(`/api/prioritized_findings?limit=${limit}&min_score=${minScore}`);
export const fetchVulnResults = (limit = 50, severity?: string) => {
  let path = `/api/vulns/results?limit=${limit}`;
  if (severity) path += `&severity=${severity}`;
  return apiFetch<VulnResult[]>(path);
};
export const fetchVulnStats = () => apiFetch<VulnStats>("/api/vulns/stats");
export const fetchVulnsByIp = (ip: string) => apiFetch<VulnResult[]>(`/api/vulns/ip/${ip}`);

const API_POST = async <T>(path: string, body: Record<string, unknown>): Promise<T> => {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`API POST ${path}: ${res.status}`);
  return res.json();
};

export const triggerVulnScan = (ip: string) =>
  API_POST<{ queued: boolean; ip: string }>("/api/vulns/scan", { ip });
export const triggerBatchVulnScan = (minScore = 70) =>
  API_POST<{ queued: number; min_score: number }>("/api/vulns/scan", { min_score: minScore });
