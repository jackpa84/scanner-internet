"use client";

import { Component, type ReactNode, useEffect, useState, useCallback } from "react";
import BountyPanel from "@/components/BountyPanel";
import VulnPanel from "@/components/VulnPanel";
import {
  fetchHealth,
  fetchBountyStats,
  fetchVulnStats,
  fetchScannerStats,
  fetchROIDashboard,
  fetchPrioritizedPrograms,
  fetchRecentChanges,
  fetchSubmittedReportsStats,
  fetchRecentCVEs,
  fetchBlindVulns,
  fetchAIStats,
  fetchNewTargets,
  fetchHackerOneReports,
  fetchHackerOneEarnings,
  scoreAllPrograms,
  discoverH1Programs,
  triggerCTCheck,
  triggerCVECheck,
  recordEarning,
  type HealthInfo,
  type BountyStats,
  type VulnStats,
  type ScannerStats,
  type ROIDashboard,
  type PrioritizedProgram,
  type BountyChange,
  type SubmittedReportsStats,
  type AIStats,
  type BountyTarget,
} from "@/lib/api";

/* ═══════════════════════════════════════════════════════════════
   Error Boundary
   ═══════════════════════════════════════════════════════════════ */

class EB extends Component<{ children: ReactNode }, { error: string | null }> {
  state = { error: null as string | null };
  static getDerivedStateFromError(err: Error) { return { error: err.message }; }
  render() {
    if (this.state.error) return <div className="text-xs text-red-400 p-2 border border-red-500/20 rounded-lg">Erro: {this.state.error}</div>;
    return this.props.children;
  }
}

/* ═══════════════════════════════════════════════════════════════
   Reusable micro-components
   ═══════════════════════════════════════════════════════════════ */

function Metric({ label, value, color, sub, icon }: { label: string; value: string | number; color?: string; sub?: string; icon?: string }) {
  return (
    <div className="min-w-0">
      <div className="flex items-center gap-1.5">
        {icon && <span className="text-base opacity-80">{icon}</span>}
        <div className={`text-2xl font-bold tabular-nums leading-none ${color || "text-[var(--foreground)]"}`}>
          {typeof value === "number" ? value.toLocaleString() : value}
        </div>
      </div>
      <div className="text-[10px] text-[var(--muted)] mt-1.5 uppercase tracking-wider leading-none truncate">{label}</div>
      {sub && <div className="text-[10px] text-[var(--muted)] mt-0.5 truncate">{sub}</div>}
    </div>
  );
}

function MiniBar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.min(value / max, 1) * 100 : 0;
  return (
    <div className="w-full h-1.5 rounded-full bg-white/5 overflow-hidden">
      <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, background: color }} />
    </div>
  );
}

function SevBar({ c, h, m, l, i }: { c: number; h: number; m: number; l: number; i: number }) {
  const total = c + h + m + l + i;
  if (total === 0) return <div className="w-full h-2.5 rounded-full bg-white/5" />;
  return (
    <div className="flex h-2.5 rounded-full overflow-hidden gap-px">
      {c > 0 && <div style={{ width: `${(c / total) * 100}%` }} className="bg-red-500 first:rounded-l-full last:rounded-r-full" />}
      {h > 0 && <div style={{ width: `${(h / total) * 100}%` }} className="bg-orange-500 first:rounded-l-full last:rounded-r-full" />}
      {m > 0 && <div style={{ width: `${(m / total) * 100}%` }} className="bg-amber-500 first:rounded-l-full last:rounded-r-full" />}
      {l > 0 && <div style={{ width: `${(l / total) * 100}%` }} className="bg-sky-500 first:rounded-l-full last:rounded-r-full" />}
      {i > 0 && <div style={{ width: `${(i / total) * 100}%` }} className="bg-slate-600 first:rounded-l-full last:rounded-r-full" />}
    </div>
  );
}

function Donut({ value, total, color, size = 52 }: { value: number; total: number; color: string; size?: number }) {
  const r = (size - 6) / 2;
  const c = 2 * Math.PI * r;
  const pct = total > 0 ? value / total : 0;
  return (
    <svg width={size} height={size} className="shrink-0">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth={5} />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={5} strokeLinecap="round"
        strokeDasharray={`${c * pct} ${c * (1 - pct)}`} transform={`rotate(-90 ${size / 2} ${size / 2})`}
        className="transition-all duration-700" style={{ filter: `drop-shadow(0 0 4px ${color}40)` }} />
      <text x={size / 2} y={size / 2} textAnchor="middle" dominantBaseline="central"
        className="fill-[var(--foreground)] text-[10px] font-bold">{total > 0 ? `${Math.round(pct * 100)}%` : "–"}</text>
    </svg>
  );
}

const TIER_COLORS: Record<string, string> = {
  S: "bg-yellow-500/15 text-yellow-400 border-yellow-500/25",
  A: "bg-emerald-500/15 text-emerald-400 border-emerald-500/25",
  B: "bg-blue-500/15 text-blue-400 border-blue-500/25",
  C: "bg-slate-500/15 text-slate-400 border-slate-500/25",
  D: "bg-red-500/15 text-red-400 border-red-500/25",
};

/* ═══════════════════════════════════════════════════════════════
   Card wrapper
   ═══════════════════════════════════════════════════════════════ */

function Card({ children, className = "", title, accent, action, glow }: {
  children: ReactNode; className?: string; title?: string; accent?: string;
  action?: ReactNode; glow?: string;
}) {
  return (
    <div className={`rounded-xl border border-[var(--border)] bg-[var(--card)] p-3 card-glow ${className}`}
      style={glow ? { boxShadow: `inset 0 1px 0 0 ${glow}` } : undefined}>
      {title && (
        <div className="flex items-center justify-between mb-2.5">
          <h3 className={`text-xs font-semibold uppercase tracking-wider ${accent || "text-[var(--muted)]"}`}>{title}</h3>
          {action}
        </div>
      )}
      {children}
    </div>
  );
}

/* Metric card with colored top accent */
function MetricCard({ children, accentColor, className = "" }: { children: ReactNode; accentColor: string; className?: string }) {
  return (
    <div className={`metric-card rounded-xl border border-[var(--border)] bg-[var(--card)] p-3 card-glow ${className}`}
      style={{ "--metric-accent": accentColor } as React.CSSProperties}>
      {children}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   Scanner Status Grid
   ═══════════════════════════════════════════════════════════════ */

function ScannerStatusItem({ name, icon, found, tested, color }: {
  name: string; icon: string; found: number; tested: number; color: string;
}) {
  return (
    <div className="flex items-center gap-2 py-1.5 px-2 rounded-lg hover:bg-white/[0.02] transition-colors group">
      <span className="text-sm group-hover:scale-110 transition-transform">{icon}</span>
      <div className="flex-1 min-w-0">
        <div className="text-xs font-medium text-[var(--foreground)] truncate">{name}</div>
      </div>
      {found > 0 ? (
        <span className={`text-xs font-bold tabular-nums ${color}`}>{found}</span>
      ) : (
        <span className="text-xs text-[var(--muted)] tabular-nums">{tested > 0 ? tested : "–"}</span>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   Monthly Trend mini-chart
   ═══════════════════════════════════════════════════════════════ */

function MonthlyTrend({ data }: { data: Record<string, { earnings: number; count: number }> }) {
  const entries = Object.entries(data).slice(-6);
  if (entries.length === 0) return null;
  const maxEarnings = Math.max(...entries.map(([, v]) => v.earnings), 1);
  return (
    <div className="flex items-end gap-1 h-12">
      {entries.map(([month, v]) => (
        <div key={month} className="flex-1 flex flex-col items-center gap-0.5">
          <div
            className="w-full rounded-t bg-emerald-500/60 hover:bg-emerald-400/80 transition-colors min-h-[2px]"
            style={{ height: `${Math.max((v.earnings / maxEarnings) * 100, 4)}%` }}
            title={`${month}: $${v.earnings} (${v.count} reports)`}
          />
          <span className="text-[7px] text-[var(--muted)] tabular-nums">{month.slice(-2)}</span>
        </div>
      ))}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   MAIN DASHBOARD
   ═══════════════════════════════════════════════════════════════ */

export default function Home() {
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [bounty, setBounty] = useState<BountyStats | null>(null);
  const [vuln, setVuln] = useState<VulnStats | null>(null);
  const [scanners, setScanners] = useState<ScannerStats | null>(null);
  const [roi, setRoi] = useState<ROIDashboard | null>(null);
  const [programs, setPrograms] = useState<PrioritizedProgram[]>([]);
  const [changes, setChanges] = useState<BountyChange[]>([]);
  const [reportStats, setReportStats] = useState<SubmittedReportsStats | null>(null);
  const [recentCVEs, setRecentCVEs] = useState<any[]>([]);
  const [blindVulns, setBlindVulns] = useState<any[]>([]);
  const [aiStats, setAiStats] = useState<AIStats | null>(null);
  const [newTargets, setNewTargets] = useState<BountyTarget[]>([]);
  const [h1Reports, setH1Reports] = useState<any>(null);
  const [h1Earnings, setH1Earnings] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "programs" | "vulns">("overview");
  const [actionMsg, setActionMsg] = useState("");

  const [earningForm, setEarningForm] = useState({ program_name: "", amount: "", vuln_type: "" });

  const loadFast = useCallback(async () => {
    const results = await Promise.allSettled([
      fetchHealth(),
      fetchBountyStats(),
      fetchVulnStats(),
    ]);
    if (results[0].status === "fulfilled") setHealth(results[0].value);
    if (results[1].status === "fulfilled") setBounty(results[1].value);
    if (results[2].status === "fulfilled") setVuln(results[2].value);
  }, []);

  const loadSlow = useCallback(async () => {
    const results = await Promise.allSettled([
      fetchScannerStats(),
      fetchROIDashboard(),
      fetchPrioritizedPrograms(0),
      fetchRecentChanges(10),
      fetchSubmittedReportsStats(),
      fetchRecentCVEs(),
      fetchBlindVulns(),
      fetchAIStats(),
      fetchNewTargets(20),
    ]);
    if (results[0].status === "fulfilled") setScanners(results[0].value);
    if (results[1].status === "fulfilled") setRoi(results[1].value);
    if (results[2].status === "fulfilled") setPrograms(results[2].value);
    if (results[3].status === "fulfilled") setChanges(results[3].value);
    if (results[4].status === "fulfilled") setReportStats(results[4].value);
    if (results[5].status === "fulfilled") setRecentCVEs(results[5].value);
    if (results[6].status === "fulfilled") setBlindVulns(results[6].value);
    if (results[7].status === "fulfilled") setAiStats(results[7].value);
    if (results[8].status === "fulfilled") setNewTargets(results[8].value);
  }, []);

  const loadH1 = useCallback(async () => {
    const results = await Promise.allSettled([
      fetchHackerOneReports({ page_size: 5 }),
      fetchHackerOneEarnings({ page_size: 5 }),
    ]);
    if (results[0].status === "fulfilled") setH1Reports(results[0].value);
    if (results[1].status === "fulfilled") setH1Earnings(results[1].value);
  }, []);

  useEffect(() => {
    loadFast();
    loadSlow();
    const fastId = setInterval(loadFast, 15000);
    const slowId = setInterval(loadSlow, 30000);
    return () => { clearInterval(fastId); clearInterval(slowId); };
  }, [loadFast, loadSlow]);

  useEffect(() => {
    loadH1();
    const id = setInterval(loadH1, 120_000);
    return () => clearInterval(id);
  }, [loadH1]);

  const ss = health?.scan_stats;
  const recon = bounty?.recon;
  const scanner = vuln?.scanner;
  const sev = vuln?.by_severity;

  const tabs = [
    { id: "overview" as const, label: "Overview", icon: "📊" },
    { id: "programs" as const, label: "Programs", icon: "🎯" },
    { id: "vulns" as const, label: "Vulnerabilities", icon: "🛡" },
  ];

  return (
    <div className="space-y-3">
      {/* ── Tab Navigation ── */}
      <div className="flex items-center gap-1 bg-[var(--card)] border border-[var(--border)] rounded-xl p-1 w-fit">
        {tabs.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)}
            className={`px-4 py-2 text-xs font-medium rounded-lg transition-all flex items-center gap-1.5 ${
              activeTab === t.id
                ? "bg-[var(--accent)]/15 text-[var(--accent-light)] shadow-sm shadow-[var(--accent)]/10"
                : "text-[var(--muted)] hover:text-[var(--foreground)] hover:bg-white/[0.02]"
            }`}><span>{t.icon}</span>{t.label}</button>
        ))}
      </div>

      {activeTab === "overview" && (
        <>
          {/* ══════════ ROW 1: Top Metrics ══════════ */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 xl:grid-cols-8 gap-2">
            <MetricCard accentColor="#10b981"><Metric icon="💰" label="Earnings" value={roi ? `$${roi.summary.total_earnings.toLocaleString()}` : "$0"} color="text-emerald-400" /></MetricCard>
            <MetricCard accentColor="#eab308"><Metric icon="📈" label="Avg Payout" value={roi ? `$${roi.summary.avg_payout}` : "$0"} color="text-yellow-400" /></MetricCard>
            <MetricCard accentColor="#6366f1"><Metric icon="🎯" label="Programs" value={bounty?.programs ?? 0} color="text-[var(--accent-light)]" sub={`${bounty?.programs_with_bounty ?? 0} com bounty`} /></MetricCard>
            <MetricCard accentColor="#e2e8f0"><Metric icon="🌐" label="Targets" value={bounty?.targets ?? 0} color="text-[var(--foreground)]" sub={`${bounty?.alive_targets ?? 0} vivos`} /></MetricCard>
            <MetricCard accentColor="#f59e0b"><Metric icon="⚠️" label="Vulns" value={vuln?.total_vulns ?? 0} color="text-amber-400" sub={sev ? `${sev.critical}C ${sev.high}H ${sev.medium}M` : ""} /></MetricCard>
            <MetricCard accentColor="#06b6d4"><Metric icon="🔍" label="Subdomains" value={recon?.subdomains_found ?? 0} color="text-cyan-400" sub={`${recon?.new_subdomains_detected ?? 0} novos`} /></MetricCard>
            <MetricCard accentColor="#8b5cf6"><Metric icon="📝" label="Reports" value={reportStats?.total ?? 0} color="text-violet-400" sub={`${reportStats?.submitted ?? 0} ok / ${reportStats?.errors ?? 0} err`} /></MetricCard>
            <MetricCard accentColor={(roi?.operations.acceptance_rate ?? 0) > 50 ? "#10b981" : "#ef4444"}>
              <Metric icon="✅" label="Acceptance" value={roi ? `${roi.operations.acceptance_rate}%` : "–"} color={(roi?.operations.acceptance_rate ?? 0) > 50 ? "text-emerald-400" : "text-red-400"} />
            </MetricCard>
          </div>

          {/* ══════════ ROW 2: Scanner Activity + Vulns + Recon + Operations ══════════ */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-2">

            {/* Scanner Activity */}
            <Card className="lg:col-span-3" title="Scanners" accent="text-[var(--accent-light)]"
              action={<span className="text-[10px] text-emerald-400 pulse-live inline-block w-1.5 h-1.5 rounded-full bg-emerald-400" />}
              glow="rgba(99, 102, 241, 0.08)">
              <div className="space-y-0.5">
                <ScannerStatusItem name="IDOR" icon="🔓" found={scanners?.idor?.idor_found ?? 0} tested={scanners?.idor?.endpoints_tested ?? 0} color="text-red-400" />
                <ScannerStatusItem name="SSRF" icon="🌐" found={scanners?.ssrf?.ssrf_found ?? 0} tested={scanners?.ssrf?.urls_tested ?? 0} color="text-orange-400" />
                <ScannerStatusItem name="GraphQL" icon="◇" found={scanners?.graphql?.vulns_found ?? 0} tested={scanners?.graphql?.endpoints_found ?? 0} color="text-pink-400" />
                <ScannerStatusItem name="Race Condition" icon="⚡" found={scanners?.race_condition?.race_conditions_found ?? 0} tested={scanners?.race_condition?.endpoints_tested ?? 0} color="text-yellow-400" />
                <ScannerStatusItem name="Blind (OOB)" icon="👁" found={scanners?.interactsh?.blind_vulns_confirmed ?? 0} tested={scanners?.interactsh?.payloads_generated ?? 0} color="text-purple-400" />
                <ScannerStatusItem name="CT Monitor" icon="📜" found={scanners?.ct_monitor?.new_subdomains_found ?? 0} tested={scanners?.ct_monitor?.checks_completed ?? 0} color="text-sky-400" />
                <ScannerStatusItem name="CVE Monitor" icon="🛡" found={scanners?.cve_monitor?.templates_generated ?? 0} tested={scanners?.cve_monitor?.cves_fetched ?? 0} color="text-teal-400" />
                <ScannerStatusItem name="Scorer" icon="📊" found={0} tested={typeof scanners?.scorer?.programs_scored === "number" ? scanners.scorer.programs_scored : 0} color="text-indigo-400" />
                <ScannerStatusItem name={`AI${scanners?.ai?.provider ? ` (${scanners.ai.provider})` : ""}`} icon="🧠" found={scanners?.ai?.reports_generated ?? 0} tested={scanners?.ai?.requests ?? 0} color="text-fuchsia-400" />
              </div>
            </Card>

            {/* Vulnerabilities Breakdown */}
            <Card className="lg:col-span-3" title="Vulnerabilities" accent="text-amber-400" glow="rgba(245, 158, 11, 0.06)">
              <div className="flex items-center gap-3 mb-3">
                <Donut value={(sev?.critical ?? 0) + (sev?.high ?? 0)} total={vuln?.total_vulns ?? 1} color="#f97316" size={56} />
                <div>
                  <div className="text-2xl font-bold tabular-nums text-[var(--foreground)]">{vuln?.total_vulns ?? 0}</div>
                  <div className="text-[10px] text-[var(--muted)] uppercase">Total vulns</div>
                </div>
              </div>
              <SevBar c={sev?.critical ?? 0} h={sev?.high ?? 0} m={sev?.medium ?? 0} l={sev?.low ?? 0} i={sev?.info ?? 0} />
              <div className="grid grid-cols-5 gap-1 mt-2.5">
                {[
                  { label: "CRIT", val: sev?.critical ?? 0, c: "text-red-400" },
                  { label: "HIGH", val: sev?.high ?? 0, c: "text-orange-400" },
                  { label: "MED", val: sev?.medium ?? 0, c: "text-amber-400" },
                  { label: "LOW", val: sev?.low ?? 0, c: "text-sky-400" },
                  { label: "INFO", val: sev?.info ?? 0, c: "text-slate-500" },
                ].map(s => (
                  <div key={s.label} className="text-center">
                    <div className={`text-sm font-bold tabular-nums ${s.val > 0 ? s.c : "text-[var(--muted)]"}`}>{s.val}</div>
                    <div className="text-[8px] text-[var(--muted)] uppercase">{s.label}</div>
                  </div>
                ))}
              </div>
              {/* Top Vulns */}
              {vuln?.top_vulns && vuln.top_vulns.length > 0 && (
                <div className="mt-2.5 pt-2 border-t border-[var(--border)]">
                  <div className="text-[10px] text-[var(--muted)] uppercase font-semibold mb-1">Top Vulnerabilities</div>
                  {vuln.top_vulns.slice(0, 4).map((tv, i) => (
                    <div key={i} className="flex items-center justify-between text-[10px] py-0.5">
                      <span className="text-[var(--foreground)] truncate flex-1">{tv.name || tv.template_id}</span>
                      <span className={`font-bold ml-2 shrink-0 px-1.5 py-0.5 rounded text-[9px] sev-${tv.severity}`}>{tv.count}</span>
                    </div>
                  ))}
                </div>
              )}
              <div className="mt-2 pt-2 border-t border-[var(--border)] grid grid-cols-2 gap-1 text-xs">
                <div className="text-[var(--muted)]">Nuclei <span className="text-[var(--foreground)] font-semibold">{scanner?.nuclei_runs ?? 0}</span></div>
                <div className="text-[var(--muted)]">Nmap <span className="text-[var(--foreground)] font-semibold">{scanner?.nmap_runs ?? 0}</span></div>
                <div className="text-[var(--muted)]">Queue <span className="text-amber-400 font-semibold">{scanner?.queue_size ?? 0}</span></div>
                <div className="text-[var(--muted)]">Scanning <span className="text-blue-400 font-semibold">{scanner?.scanning ?? 0}</span></div>
              </div>
              {blindVulns.length > 0 && (
                <div className="mt-2 pt-2 border-t border-[var(--border)]">
                  <div className="text-[10px] text-purple-400 font-semibold uppercase mb-1">Blind Vulns Confirmed</div>
                  <div className="text-lg font-bold text-purple-400">{blindVulns.length}</div>
                </div>
              )}
            </Card>

            {/* Recon Pipeline */}
            <Card className="lg:col-span-3" title="Recon Pipeline" accent="text-cyan-400" glow="rgba(6, 182, 212, 0.06)">
              <div className="flex items-center gap-3 mb-3">
                <Donut value={recon?.recons_completed ?? 0} total={bounty?.programs ?? 1} color="#06b6d4" size={56} />
                <div>
                  <div className="text-sm font-semibold text-[var(--foreground)]">
                    {recon?.recons_completed ?? 0}<span className="text-[var(--muted)]">/{bounty?.programs ?? 0}</span>
                  </div>
                  <div className="text-[10px] text-[var(--muted)] uppercase">Recons done</div>
                </div>
              </div>
              <div className="space-y-1.5">
                {[
                  { label: "Subdomains", val: recon?.subdomains_found ?? 0, c: "text-[var(--foreground)]" },
                  { label: "Hosts alive", val: recon?.hosts_alive ?? 0, c: "text-emerald-400" },
                  { label: "crt.sh", val: recon?.crtsh_subdomains ?? 0, c: "text-sky-400" },
                  { label: "ASNs", val: recon?.asns_discovered ?? 0, c: "text-violet-400" },
                  { label: "rDNS", val: recon?.rdns_subdomains ?? 0, c: "text-pink-400" },
                  { label: "New subs", val: recon?.new_subdomains_detected ?? 0, c: "text-lime-400" },
                  { label: "Targets alive", val: bounty?.alive_targets ?? 0, c: "text-emerald-400" },
                  { label: "New targets", val: bounty?.new_targets ?? 0, c: "text-lime-400" },
                  { label: "Changes", val: bounty?.total_changes ?? 0, c: "text-slate-300" },
                ].map(r => (
                  <div key={r.label} className="flex items-center justify-between text-xs">
                    <span className="text-[var(--muted)]">{r.label}</span>
                    <span className={`font-semibold tabular-nums ${r.c}`}>{r.val.toLocaleString()}</span>
                  </div>
                ))}
              </div>
              {(recon?.errors ?? 0) > 0 && (
                <div className="mt-2 text-xs text-red-400">Errors: {recon!.errors}</div>
              )}
            </Card>

            {/* Operations */}
            <Card className="lg:col-span-3" title="Operations" accent="text-blue-400" glow="rgba(59, 130, 246, 0.06)">
              {health?.network_scanner_enabled && ss ? (
                <div className="mb-3">
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="text-[var(--muted)]">Network Scanner</span>
                    <span className="flex items-center gap-1 text-emerald-400 text-[10px]">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 pulse-live" /> ACTIVE
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-1 mb-2">
                    <div className="text-center"><div className="text-sm font-bold tabular-nums text-blue-400">{ss.tested.toLocaleString()}</div><div className="text-[8px] text-[var(--muted)] uppercase">Tested</div></div>
                    <div className="text-center"><div className="text-sm font-bold tabular-nums text-emerald-400">{ss.alive.toLocaleString()}</div><div className="text-[8px] text-[var(--muted)] uppercase">Alive</div></div>
                    <div className="text-center"><div className="text-sm font-bold tabular-nums text-red-400">{ss.dead.toLocaleString()}</div><div className="text-[8px] text-[var(--muted)] uppercase">Dead</div></div>
                  </div>
                  <MiniBar value={ss.alive} max={ss.tested || 1} color="#3b82f6" />
                </div>
              ) : (
                <div className="text-xs text-[var(--muted)] mb-3 italic">Network scanner off</div>
              )}

              <div className="border-t border-[var(--border)] pt-2 space-y-1">
                <div className="text-[10px] text-[var(--muted)] uppercase font-semibold">Quick Actions</div>
                {[
                  { label: "🔍 Discover H1 Programs", fn: async () => { const r = await discoverH1Programs(); setActionMsg(`Found ${r.new_programs_found}, imported ${r.auto_imported}`); } },
                  { label: "📊 Score Programs", fn: async () => { const r = await scoreAllPrograms(); setActionMsg(`Scored ${r.scored} programs`); } },
                  { label: "📜 Check CT Logs", fn: async () => { const r = await triggerCTCheck(); setActionMsg(`${r.new_domains_found} new domains`); } },
                  { label: "🛡 Check CVE Feeds", fn: async () => { const r = await triggerCVECheck(); setActionMsg(`${r.templates_created} templates`); } },
                ].map(a => (
                  <button key={a.label} onClick={() => a.fn().catch(e => setActionMsg(`Error: ${e.message}`))}
                    className="w-full text-left text-xs px-2 py-1.5 rounded-lg hover:bg-white/[0.03] text-[var(--muted)] hover:text-[var(--foreground)] transition-all">
                    {a.label}
                  </button>
                ))}
                {actionMsg && <div className="text-[10px] text-emerald-400 px-2 py-1 bg-emerald-500/5 rounded-md">{actionMsg}</div>}
              </div>

              {/* Earnings form */}
              <div className="border-t border-[var(--border)] pt-2 mt-2">
                <div className="text-[10px] text-[var(--muted)] uppercase font-semibold mb-1.5">Record Earning</div>
                <div className="flex gap-1">
                  <input type="text" placeholder="Program" value={earningForm.program_name}
                    onChange={e => setEarningForm(f => ({ ...f, program_name: e.target.value }))}
                    className="flex-1 !text-xs !py-1 !px-2 !rounded-lg !border-[var(--border)] !bg-[var(--background)]" />
                  <input type="number" placeholder="$" value={earningForm.amount}
                    onChange={e => setEarningForm(f => ({ ...f, amount: e.target.value }))}
                    className="w-16 !text-xs !py-1 !px-2 !rounded-lg !border-[var(--border)] !bg-[var(--background)]" />
                  <button onClick={async () => {
                    const amt = parseFloat(earningForm.amount);
                    if (!amt || !earningForm.program_name) return;
                    await recordEarning({ program_id: "", program_name: earningForm.program_name, amount: amt, vuln_type: earningForm.vuln_type });
                    setEarningForm({ program_name: "", amount: "", vuln_type: "" });
                    setActionMsg(`Recorded $${amt}`);
                    load();
                  }} className="text-[10px] px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-medium transition-colors">+</button>
                </div>
              </div>
            </Card>
          </div>

          {/* ══════════ ROW 3: AI + HackerOne + New Targets ══════════ */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-2">

            {/* AI Analyzer Status */}
            <Card className="lg:col-span-3" title="AI Analyzer" accent="text-fuchsia-400" glow="rgba(192, 38, 211, 0.06)">
              {aiStats ? (
                <>
                  <div className="flex items-center gap-2 mb-3">
                    <div className={`w-2 h-2 rounded-full ${aiStats.enabled ? "bg-emerald-400 pulse-live" : "bg-red-400"}`} />
                    <span className={`text-xs font-medium ${aiStats.enabled ? "text-emerald-400" : "text-red-400"}`}>
                      {aiStats.enabled ? "Active" : "Disabled"}
                    </span>
                    {aiStats.model && (
                      <span className="text-[10px] text-[var(--muted)] bg-white/5 px-1.5 py-0.5 rounded ml-auto font-mono truncate max-w-[120px]">
                        {aiStats.model}
                      </span>
                    )}
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <div className="text-lg font-bold text-fuchsia-400 tabular-nums">{aiStats.reports_generated}</div>
                      <div className="text-[8px] text-[var(--muted)] uppercase">Reports</div>
                    </div>
                    <div>
                      <div className="text-lg font-bold text-violet-400 tabular-nums">{aiStats.findings_classified}</div>
                      <div className="text-[8px] text-[var(--muted)] uppercase">Classified</div>
                    </div>
                    <div>
                      <div className="text-lg font-bold text-cyan-400 tabular-nums">{aiStats.responses_analyzed}</div>
                      <div className="text-[8px] text-[var(--muted)] uppercase">Analyzed</div>
                    </div>
                    <div>
                      <div className="text-lg font-bold text-[var(--foreground)] tabular-nums">{aiStats.requests}</div>
                      <div className="text-[8px] text-[var(--muted)] uppercase">Requests</div>
                    </div>
                  </div>
                  {aiStats.errors > 0 && (
                    <div className="mt-2 pt-2 border-t border-[var(--border)] flex items-center justify-between text-xs">
                      <span className="text-[var(--muted)]">Errors</span>
                      <span className="text-red-400 font-semibold">{aiStats.errors}</span>
                    </div>
                  )}
                  {aiStats.tokens_used > 0 && (
                    <div className="mt-1.5 flex items-center justify-between text-xs">
                      <span className="text-[var(--muted)]">Tokens used</span>
                      <span className="text-[var(--foreground)] font-semibold tabular-nums">{aiStats.tokens_used.toLocaleString()}</span>
                    </div>
                  )}
                </>
              ) : (
                <div className="text-xs text-[var(--muted)] text-center py-6">
                  Configure AI_PROVIDER in .env
                </div>
              )}
            </Card>

            {/* HackerOne Live */}
            <Card className="lg:col-span-5" title="HackerOne" accent="text-green-400" glow="rgba(74, 222, 128, 0.06)"
              action={<span className="text-[10px] text-[var(--muted)]">Live from API</span>}>
              <div className="grid grid-cols-2 gap-3">
                {/* Reports */}
                <div>
                  <div className="text-[10px] text-[var(--muted)] uppercase font-semibold mb-1.5">Recent Reports</div>
                  {h1Reports?.data && h1Reports.data.length > 0 ? (
                    <div className="space-y-1">
                      {h1Reports.data.slice(0, 5).map((r: any, i: number) => {
                        const attrs = r.attributes || {};
                        const state = attrs.state || "new";
                        const stateColors: Record<string, string> = {
                          new: "text-blue-400",
                          triaged: "text-amber-400",
                          resolved: "text-emerald-400",
                          "not-applicable": "text-red-400",
                          informative: "text-slate-400",
                          duplicate: "text-orange-400",
                        };
                        return (
                          <div key={i} className="text-[10px] py-1 border-l-2 border-green-500/20 pl-2">
                            <div className="text-[var(--foreground)] truncate font-medium">{attrs.title || "Report"}</div>
                            <div className="flex items-center gap-2 mt-0.5">
                              <span className={`font-semibold ${stateColors[state] || "text-[var(--muted)]"}`}>{state}</span>
                              {attrs.severity_rating && <span className={`sev-${attrs.severity_rating} text-[9px] px-1 py-0.5 rounded`}>{attrs.severity_rating}</span>}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="text-[10px] text-[var(--muted)] py-3 text-center">No reports yet</div>
                  )}
                </div>

                {/* Earnings */}
                <div>
                  <div className="text-[10px] text-[var(--muted)] uppercase font-semibold mb-1.5">Recent Earnings</div>
                  {h1Earnings?.data && h1Earnings.data.length > 0 ? (
                    <div className="space-y-1">
                      {h1Earnings.data.slice(0, 5).map((e: any, i: number) => {
                        const attrs = e.attributes || {};
                        return (
                          <div key={i} className="flex items-center justify-between text-[10px] py-1 border-l-2 border-emerald-500/20 pl-2">
                            <span className="text-[var(--foreground)] truncate">{attrs.bounty_program_name || "Program"}</span>
                            <span className="text-emerald-400 font-bold shrink-0">${attrs.amount || 0}</span>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="text-[10px] text-[var(--muted)] py-3 text-center">No earnings yet</div>
                  )}
                </div>
              </div>
            </Card>

            {/* New Targets */}
            <Card className="lg:col-span-4" title="New Targets" accent="text-lime-400" glow="rgba(132, 204, 22, 0.06)"
              action={<span className="text-[10px] font-bold text-lime-400">{newTargets.length}</span>}>
              <div className="space-y-1 max-h-56 overflow-y-auto hide-scrollbar">
                {newTargets.slice(0, 12).map((t, i) => {
                  const rc = t.recon_checks;
                  const findings = rc?.total_findings ?? (rc?.findings?.length ?? 0);
                  const riskScore = rc?.risk_score ?? 0;
                  return (
                    <div key={t.id || i} className="flex items-center gap-2 text-xs py-1 px-1.5 rounded-lg hover:bg-white/[0.02] transition-colors">
                      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${t.alive ? "bg-emerald-400" : "bg-red-400"}`} />
                      <span className="text-[var(--foreground)] truncate flex-1 font-mono text-[10px]">{t.domain}</span>
                      {findings > 0 && (
                        <span className={`text-[9px] font-bold px-1 py-0.5 rounded ${
                          riskScore >= 70 ? "sev-critical" : riskScore >= 40 ? "sev-medium" : "sev-low"
                        }`}>{findings}</span>
                      )}
                      {t.httpx?.status_code && (
                        <span className={`text-[9px] tabular-nums ${
                          t.httpx.status_code < 300 ? "text-emerald-400" : t.httpx.status_code < 400 ? "text-amber-400" : "text-red-400"
                        }`}>{t.httpx.status_code}</span>
                      )}
                    </div>
                  );
                })}
                {newTargets.length === 0 && <div className="text-xs text-[var(--muted)] text-center py-6">No new targets discovered</div>}
              </div>
            </Card>
          </div>

          {/* ══════════ ROW 4: Program Rankings + Activity Feed + Intelligence ══════════ */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-2">

            {/* Program Rankings */}
            <Card className="lg:col-span-4" title="Program Rankings" accent="text-[var(--accent-light)]"
              action={<span className="text-[10px] text-[var(--muted)]">{programs.length} programs</span>}
              glow="rgba(99, 102, 241, 0.06)">
              <div className="space-y-1 max-h-64 overflow-y-auto hide-scrollbar">
                {programs.slice(0, 15).map((p, i) => (
                  <div key={p.program_id} className="flex items-center gap-2 py-1 px-1 rounded-lg hover:bg-white/[0.02] transition-colors">
                    <span className="text-[10px] text-[var(--muted)] w-4 text-right tabular-nums">{i + 1}</span>
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${TIER_COLORS[p.tier] || "bg-slate-700 text-slate-300 border-slate-600"}`}>
                      {p.tier}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-medium text-[var(--foreground)] truncate">{p.name}</div>
                    </div>
                    <div className="flex items-center gap-2 text-[10px] tabular-nums shrink-0">
                      <span className="text-[var(--muted)]">{p.score}</span>
                      {p.has_bounty && p.bounty_max && (
                        <span className="text-emerald-400">${p.bounty_max >= 1000 ? `${(p.bounty_max / 1000).toFixed(0)}k` : p.bounty_max}</span>
                      )}
                      <span className="text-[var(--muted)]">{p.alive_targets}a</span>
                    </div>
                  </div>
                ))}
                {programs.length === 0 && <div className="text-xs text-[var(--muted)] text-center py-4">No programs scored yet</div>}
              </div>
            </Card>

            {/* Recent Activity */}
            <Card className="lg:col-span-4" title="Recent Activity" accent="text-lime-400">
              <div className="space-y-1.5 max-h-64 overflow-y-auto hide-scrollbar">
                {changes.map((ch, i) => (
                  <div key={ch.id || i} className="text-xs border-l-2 border-lime-500/30 pl-2 py-0.5">
                    <div className="flex items-center gap-1">
                      <span className="font-medium text-[var(--foreground)]">{ch.program_name}</span>
                      {ch.new_subdomains?.length > 0 && (
                        <span className="text-emerald-400 font-semibold">+{ch.new_subdomains.length}</span>
                      )}
                      {ch.removed_subdomains?.length > 0 && (
                        <span className="text-red-400 font-semibold">-{ch.removed_subdomains.length}</span>
                      )}
                    </div>
                    <div className="text-[var(--muted)] text-[10px] truncate">
                      {ch.new_subdomains?.slice(0, 3).join(", ")}
                    </div>
                  </div>
                ))}
                {changes.length === 0 && <div className="text-xs text-[var(--muted)] text-center py-4">No recent changes</div>}
              </div>
            </Card>

            {/* Intelligence */}
            <Card className="lg:col-span-4" title="Intelligence" accent="text-teal-400" glow="rgba(20, 184, 166, 0.06)">
              {/* Monthly Trend */}
              {roi && Object.keys(roi.monthly_trend).length > 0 && (
                <div className="mb-3">
                  <div className="text-[10px] text-[var(--muted)] uppercase font-semibold mb-1">Earnings Trend</div>
                  <MonthlyTrend data={roi.monthly_trend} />
                </div>
              )}

              {/* Top programs by earnings */}
              {roi && roi.top_programs.length > 0 && (
                <div className="mb-3">
                  <div className="text-[10px] text-[var(--muted)] uppercase font-semibold mb-1">Top Earners</div>
                  {roi.top_programs.slice(0, 3).map((p, i) => (
                    <div key={i} className="flex items-center justify-between text-xs py-0.5">
                      <span className="text-[var(--foreground)] truncate">{p.name}</span>
                      <span className="text-emerald-400 font-semibold tabular-nums">${p.earned.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Most profitable vulns */}
              {roi && roi.most_profitable_vulns.length > 0 && (
                <div className="mb-3">
                  <div className="text-[10px] text-[var(--muted)] uppercase font-semibold mb-1">Best Vuln Types</div>
                  {roi.most_profitable_vulns.slice(0, 3).map((v, i) => (
                    <div key={i} className="flex items-center justify-between text-xs py-0.5">
                      <span className="text-[var(--foreground)] truncate">{v.type}</span>
                      <span className="text-yellow-400 font-semibold tabular-nums">avg ${v.avg_payout}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Recent CVEs */}
              {recentCVEs.length > 0 && (
                <div className="border-t border-[var(--border)] pt-2">
                  <div className="text-[10px] text-[var(--muted)] uppercase font-semibold mb-1">Recent CVEs</div>
                  {recentCVEs.slice(0, 4).map((cve: any, i: number) => (
                    <div key={i} className="flex items-center justify-between text-[10px] py-0.5">
                      <span className="text-[var(--foreground)] font-mono truncate">{cve.id}</span>
                      <span className={`font-bold px-1.5 py-0.5 rounded text-[9px] ${
                        cve.severity === "critical" ? "sev-critical" : cve.severity === "high" ? "sev-high" : "sev-medium"
                      }`}>{cve.cvss_score}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Recommendations */}
              {roi && roi.recommendations.length > 0 && (
                <div className="border-t border-[var(--border)] pt-2 mt-2">
                  <div className="text-[10px] text-[var(--muted)] uppercase font-semibold mb-1">Recommendations</div>
                  {roi.recommendations.slice(0, 2).map((r, i) => (
                    <div key={i} className="text-[10px] text-[var(--muted)] py-0.5 leading-relaxed">{r}</div>
                  ))}
                </div>
              )}
            </Card>
          </div>

          {/* ══════════ ROW 5: Reports + Tools Pipeline ══════════ */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-2">
            <Card className="lg:col-span-4" title="Report Stats" accent="text-violet-400" glow="rgba(139, 92, 246, 0.06)">
              <div className="grid grid-cols-2 gap-3 mb-3">
                <div className="text-center p-2 rounded-lg bg-violet-500/5 border border-violet-500/10">
                  <div className="text-xl font-bold text-violet-400 tabular-nums">{reportStats?.submitted ?? 0}</div>
                  <div className="text-[8px] text-[var(--muted)] uppercase">Submitted</div>
                </div>
                <div className="text-center p-2 rounded-lg bg-red-500/5 border border-red-500/10">
                  <div className="text-xl font-bold text-red-400 tabular-nums">{reportStats?.errors ?? 0}</div>
                  <div className="text-[8px] text-[var(--muted)] uppercase">Errors</div>
                </div>
                <div className="text-center p-2 rounded-lg bg-amber-500/5 border border-amber-500/10">
                  <div className="text-xl font-bold text-amber-400 tabular-nums">{reportStats?.pending ?? 0}</div>
                  <div className="text-[8px] text-[var(--muted)] uppercase">Pending</div>
                </div>
                <div className="text-center p-2 rounded-lg bg-white/[0.02] border border-white/5">
                  <div className="text-xl font-bold text-[var(--foreground)] tabular-nums">{reportStats?.total ?? 0}</div>
                  <div className="text-[8px] text-[var(--muted)] uppercase">Total</div>
                </div>
              </div>
              {reportStats?.by_severity && Object.keys(reportStats.by_severity).length > 0 && (
                <div className="border-t border-[var(--border)] pt-2">
                  <div className="text-[10px] text-[var(--muted)] uppercase font-semibold mb-1">By Severity</div>
                  <div className="flex gap-2 flex-wrap">
                    {Object.entries(reportStats.by_severity).map(([s, count]) => (
                      <span key={s} className={`text-[10px] font-semibold px-1.5 py-0.5 rounded sev-${s}`}>{s}: {count as number}</span>
                    ))}
                  </div>
                </div>
              )}
            </Card>

            <Card className="lg:col-span-8" title="Tools Pipeline" accent="text-pink-400">
              <div className="flex flex-wrap gap-1.5">
                {[
                  { name: "subfinder", c: "text-cyan-400 border-cyan-500/15 bg-cyan-500/5" },
                  { name: "crt.sh", c: "text-sky-400 border-sky-500/15 bg-sky-500/5" },
                  { name: "httpx", c: "text-emerald-400 border-emerald-500/15 bg-emerald-500/5" },
                  { name: "katana", c: "text-pink-400 border-pink-500/15 bg-pink-500/5" },
                  { name: "gau", c: "text-rose-400 border-rose-500/15 bg-rose-500/5" },
                  { name: "nuclei", c: "text-violet-400 border-violet-500/15 bg-violet-500/5" },
                  { name: "nmap", c: "text-blue-400 border-blue-500/15 bg-blue-500/5" },
                  { name: "IDOR", c: "text-red-400 border-red-500/15 bg-red-500/5" },
                  { name: "SSRF", c: "text-orange-400 border-orange-500/15 bg-orange-500/5" },
                  { name: "GraphQL", c: "text-pink-400 border-pink-500/15 bg-pink-500/5" },
                  { name: "Race", c: "text-yellow-400 border-yellow-500/15 bg-yellow-500/5" },
                  { name: "Interactsh", c: "text-purple-400 border-purple-500/15 bg-purple-500/5" },
                  { name: "CT Monitor", c: "text-sky-400 border-sky-500/15 bg-sky-500/5" },
                  { name: "CVE Monitor", c: "text-teal-400 border-teal-500/15 bg-teal-500/5" },
                  { name: "ParamSpider", c: "text-orange-400 border-orange-500/15 bg-orange-500/5" },
                  { name: "dnsx", c: "text-teal-400 border-teal-500/15 bg-teal-500/5" },
                  { name: "dalfox", c: "text-red-400 border-red-500/15 bg-red-500/5" },
                  { name: "ffuf", c: "text-lime-400 border-lime-500/15 bg-lime-500/5" },
                  { name: "testssl", c: "text-yellow-400 border-yellow-500/15 bg-yellow-500/5" },
                  { name: "wafw00f", c: "text-slate-300 border-slate-500/15 bg-slate-500/5" },
                  { name: "GitHub Dork", c: "text-slate-300 border-slate-500/15 bg-slate-500/5" },
                  { name: "JS Secrets", c: "text-red-400 border-red-500/15 bg-red-500/5" },
                  { name: "AI Analyzer", c: "text-fuchsia-400 border-fuchsia-500/15 bg-fuchsia-500/5" },
                  { name: "Scorer", c: "text-indigo-400 border-indigo-500/15 bg-indigo-500/5" },
                ].map(t => (
                  <span key={t.name} className={`text-[10px] font-semibold px-2 py-1 rounded-md border ${t.c} hover:brightness-125 transition-all cursor-default`}>{t.name}</span>
                ))}
              </div>
            </Card>
          </div>
        </>
      )}

      {activeTab === "programs" && (
        <EB><BountyPanel /></EB>
      )}

      {activeTab === "vulns" && (
        <EB><VulnPanel /></EB>
      )}
    </div>
  );
}
