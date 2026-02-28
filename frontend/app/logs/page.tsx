"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  fetchDbActivity,
  fetchHealth,
  fetchVulnStats,
  fetchBountyStats,
  fetchScannerStats,
  fetchAIStats,
  type DbActivityEntry,
  type HealthInfo,
  type AIStats,
} from "@/lib/api";

/* ═══════════════════════════════════════════════════════════════
   Types
   ═══════════════════════════════════════════════════════════════ */

interface LogLine {
  id: number;
  ts: Date;
  source: "api" | "scan" | "vuln" | "recon" | "bounty" | "system";
  level: "info" | "warn" | "error" | "success";
  message: string;
  detail?: string;
  ip?: string;
  country?: string;
  riskLevel?: string;
}

interface ApiCallLog {
  id: number;
  ts: Date;
  method: string;
  path: string;
  status: number | null;
  ms: number | null;
  error?: string;
}

/* ═══════════════════════════════════════════════════════════════
   Constants
   ═══════════════════════════════════════════════════════════════ */

const MAX_LINES = 500;
const MAX_API_CALLS = 300;
let _lid = 0;
let _aid = 0;

const SOURCE_COLORS: Record<string, string> = {
  scan: "text-blue-400",
  vuln: "text-orange-400",
  recon: "text-cyan-400",
  bounty: "text-emerald-400",
  api: "text-violet-400",
  system: "text-slate-400",
};

const SOURCE_BG: Record<string, string> = {
  scan: "bg-blue-500/10 border-blue-500/20",
  vuln: "bg-orange-500/10 border-orange-500/20",
  recon: "bg-cyan-500/10 border-cyan-500/20",
  bounty: "bg-emerald-500/10 border-emerald-500/20",
  api: "bg-violet-500/10 border-violet-500/20",
  system: "bg-slate-500/10 border-slate-500/20",
};

const LEVEL_COLORS: Record<string, string> = {
  info: "text-[var(--foreground)]",
  warn: "text-amber-400",
  error: "text-red-400",
  success: "text-emerald-400",
};

/* ═══════════════════════════════════════════════════════════════
   Helpers
   ═══════════════════════════════════════════════════════════════ */

function classifyActivity(entry: DbActivityEntry): LogLine {
  const sourceMap: Record<string, LogLine["source"]> = {
    scan_results: "scan",
    vuln_results: "vuln",
    bounty_targets: "recon",
    bounty_programs: "bounty",
    bounty_changes: "bounty",
  };

  let level: LogLine["level"] = "info";
  const rl = (entry.risk_level || "").toLowerCase();
  if (rl === "critical" || rl === "high") level = "warn";
  if (entry.action === "vuln" && (rl === "critical" || rl === "high")) level = "error";

  return {
    id: ++_lid,
    ts: entry.timestamp ? new Date(entry.timestamp) : new Date(),
    source: sourceMap[entry.collection] || "system",
    level,
    message: entry.summary || `${entry.action} event`,
    ip: entry.ip || undefined,
    country: entry.country || undefined,
    riskLevel: entry.risk_level || undefined,
  };
}

function formatTime(d: Date): string {
  return d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatDate(d: Date): string {
  return d.toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit" });
}

/* ═══════════════════════════════════════════════════════════════
   Main Page
   ═══════════════════════════════════════════════════════════════ */

export default function LogsPage() {
  const [lines, setLines] = useState<LogLine[]>([]);
  const [apiCalls, setApiCalls] = useState<ApiCallLog[]>([]);
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [aiStats, setAiStats] = useState<AIStats | null>(null);
  const [vulnCount, setVulnCount] = useState(0);
  const [scannerStats, setScannerStats] = useState<any>(null);
  const [bountyStats, setBountyStats] = useState<any>(null);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState<"all" | LogLine["source"]>("all");
  const [search, setSearch] = useState("");
  const [tab, setTab] = useState<"activity" | "api" | "circuit">("activity");
  const [autoScroll, setAutoScroll] = useState(true);

  const seenKeys = useRef<Set<string>>(new Set());
  const logEndRef = useRef<HTMLDivElement>(null);
  const originalFetchRef = useRef<typeof fetch | null>(null);

  // ── Intercept fetch for API call logging ──
  useEffect(() => {
    if (originalFetchRef.current) return;
    originalFetchRef.current = window.fetch;

    window.fetch = async function (...args) {
      const url = typeof args[0] === "string" ? args[0] : (args[0] as Request)?.url ?? "";
      const opts = (args[1] as RequestInit) ?? {};
      const method = (opts.method || "GET").toUpperCase();

      const isApi = url.includes("/api/");
      if (!isApi) return originalFetchRef.current!.apply(this, args);

      const path = url.replace(/^https?:\/\/[^/]+/, "").split("?")[0].replace("/api/", "");
      const entry: ApiCallLog = {
        id: ++_aid,
        ts: new Date(),
        method,
        path,
        status: null,
        ms: null,
      };

      const t0 = performance.now();
      try {
        const res = await originalFetchRef.current!.apply(this, args);
        entry.status = res.status;
        entry.ms = Math.round(performance.now() - t0);
        setApiCalls(prev => [entry, ...prev].slice(0, MAX_API_CALLS));
        return res;
      } catch (err: any) {
        entry.ms = Math.round(performance.now() - t0);
        entry.error = err.message?.slice(0, 80);
        setApiCalls(prev => [entry, ...prev].slice(0, MAX_API_CALLS));
        throw err;
      }
    };

    return () => {
      if (originalFetchRef.current) window.fetch = originalFetchRef.current;
    };
  }, []);

  // ── Poll backend activity ──
  const pollActivity = useCallback(async () => {
    if (paused) return;
    try {
      const data = await fetchDbActivity(50);
      if (!data?.activity) return;

      const newLines: LogLine[] = [];
      for (const entry of data.activity) {
        const key = `${entry.collection}:${entry.timestamp}:${entry.summary?.slice(0, 40)}`;
        if (seenKeys.current.has(key)) continue;
        seenKeys.current.add(key);
        newLines.push(classifyActivity(entry));
      }

      if (seenKeys.current.size > 1000) {
        const arr = [...seenKeys.current];
        seenKeys.current = new Set(arr.slice(-500));
      }

      if (newLines.length > 0) {
        setLines(prev => [...newLines, ...prev].slice(0, MAX_LINES));
      }
    } catch { /* ignore */ }
  }, [paused]);

  // ── Poll health + stats ──
  const pollStats = useCallback(async () => {
    const results = await Promise.allSettled([
      fetchHealth(),
      fetchAIStats(),
      fetchVulnStats(),
      fetchScannerStats(),
      fetchBountyStats(),
    ]);
    if (results[0].status === "fulfilled") setHealth(results[0].value);
    if (results[1].status === "fulfilled") setAiStats(results[1].value);
    if (results[2].status === "fulfilled") setVulnCount(results[2].value.total_vulns);
    if (results[3].status === "fulfilled") setScannerStats(results[3].value);
    if (results[4].status === "fulfilled") setBountyStats(results[4].value);
  }, []);

  useEffect(() => {
    pollActivity();
    pollStats();
    const a = setInterval(pollActivity, 5000);
    const s = setInterval(pollStats, 10000);
    return () => { clearInterval(a); clearInterval(s); };
  }, [pollActivity, pollStats]);

  // ── Auto-scroll ──
  useEffect(() => {
    if (autoScroll && logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [lines, autoScroll]);

  // ── Filtered & searched lines ──
  const filtered = lines.filter(l => {
    if (filter !== "all" && l.source !== filter) return false;
    if (search && !l.message.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  // ── Stats counters ──
  const counts = {
    scan: lines.filter(l => l.source === "scan").length,
    vuln: lines.filter(l => l.source === "vuln").length,
    recon: lines.filter(l => l.source === "recon").length,
    bounty: lines.filter(l => l.source === "bounty").length,
    errors: lines.filter(l => l.level === "error").length,
    apiTotal: apiCalls.length,
    apiErrors: apiCalls.filter(c => c.error || (c.status && c.status >= 400)).length,
    avgMs: apiCalls.length > 0
      ? Math.round(apiCalls.filter(c => c.ms).reduce((s, c) => s + (c.ms ?? 0), 0) / Math.max(apiCalls.filter(c => c.ms).length, 1))
      : 0,
  };

  const apis = health?.apis ?? [];

  return (
    <div className="space-y-3">
      {/* ── Header Bar ── */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3">
          <a href="/" className="text-xs text-[var(--muted)] hover:text-[var(--accent-light)] transition-colors">← Dashboard</a>
          <h1 className="text-lg font-bold gradient-text">API Logs & Monitoring</h1>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setPaused(p => !p)}
            className={`text-xs px-3 py-1.5 rounded-lg border transition-all ${
              paused
                ? "border-amber-500/30 bg-amber-500/10 text-amber-400"
                : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
            }`}>
            {paused ? "⏸ Paused" : "● Recording"}
          </button>
          <button onClick={() => setAutoScroll(a => !a)}
            className={`text-xs px-3 py-1.5 rounded-lg border transition-all ${
              autoScroll
                ? "border-blue-500/30 bg-blue-500/10 text-blue-400"
                : "border-[var(--border)] bg-[var(--card)] text-[var(--muted)]"
            }`}>
            {autoScroll ? "↓ Auto-scroll" : "↓ Manual"}
          </button>
        </div>
      </div>

      {/* ── Stats Row ── */}
      <div className="grid grid-cols-3 sm:grid-cols-5 lg:grid-cols-10 gap-2">
        {[
          { label: "Events", val: lines.length, c: "text-[var(--foreground)]", bg: "bg-white/[0.02] border-white/5" },
          { label: "Scans", val: counts.scan, c: "text-blue-400", bg: SOURCE_BG.scan },
          { label: "Vulns", val: counts.vuln, c: "text-orange-400", bg: SOURCE_BG.vuln },
          { label: "Recon", val: counts.recon, c: "text-cyan-400", bg: SOURCE_BG.recon },
          { label: "Bounty", val: counts.bounty, c: "text-emerald-400", bg: SOURCE_BG.bounty },
          { label: "Errors", val: counts.errors, c: counts.errors > 0 ? "text-red-400" : "text-[var(--muted)]", bg: counts.errors > 0 ? "bg-red-500/10 border-red-500/20" : "bg-white/[0.02] border-white/5" },
          { label: "API Calls", val: counts.apiTotal, c: "text-violet-400", bg: SOURCE_BG.api },
          { label: "API Errors", val: counts.apiErrors, c: counts.apiErrors > 0 ? "text-red-400" : "text-[var(--muted)]", bg: counts.apiErrors > 0 ? "bg-red-500/10 border-red-500/20" : "bg-white/[0.02] border-white/5" },
          { label: "Avg Latency", val: `${counts.avgMs}ms`, c: counts.avgMs > 500 ? "text-amber-400" : "text-emerald-400", bg: "bg-white/[0.02] border-white/5" },
          { label: "Circuit Brk", val: apis.filter(a => a.blocked).length, c: apis.some(a => a.blocked) ? "text-red-400" : "text-emerald-400", bg: apis.some(a => a.blocked) ? "bg-red-500/10 border-red-500/20" : "bg-emerald-500/10 border-emerald-500/20" },
        ].map(s => (
          <div key={s.label} className={`rounded-lg border p-2 text-center ${s.bg}`}>
            <div className={`text-lg font-bold tabular-nums ${s.c}`}>{s.val}</div>
            <div className="text-[8px] text-[var(--muted)] uppercase">{s.label}</div>
          </div>
        ))}
      </div>

      {/* ── Tab Navigation ── */}
      <div className="flex items-center gap-1 bg-[var(--card)] border border-[var(--border)] rounded-xl p-1 w-fit">
        {([
          { id: "activity" as const, label: "Activity Log", icon: "📋" },
          { id: "api" as const, label: "API Calls", icon: "🔌" },
          { id: "circuit" as const, label: "Circuit Breakers", icon: "⚡" },
        ]).map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`px-4 py-2 text-xs font-medium rounded-lg transition-all flex items-center gap-1.5 ${
              tab === t.id
                ? "bg-[var(--accent)]/15 text-[var(--accent-light)] shadow-sm shadow-[var(--accent)]/10"
                : "text-[var(--muted)] hover:text-[var(--foreground)] hover:bg-white/[0.02]"
            }`}><span>{t.icon}</span>{t.label}</button>
        ))}
      </div>

      {/* ── ACTIVITY LOG TAB ── */}
      {tab === "activity" && (
        <div className="rounded-xl border border-[var(--border)] bg-[var(--card)] overflow-hidden">
          {/* Toolbar */}
          <div className="flex items-center gap-2 p-2 border-b border-[var(--border)] flex-wrap">
            <div className="flex gap-0.5 bg-[var(--background)] rounded-lg p-0.5">
              {(["all", "scan", "vuln", "recon", "bounty", "system"] as const).map(f => (
                <button key={f} onClick={() => setFilter(f)}
                  className={`text-[10px] font-medium px-2.5 py-1 rounded-md transition-all ${
                    filter === f
                      ? `${SOURCE_BG[f] || "bg-[var(--accent)]/15"} ${SOURCE_COLORS[f] || "text-[var(--accent-light)]"} border`
                      : "text-[var(--muted)] hover:text-[var(--foreground)]"
                  }`}>
                  {f === "all" ? "All" : f.charAt(0).toUpperCase() + f.slice(1)}
                </button>
              ))}
            </div>
            <input
              type="text"
              placeholder="Search logs..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="!text-xs !py-1 !px-3 !rounded-lg !border-[var(--border)] !bg-[var(--background)] w-48"
            />
            <div className="flex-1" />
            <span className="text-[10px] text-[var(--muted)] tabular-nums">{filtered.length} / {lines.length} entries</span>
            <button onClick={() => { setLines([]); seenKeys.current.clear(); }}
              className="text-[10px] text-red-400 hover:text-red-300 px-2 py-1 rounded-lg hover:bg-red-500/10 transition-all">
              Clear
            </button>
          </div>

          {/* Log entries */}
          <div className="h-[60vh] overflow-y-auto hide-scrollbar font-mono text-[11px]">
            {filtered.length === 0 ? (
              <div className="flex items-center justify-center h-full text-[var(--muted)] text-sm">
                {paused ? "⏸ Logging paused" : "Waiting for events..."}
              </div>
            ) : (
              <table className="w-full">
                <thead className="sticky top-0 bg-[var(--card)] z-10">
                  <tr className="text-[9px] text-[var(--muted)] uppercase tracking-wider">
                    <th className="text-left py-1.5 px-2 w-16">Time</th>
                    <th className="text-left py-1.5 px-2 w-14">Source</th>
                    <th className="text-left py-1.5 px-2 w-12">Level</th>
                    <th className="text-left py-1.5 px-2">Message</th>
                    <th className="text-left py-1.5 px-2 w-20">IP</th>
                    <th className="text-left py-1.5 px-2 w-10">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.slice().reverse().map(line => (
                    <tr key={line.id} className="hover:bg-white/[0.015] transition-colors border-t border-[var(--border)]/30">
                      <td className="py-1 px-2 text-[var(--muted)] tabular-nums whitespace-nowrap">
                        <span className="text-[9px]">{formatDate(line.ts)}</span>{" "}
                        {formatTime(line.ts)}
                      </td>
                      <td className="py-1 px-2">
                        <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border ${SOURCE_BG[line.source]} ${SOURCE_COLORS[line.source]}`}>
                          {line.source}
                        </span>
                      </td>
                      <td className="py-1 px-2">
                        <span className={`text-[10px] ${LEVEL_COLORS[line.level]}`}>
                          {line.level === "error" ? "●" : line.level === "warn" ? "▲" : line.level === "success" ? "✓" : "○"} {line.level}
                        </span>
                      </td>
                      <td className={`py-1 px-2 ${LEVEL_COLORS[line.level]} break-all`}>{line.message}</td>
                      <td className="py-1 px-2 text-[var(--muted)] tabular-nums">{line.ip || "–"}</td>
                      <td className="py-1 px-2">
                        {line.riskLevel && (
                          <span className={`text-[9px] font-bold px-1 py-0.5 rounded sev-${line.riskLevel}`}>{line.riskLevel}</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <div ref={logEndRef} />
          </div>
        </div>
      )}

      {/* ── API CALLS TAB ── */}
      {tab === "api" && (
        <div className="rounded-xl border border-[var(--border)] bg-[var(--card)] overflow-hidden">
          <div className="flex items-center justify-between p-2 border-b border-[var(--border)]">
            <span className="text-[10px] text-[var(--muted)] uppercase font-semibold">Frontend → Backend API Calls</span>
            <div className="flex items-center gap-3 text-[10px] tabular-nums">
              <span className="text-emerald-400">{apiCalls.filter(c => c.status && c.status < 400).length} ok</span>
              <span className="text-red-400">{counts.apiErrors} err</span>
              <span className="text-[var(--muted)]">avg {counts.avgMs}ms</span>
            </div>
          </div>

          <div className="h-[60vh] overflow-y-auto hide-scrollbar font-mono text-[11px]">
            <table className="w-full">
              <thead className="sticky top-0 bg-[var(--card)] z-10">
                <tr className="text-[9px] text-[var(--muted)] uppercase tracking-wider">
                  <th className="text-left py-1.5 px-2 w-16">Time</th>
                  <th className="text-left py-1.5 px-2 w-12">Method</th>
                  <th className="text-left py-1.5 px-2">Path</th>
                  <th className="text-right py-1.5 px-2 w-12">Status</th>
                  <th className="text-right py-1.5 px-2 w-14">Latency</th>
                  <th className="text-left py-1.5 px-2 w-24">Error</th>
                </tr>
              </thead>
              <tbody>
                {apiCalls.map(call => {
                  const isErr = call.error || (call.status && call.status >= 400);
                  const isSlow = (call.ms ?? 0) > 1000;
                  return (
                    <tr key={call.id} className={`hover:bg-white/[0.015] transition-colors border-t border-[var(--border)]/30 ${isErr ? "bg-red-500/[0.03]" : ""}`}>
                      <td className="py-1 px-2 text-[var(--muted)] tabular-nums whitespace-nowrap">{formatTime(call.ts)}</td>
                      <td className="py-1 px-2">
                        <span className={`font-bold ${call.method === "GET" ? "text-blue-400" : call.method === "POST" ? "text-amber-400" : call.method === "DELETE" ? "text-red-400" : "text-[var(--foreground)]"}`}>
                          {call.method}
                        </span>
                      </td>
                      <td className="py-1 px-2 text-[var(--foreground)] break-all">{call.path}</td>
                      <td className="py-1 px-2 text-right tabular-nums">
                        {call.status ? (
                          <span className={`font-bold ${call.status < 300 ? "text-emerald-400" : call.status < 400 ? "text-amber-400" : "text-red-400"}`}>
                            {call.status}
                          </span>
                        ) : (
                          <span className="text-[var(--muted)]">–</span>
                        )}
                      </td>
                      <td className={`py-1 px-2 text-right tabular-nums ${isSlow ? "text-amber-400 font-bold" : "text-[var(--muted)]"}`}>
                        {call.ms != null ? `${call.ms}ms` : "–"}
                      </td>
                      <td className="py-1 px-2 text-red-400 truncate text-[10px]">{call.error || ""}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {apiCalls.length === 0 && (
              <div className="flex items-center justify-center h-full text-[var(--muted)] text-sm">No API calls captured yet</div>
            )}
          </div>
        </div>
      )}

      {/* ── CIRCUIT BREAKERS TAB ── */}
      {tab === "circuit" && (
        <div className="space-y-3">
          {/* Circuit Breakers Grid */}
          <div className="rounded-xl border border-[var(--border)] bg-[var(--card)] p-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)] mb-3">API Circuit Breakers</h3>
            {apis.length > 0 ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                {apis.map(api => (
                  <div key={api.name} className={`rounded-lg border p-3 transition-all ${
                    api.blocked
                      ? "border-red-500/30 bg-red-500/5"
                      : "border-emerald-500/20 bg-emerald-500/5"
                  }`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-semibold text-[var(--foreground)]">{api.name}</span>
                      <span className={`w-2.5 h-2.5 rounded-full ${api.blocked ? "bg-red-500 animate-pulse" : "bg-emerald-500"}`} />
                    </div>
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="text-[var(--muted)]">Status</span>
                      <span className={`font-bold ${api.blocked ? "text-red-400" : "text-emerald-400"}`}>
                        {api.blocked ? "BLOCKED" : "HEALTHY"}
                      </span>
                    </div>
                    {api.blocked && (
                      <>
                        <div className="flex items-center justify-between text-[10px] mt-1">
                          <span className="text-[var(--muted)]">Cooldown</span>
                          <span className="text-amber-400 font-semibold tabular-nums">{api.remaining_seconds}s remaining</span>
                        </div>
                        <div className="mt-2">
                          <div className="w-full h-1.5 rounded-full bg-red-500/20 overflow-hidden">
                            <div className="h-full rounded-full bg-red-500 transition-all duration-1000"
                              style={{ width: `${Math.max(0, (1 - api.remaining_seconds / Math.max(api.cooldown, 1)) * 100)}%` }} />
                          </div>
                        </div>
                        {api.blocked_since && (
                          <div className="text-[9px] text-[var(--muted)] mt-1">Blocked since: {api.blocked_since}</div>
                        )}
                      </>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs text-[var(--muted)] text-center py-8">No circuit breakers configured</div>
            )}
          </div>

          {/* System Status */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
            {/* Health */}
            <div className="rounded-xl border border-[var(--border)] bg-[var(--card)] p-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)] mb-3">System Health</h3>
              <div className="space-y-2">
                {[
                  { label: "Network Scanner", val: health?.network_scanner_enabled ? "ON" : "OFF", c: health?.network_scanner_enabled ? "text-emerald-400" : "text-red-400" },
                  { label: "Workers", val: health?.workers ?? 0, c: "text-blue-400" },
                  { label: "Scan Interval", val: `${health?.scan_interval ?? 0}s`, c: "text-[var(--foreground)]" },
                  { label: "Total Vulns", val: vulnCount, c: "text-amber-400" },
                  { label: "Programs", val: bountyStats?.programs ?? 0, c: "text-[var(--accent-light)]" },
                  { label: "Alive Targets", val: bountyStats?.alive_targets ?? 0, c: "text-emerald-400" },
                ].map(item => (
                  <div key={item.label} className="flex items-center justify-between text-xs">
                    <span className="text-[var(--muted)]">{item.label}</span>
                    <span className={`font-semibold tabular-nums ${item.c}`}>{item.val}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* AI Status */}
            <div className="rounded-xl border border-[var(--border)] bg-[var(--card)] p-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-fuchsia-400 mb-3">AI Analyzer</h3>
              {aiStats ? (
                <div className="space-y-2">
                  {[
                    { label: "Status", val: aiStats.enabled ? "Active" : "Disabled", c: aiStats.enabled ? "text-emerald-400" : "text-red-400" },
                    { label: "Provider", val: aiStats.provider || "–", c: "text-[var(--foreground)]" },
                    { label: "Model", val: aiStats.model || "–", c: "text-fuchsia-400" },
                    { label: "Requests", val: aiStats.requests, c: "text-[var(--foreground)]" },
                    { label: "Reports", val: aiStats.reports_generated, c: "text-violet-400" },
                    { label: "Classified", val: aiStats.findings_classified, c: "text-cyan-400" },
                    { label: "Tokens Used", val: aiStats.tokens_used.toLocaleString(), c: "text-amber-400" },
                    { label: "Errors", val: aiStats.errors, c: aiStats.errors > 0 ? "text-red-400" : "text-[var(--muted)]" },
                  ].map(item => (
                    <div key={item.label} className="flex items-center justify-between text-xs">
                      <span className="text-[var(--muted)]">{item.label}</span>
                      <span className={`font-semibold tabular-nums ${item.c}`}>{item.val}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-[var(--muted)] text-center py-4">Not configured</div>
              )}
            </div>

            {/* Scanner Stats */}
            <div className="rounded-xl border border-[var(--border)] bg-[var(--card)] p-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--accent-light)] mb-3">Scanners</h3>
              <div className="space-y-2">
                {[
                  { label: "IDOR Found", val: scannerStats?.idor?.idor_found ?? 0, c: "text-red-400" },
                  { label: "SSRF Found", val: scannerStats?.ssrf?.ssrf_found ?? 0, c: "text-orange-400" },
                  { label: "GraphQL", val: scannerStats?.graphql?.vulns_found ?? 0, c: "text-pink-400" },
                  { label: "Race Cond.", val: scannerStats?.race_condition?.race_conditions_found ?? 0, c: "text-yellow-400" },
                  { label: "Blind (OOB)", val: scannerStats?.interactsh?.blind_vulns_confirmed ?? 0, c: "text-purple-400" },
                  { label: "CT New Subs", val: scannerStats?.ct_monitor?.new_subdomains_found ?? 0, c: "text-sky-400" },
                  { label: "CVE Templates", val: scannerStats?.cve_monitor?.templates_generated ?? 0, c: "text-teal-400" },
                ].map(item => (
                  <div key={item.label} className="flex items-center justify-between text-xs">
                    <span className="text-[var(--muted)]">{item.label}</span>
                    <span className={`font-semibold tabular-nums ${item.c}`}>{item.val}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
