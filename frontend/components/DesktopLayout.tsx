"use client";

import { useEffect, useState, useCallback, useRef, createContext, useContext } from "react";
import { usePathname } from "next/navigation";
import { useAuth } from "./AuthProvider";
import { fetchHealth, fetchDbActivity, type HealthInfo, type DbActivityEntry } from "@/lib/api";

/* ═══════════════════════════════════════════════════════════════
   Log context — captures frontend API calls + backend activity
   ═══════════════════════════════════════════════════════════════ */

export interface LogEntry {
  id: number;
  timestamp: Date;
  type: "api_req" | "api_res" | "api_err" | "scan" | "vuln" | "recon" | "system";
  method?: string;
  path?: string;
  status?: number;
  ms?: number;
  message: string;
  color: string;
}

interface LogContextType {
  logs: LogEntry[];
  addLog: (entry: Omit<LogEntry, "id" | "timestamp">) => void;
}

const LogContext = createContext<LogContextType>({ logs: [], addLog: () => {} });
export const useLogs = () => useContext(LogContext);

let _logId = 0;
const MAX_LOGS = 200;

function LogProvider({ children }: { children: React.ReactNode }) {
  const [logs, setLogs] = useState<LogEntry[]>([]);

  const addLog = useCallback((entry: Omit<LogEntry, "id" | "timestamp">) => {
    setLogs(prev => {
      const next = [{ ...entry, id: ++_logId, timestamp: new Date() }, ...prev];
      return next.length > MAX_LOGS ? next.slice(0, MAX_LOGS) : next;
    });
  }, []);

  return <LogContext.Provider value={{ logs, addLog }}>{children}</LogContext.Provider>;
}

/* ═══════════════════════════════════════════════════════════════
   Intercept fetch to capture API logs
   ═══════════════════════════════════════════════════════════════ */

function useFetchInterceptor() {
  const { addLog } = useLogs();
  const originalFetchRef = useRef<typeof fetch | null>(null);

  useEffect(() => {
    if (originalFetchRef.current) return;
    originalFetchRef.current = window.fetch;

    window.fetch = async function (...args) {
      const url = typeof args[0] === "string" ? args[0] : (args[0] as Request)?.url ?? "";
      const opts = (args[1] as RequestInit) ?? {};
      const method = (opts.method || "GET").toUpperCase();

      const isApi = url.includes("/api/");
      if (!isApi) return originalFetchRef.current!.apply(this, args);

      const path = url.replace(/^https?:\/\/[^/]+/, "").split("?")[0];
      const shortPath = path.replace("/api/", "");

      addLog({
        type: "api_req",
        method,
        path: shortPath,
        message: `${method} ${shortPath}`,
        color: method === "GET" ? "text-blue-400" : "text-amber-400",
      });

      const t0 = performance.now();
      try {
        const res = await originalFetchRef.current!.apply(this, args);
        const ms = Math.round(performance.now() - t0);

        if (res.ok) {
          addLog({
            type: "api_res",
            method,
            path: shortPath,
            status: res.status,
            ms,
            message: `${res.status} ${shortPath} (${ms}ms)`,
            color: "text-emerald-400",
          });
        } else {
          addLog({
            type: "api_err",
            method,
            path: shortPath,
            status: res.status,
            ms,
            message: `${res.status} ${shortPath} (${ms}ms)`,
            color: "text-red-400",
          });
        }
        return res;
      } catch (err: any) {
        const ms = Math.round(performance.now() - t0);
        addLog({
          type: "api_err",
          method,
          path: shortPath,
          ms,
          message: `ERR ${shortPath}: ${err.message?.slice(0, 60)}`,
          color: "text-red-500",
        });
        throw err;
      }
    };

    return () => {
      if (originalFetchRef.current) {
        window.fetch = originalFetchRef.current;
      }
    };
  }, [addLog]);
}

/* ═══════════════════════════════════════════════════════════════
   Backend activity poller
   ═══════════════════════════════════════════════════════════════ */

function useBackendActivity() {
  const { addLog } = useLogs();
  const seenRef = useRef<Set<string>>(new Set());

  const poll = useCallback(async () => {
    try {
      const data = await fetchDbActivity(15);
      if (!data?.activity) return;
      for (const entry of data.activity) {
        const key = `${entry.collection}:${entry.timestamp}:${entry.summary?.slice(0, 30)}`;
        if (seenRef.current.has(key)) continue;
        seenRef.current.add(key);
        if (seenRef.current.size > 500) {
          const arr = [...seenRef.current];
          seenRef.current = new Set(arr.slice(-300));
        }

        const typeMap: Record<string, LogEntry["type"]> = {
          scan: "scan",
          vuln: "vuln",
          recon: "recon",
        };
        const colorMap: Record<string, string> = {
          scan: "text-blue-300",
          vuln: "text-orange-400",
          recon: "text-cyan-400",
        };

        addLog({
          type: typeMap[entry.action] || "system",
          message: entry.summary || entry.action,
          color: colorMap[entry.action] || "text-slate-400",
        });
      }
    } catch { /* ignore */ }
  }, [addLog]);

  useEffect(() => {
    poll();
    const id = setInterval(poll, 20000);
    return () => clearInterval(id);
  }, [poll]);
}

/* ═══════════════════════════════════════════════════════════════
   Log Sidebar
   ═══════════════════════════════════════════════════════════════ */

const TYPE_ICONS: Record<string, string> = {
  api_req: "→",
  api_res: "←",
  api_err: "✕",
  scan: "◉",
  vuln: "⚠",
  recon: "◈",
  system: "●",
};

const TYPE_LABELS: Record<string, string> = {
  api_req: "REQ",
  api_res: "RES",
  api_err: "ERR",
  scan: "SCAN",
  vuln: "VULN",
  recon: "RECON",
  system: "SYS",
};

function LogSidebar({ open, onToggle }: { open: boolean; onToggle: () => void }) {
  const { logs } = useLogs();
  const [filter, setFilter] = useState<"all" | "api" | "backend">("all");
  const listRef = useRef<HTMLDivElement>(null);

  const filtered = logs.filter(l => {
    if (filter === "api") return l.type === "api_req" || l.type === "api_res" || l.type === "api_err";
    if (filter === "backend") return l.type === "scan" || l.type === "vuln" || l.type === "recon";
    return true;
  });

  const apiCount = logs.filter(l => l.type.startsWith("api")).length;
  const errCount = logs.filter(l => l.type === "api_err").length;
  const backendCount = logs.filter(l => ["scan", "vuln", "recon"].includes(l.type)).length;

  return (
    <>
      {/* Toggle button */}
      <button
        onClick={onToggle}
        className={`fixed right-0 top-14 z-40 flex items-center gap-1 px-2 py-3 rounded-l-lg border border-r-0 border-[var(--border)] transition-all ${
          open ? "bg-[var(--accent)]/10 text-[var(--accent-light)]" : "bg-[var(--card)] text-[var(--muted)] hover:text-[var(--foreground)]"
        }`}
        title="Toggle Logs"
      >
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z" />
        </svg>
        {errCount > 0 && (
          <span className="flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 text-[9px] font-bold text-white px-1">
            {errCount}
          </span>
        )}
      </button>

      {/* Sidebar panel */}
      <aside className={`fixed right-0 top-11 bottom-0 z-30 bg-[var(--card)]/95 backdrop-blur-md border-l border-[var(--border)] flex flex-col transition-all duration-200 ${
        open ? "w-80 opacity-100" : "w-0 opacity-0 overflow-hidden"
      }`}>
        {/* Header */}
        <div className="shrink-0 p-2 border-b border-[var(--border)]">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-1.5">
              <span className="relative flex h-1.5 w-1.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500" />
              </span>
              <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--muted)]">Live Logs</span>
            </div>
            <div className="flex items-center gap-2 text-[9px] tabular-nums">
              <span className="text-blue-400">{apiCount} api</span>
              <span className="text-cyan-400">{backendCount} events</span>
              {errCount > 0 && <span className="text-red-400">{errCount} err</span>}
            </div>
          </div>

          {/* Filter tabs */}
          <div className="flex gap-0.5 bg-[var(--background)] rounded-md p-0.5">
            {(["all", "api", "backend"] as const).map(f => (
              <button key={f} onClick={() => setFilter(f)}
                className={`flex-1 text-[10px] font-medium py-1 rounded transition-colors ${
                  filter === f ? "bg-[var(--accent)]/15 text-[var(--accent-light)]" : "text-[var(--muted)] hover:text-[var(--foreground)]"
                }`}>
                {f === "all" ? "All" : f === "api" ? "API" : "Backend"}
              </button>
            ))}
          </div>
        </div>

        {/* Log entries */}
        <div ref={listRef} className="flex-1 overflow-y-auto hide-scrollbar p-1">
          {filtered.length === 0 ? (
            <div className="text-center text-[var(--muted)] text-xs py-8">Waiting for events...</div>
          ) : (
            filtered.map(log => (
              <div key={log.id} className="flex gap-1.5 py-[3px] px-1.5 rounded hover:bg-white/[0.02] group">
                {/* Time */}
                <span className="text-[9px] text-[var(--muted)] tabular-nums font-mono shrink-0 pt-px w-12">
                  {log.timestamp.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                </span>

                {/* Type badge */}
                <span className={`text-[8px] font-bold uppercase tracking-wider shrink-0 pt-0.5 w-8 ${log.color}`}>
                  {TYPE_LABELS[log.type] || log.type}
                </span>

                {/* Message */}
                <span className={`text-[10px] leading-tight break-all min-w-0 ${
                  log.type === "api_err" ? "text-red-400" : "text-[var(--foreground)]/80"
                }`}>
                  {log.ms != null && (
                    <span className={`font-mono ${log.ms > 1000 ? "text-amber-400" : "text-[var(--muted)]"}`}>
                      {log.ms}ms{" "}
                    </span>
                  )}
                  {log.message}
                </span>
              </div>
            ))
          )}
        </div>

        {/* Footer */}
        <div className="shrink-0 p-1.5 border-t border-[var(--border)] flex items-center justify-between">
          <span className="text-[9px] text-[var(--muted)]">{filtered.length} entries</span>
          <span className="text-[9px] text-[var(--muted)]">max {MAX_LOGS}</span>
        </div>
      </aside>
    </>
  );
}

/* ═══════════════════════════════════════════════════════════════
   Layout wrapper
   ═══════════════════════════════════════════════════════════════ */

function LayoutInner({ children }: { children: React.ReactNode }) {
  const { logout } = useAuth();
  const pathname = usePathname();
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [now, setNow] = useState<Date | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useFetchInterceptor();
  useBackendActivity();

  const loadHealth = useCallback(async () => {
    try {
      const h = await fetchHealth();
      setHealth(h);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    loadHealth();
    const id = setInterval(loadHealth, 8000);
    return () => clearInterval(id);
  }, [loadHealth]);

  useEffect(() => {
    setNow(new Date());
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  const apis = health?.apis ?? [];
  const blockedCount = apis.filter(a => a.blocked).length;
  const ss = health?.scan_stats;

  return (
    <div className="h-screen bg-[var(--background)] text-[var(--foreground)] flex flex-col overflow-hidden">
      {/* Top Bar */}
      <header className="h-11 shrink-0 border-b border-[var(--border)] bg-[var(--card)]/80 backdrop-blur-sm flex items-center px-4 gap-4 z-50">
        <div className="flex items-center gap-2 mr-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-[var(--accent)]/15">
            <svg className="w-4 h-4 text-[var(--accent-light)]" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          </div>
          <span className="text-sm font-bold tracking-tight text-[var(--foreground)]">SCANNER</span>
          <span className="text-xs text-[var(--accent-light)] font-medium">BOUNTY</span>
        </div>

        <div className="h-4 w-px bg-[var(--border)]" />

        <div className="flex items-center gap-1.5">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
          </span>
          <span className="text-xs text-emerald-400 font-medium">LIVE</span>
        </div>

        <div className="h-4 w-px bg-[var(--border)]" />

        <nav className="flex items-center gap-1">
          {[
            { href: "/", label: "Dashboard" },
            { href: "/logs", label: "Logs" },
            { href: "/hackerone", label: "HackerOne" },
          ].map(link => (
            <a key={link.href} href={link.href}
              className={`text-xs px-2.5 py-1 rounded-md transition-all ${
                pathname === link.href
                  ? "bg-[var(--accent)]/15 text-[var(--accent-light)] font-medium"
                  : "text-[var(--muted)] hover:text-[var(--foreground)] hover:bg-white/[0.03]"
              }`}>{link.label}</a>
          ))}
        </nav>

        <div className="h-4 w-px bg-[var(--border)]" />

        {health && (
          <div className="flex items-center gap-3 text-xs">
            {health.network_scanner_enabled && ss && (
              <span className="text-[var(--muted)]">
                NET <span className="text-blue-400 font-semibold tabular-nums">{(ss.alive ?? 0).toLocaleString()}</span>
                <span className="text-[var(--border)]">/</span>
                <span className="tabular-nums">{(ss.tested ?? 0).toLocaleString()}</span>
              </span>
            )}
            <span className="text-[var(--muted)]">
              Workers <span className="text-[var(--foreground)] font-semibold tabular-nums">{health.workers}</span>
            </span>
          </div>
        )}

        {apis.length > 0 && (
          <>
            <div className="h-4 w-px bg-[var(--border)]" />
            <div className="flex items-center gap-1">
              {apis.map((api) => (
                <div key={api.name}
                  title={`${api.name}${api.blocked ? ` (blocked ${api.remaining_seconds}s)` : ""}`}
                  className={`h-1.5 w-1.5 rounded-full ${api.blocked ? "bg-red-500 animate-pulse" : "bg-emerald-500"}`} />
              ))}
              {blockedCount > 0 && <span className="text-xs text-red-400 font-semibold ml-1">{blockedCount}</span>}
            </div>
          </>
        )}

        <div className="flex-1" />

        <span className="text-xs text-[var(--muted)] tabular-nums font-mono">
          {now ? now.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "--:--:--"}
        </span>

        <div className="h-4 w-px bg-[var(--border)]" />

        <button onClick={logout} className="text-xs text-[var(--muted)] hover:text-red-400 transition-colors" title="Sair">
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9" />
          </svg>
        </button>
      </header>

      {/* Main content */}
      <div className="flex-1 flex overflow-hidden relative">
        <main className={`flex-1 overflow-y-auto hide-scrollbar transition-all duration-200 ${sidebarOpen ? "mr-80" : ""}`}>
          <div className="min-h-full p-3 xl:p-4">
            {children}
          </div>
        </main>

        <LogSidebar open={sidebarOpen} onToggle={() => setSidebarOpen(v => !v)} />
      </div>
    </div>
  );
}

export default function DesktopLayout({ children }: { children: React.ReactNode }) {
  return (
    <LogProvider>
      <LayoutInner>{children}</LayoutInner>
    </LogProvider>
  );
}
