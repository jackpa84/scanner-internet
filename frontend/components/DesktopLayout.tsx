"use client";

import { useEffect, useState, useCallback, useRef, createContext, useContext } from "react";
import { usePathname } from "next/navigation";
import { useAuth } from "./AuthProvider";
import LoginScreen from "./LoginScreen";
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
  const { authenticated } = useAuth();
  const originalFetchRef = useRef<typeof fetch | null>(null);

  useEffect(() => {
    // Only intercept if authenticated
    if (!authenticated || originalFetchRef.current) return;
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
        originalFetchRef.current = null;
      }
    };
  }, [addLog, authenticated]);
}

/* ═══════════════════════════════════════════════════════════════
   Backend activity poller
   ═══════════════════════════════════════════════════════════════ */

function useBackendActivity() {
  const { addLog } = useLogs();
  const { authenticated } = useAuth();
  const seenRef = useRef<Set<string>>(new Set());

  const poll = useCallback(async () => {
    // Only poll if authenticated
    if (!authenticated) return;
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
  }, [addLog, authenticated]);

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
      {/* Sidebar panel - mobile fixed, desktop static */}
      <aside className={`fixed md:static right-0 top-0 bottom-0 z-40 md:z-30 bg-[var(--card)]/95 backdrop-blur-md border-l border-[var(--border)] flex flex-col transition-all duration-200 ${
        open ? "w-72 sm:w-80 opacity-100" : "w-0 opacity-0 overflow-hidden"
      }`}>
        {/* Header */}
        <div className="shrink-0 p-2 border-b border-[var(--border)] flex items-center justify-between">
          <div className="flex items-center gap-1.5 min-w-0">
            <span className="relative flex h-1.5 w-1.5 flex-shrink-0">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500" />
            </span>
            <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--muted)] whitespace-nowrap">Live Logs</span>
          </div>
          {/* Close button on mobile */}
          <button onClick={onToggle} className="md:hidden p-1 text-[var(--muted)] hover:text-[var(--foreground)]">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Stats */}
        <div className="shrink-0 px-2 py-1.5 text-[9px] flex gap-1 tabular-nums flex-wrap">
          <span className="text-blue-400">{apiCount} api</span>
          <span className="text-cyan-400">{backendCount} events</span>
          {errCount > 0 && <span className="text-red-400">{errCount} err</span>}
        </div>

        {/* Filter tabs */}
        <div className="shrink-0 px-2 pb-2">
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

/* ═══════════════════════════════════════════════════════════════
   Nav config
   ═══════════════════════════════════════════════════════════════ */

const NAV_GROUPS = [
  {
    label: "Principal",
    items: [
      {
        href: "/",
        label: "Dashboard",
        icon: (
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.75} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" />
          </svg>
        ),
      },
    ],
  },
  {
    label: "Bug Bounty",
    items: [
      {
        href: "/ai",
        label: "AI Analysis",
        icon: (
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.75} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.455 2.456L21.75 6l-1.036.259a3.375 3.375 0 00-2.455 2.456zM16.894 20.567L16.5 21.75l-.394-1.183a2.25 2.25 0 00-1.423-1.423L13.5 18.75l1.183-.394a2.25 2.25 0 001.423-1.423l.394-1.183.394 1.183a2.25 2.25 0 001.423 1.423l1.183.394-1.183.394a2.25 2.25 0 00-1.423 1.423z" />
          </svg>
        ),
      },
      {
        href: "/hackerone",
        label: "HackerOne",
        icon: (
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.75} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 12.75c1.148 0 2.278.08 3.383.237 1.037.146 1.866.966 1.866 2.013 0 3.728-2.35 6.75-5.25 6.75S6.75 18.728 6.75 15c0-1.046.83-1.867 1.866-2.013A24.204 24.204 0 0112 12.75zm0 0c2.883 0 5.647.508 8.207 1.44a23.91 23.91 0 01-1.152 6.06M12 12.75c-2.883 0-5.647.508-8.208 1.44.125 2.104.52 4.136 1.153 6.06M12 12.75a2.25 2.25 0 002.248-2.354M12 12.75a2.25 2.25 0 01-2.248-2.354M12 8.25c.995 0 1.971-.08 2.922-.236.403-.066.74-.358.795-.762a3.778 3.778 0 00-.399-2.25M12 8.25c-.995 0-1.97-.08-2.922-.236-.402-.066-.74-.358-.795-.762a3.734 3.734 0 01.4-2.253M12 8.25a2.25 2.25 0 00-2.248 2.146M12 8.25a2.25 2.25 0 012.248 2.146M8.683 5a6.032 6.032 0 01-1.155-1.002c.07-.63.27-1.222.574-1.747m.581 2.749A3.75 3.75 0 0115.318 5m0 0c.427-.283.815-.62 1.155-.999a4.471 4.471 0 00-.575-1.752M4.921 6a24.048 24.048 0 00-.392 3.314c1.668.546 3.416.914 5.223 1.082M19.08 6c.205 1.08.337 2.187.392 3.314a23.882 23.882 0 01-5.223 1.082" />
          </svg>
        ),
      },
      {
        href: "/watcher",
        label: "Platform Watcher",
        icon: (
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.75} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
        ),
      },
      {
        href: "/bughunt",
        label: "BugHunt",
        icon: (
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.75} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
          </svg>
        ),
      },
    ],
  },
  {
    label: "Sistema",
    items: [
      {
        href: "/guia",
        label: "Guia & Fluxo",
        icon: (
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.75} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 016 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0018 18a8.967 8.967 0 00-6 2.292m0-14.25v14.25" />
          </svg>
        ),
      },
      {
        href: "/logs",
        label: "Logs",
        icon: (
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.75} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z" />
          </svg>
        ),
      },
    ],
  },
];

function NavSidebar({ health }: { health: HealthInfo | null }) {
  const pathname = usePathname();
  const { logout } = useAuth();
  const ss = health?.scan_stats;

  return (
    <aside className="hidden md:flex md:w-48 shrink-0 h-full border-r border-[var(--border)] bg-[var(--card)]/60 flex-col z-40">
      {/* Logo */}
      <div className="h-14 shrink-0 flex items-center gap-2.5 px-4 border-b border-[var(--border)]">
        <div className="flex h-8 w-8 items-center justify-center rounded-xl bg-[var(--accent)]/15">
          <svg className="w-4 h-4 text-[var(--accent-light)]" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
          </svg>
        </div>
        <div>
          <div className="text-sm font-bold tracking-tight leading-none text-[var(--foreground)]">Scanner</div>
          <div className="text-[10px] text-[var(--accent-light)] font-medium mt-0.5">Bounty</div>
        </div>
      </div>

      {/* Nav groups */}
      <nav className="flex-1 overflow-y-auto hide-scrollbar px-2 py-3 space-y-4">
        {NAV_GROUPS.map(group => (
          <div key={group.label}>
            <div className="px-2 mb-1 text-[9px] font-bold uppercase tracking-widest text-[var(--muted)]">
              {group.label}
            </div>
            <ul className="space-y-0.5">
              {group.items.map(item => {
                const active = pathname === item.href;
                return (
                  <li key={item.href}>
                    <a
                      href={item.href}
                      className={`flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-xs font-medium transition-all ${
                        active
                          ? "bg-[var(--accent)]/15 text-[var(--accent-light)]"
                          : "text-[var(--muted)] hover:text-[var(--foreground)] hover:bg-white/[0.03]"
                      }`}
                    >
                      <span className={active ? "text-[var(--accent-light)]" : "text-[var(--muted)]"}>
                        {item.icon}
                      </span>
                      {item.label}
                    </a>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* Bottom: stats + live + logout */}
      <div className="shrink-0 border-t border-[var(--border)] px-3 py-3 space-y-2">
        {/* LIVE indicator */}
        <div className="flex items-center gap-1.5">
          <span className="relative flex h-1.5 w-1.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500" />
          </span>
          <span className="text-[10px] text-emerald-400 font-bold uppercase tracking-wider">Live</span>
        </div>

        {/* Health stats */}
        {health && (
          <div className="space-y-1 text-[10px] text-[var(--muted)]">
            {health.network_scanner_enabled && ss && (
              <div className="flex justify-between">
                <span>Rede</span>
                <span className="tabular-nums text-blue-400 font-semibold">
                  {(ss.alive ?? 0).toLocaleString()}/{(ss.tested ?? 0).toLocaleString()}
                </span>
              </div>
            )}
            <div className="flex justify-between">
              <span>Workers</span>
              <span className="tabular-nums text-[var(--foreground)] font-semibold">{health.workers}</span>
            </div>
          </div>
        )}

        {/* Logout */}
        <button
          onClick={logout}
          className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-[11px] text-[var(--muted)] hover:text-red-400 hover:bg-red-500/5 transition-all"
          title="Sair"
        >
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" strokeWidth={1.75} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9" />
          </svg>
          Sair
        </button>
      </div>
    </aside>
  );
}

function LayoutInner({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { authenticated, loading } = useAuth();
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [now, setNow] = useState<Date | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [hydrated, setHydrated] = useState(false);
  const [loadTimeout, setLoadTimeout] = useState(false);

  // ALL hooks must be called unconditionally at top level, BEFORE any conditionals
  useFetchInterceptor();
  useBackendActivity();

  const loadHealth = useCallback(async () => {
    try {
      const h = await fetchHealth();
      setHealth(h);
    } catch { /* ignore */ }
  }, []);

  // Hydration effect
  useEffect(() => {
    setHydrated(true);
  }, []);

  // Loading timeout — prevent infinite spinner
  useEffect(() => {
    const timer = setTimeout(() => setLoadTimeout(true), 8000);
    return () => clearTimeout(timer);
  }, []);

  // Health polling effect
  useEffect(() => {
    if (!authenticated) return;
    loadHealth();
    const id = setInterval(() => {
      loadHealth();
    }, 8000);
    return () => clearInterval(id);
  }, [authenticated, loadHealth]);

  // Clock effect
  useEffect(() => {
    setNow(new Date());
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  // Now conditionally render based on state
  if (!hydrated || loading) {
    // If loading takes too long, force show login
    if (loadTimeout) {
      return <LoginScreen />;
    }
    return (
      <div className="h-screen flex flex-col items-center justify-center gap-4" style={{ background: '#05080f' }}>
        <div className="animate-spin w-8 h-8 rounded-full" style={{
          border: '2px solid rgba(99, 102, 241, 0.2)',
          borderTopColor: '#818cf8',
        }} />
        <span style={{ color: '#5a6a80', fontSize: 13 }}>Carregando...</span>
      </div>
    );
  }

  if (!authenticated) {
    return <LoginScreen />;
  }

  const apis = health?.apis ?? [];
  const blockedCount = apis.filter(a => a.blocked).length;

  // Current page label for topbar breadcrumb
  const currentPage = NAV_GROUPS.flatMap(g => g.items).find(i => i.href === pathname);

  return (
    <div className="h-screen bg-[var(--background)] text-[var(--foreground)] flex overflow-hidden">
      {/* Left sidebar nav */}
      <NavSidebar health={health} />

      {/* Right side: topbar + content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top bar */}
        <header className="h-10 md:h-10 shrink-0 border-b border-[var(--border)] bg-[var(--card)]/60 backdrop-blur-sm flex items-center px-3 md:px-4 gap-2 md:gap-3 z-50 overflow-x-auto">
          {/* Mobile menu icon/breadcrumb placeholder */}
          <span className="text-xs md:text-xs font-semibold text-[var(--foreground)] truncate flex-shrink-0">
            {currentPage?.label ?? "Scanner"}
          </span>

          <div className="flex-1 min-w-0" />

          {/* API circuit breaker dots - hide on mobile if space constrained */}
          {apis.length > 0 && (
            <div className="hidden sm:flex items-center gap-1 flex-shrink-0">
              {apis.slice(0, 3).map((api) => (
                <div
                  key={api.name}
                  title={`${api.name}${api.blocked ? ` (blocked ${api.remaining_seconds}s)` : ""}`}
                  className={`h-1.5 w-1.5 rounded-full ${api.blocked ? "bg-red-500 animate-pulse" : "bg-emerald-500"}`}
                />
              ))}
              {blockedCount > 0 && (
                <span className="text-[10px] text-red-400 font-bold ml-1">{blockedCount}</span>
              )}
            </div>
          )}

          {apis.length > 0 && <div className="hidden sm:block h-3.5 w-px bg-[var(--border)] flex-shrink-0" />}

          {/* Clock - hide on very small screens */}
          <span className="hidden xs:inline text-[11px] text-[var(--muted)] tabular-nums font-mono flex-shrink-0">
            {now ? now.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "--:--:--"}
          </span>

          <div className="hidden xs:block h-3.5 w-px bg-[var(--border)] flex-shrink-0" />

          {/* Log toggle */}
          <button
            onClick={() => setSidebarOpen(v => !v)}
            className={`flex items-center gap-1 px-2 py-1 rounded-md text-[10px] md:text-[11px] font-medium transition-all whitespace-nowrap flex-shrink-0 ${
              sidebarOpen ? "bg-[var(--accent)]/10 text-[var(--accent-light)]" : "text-[var(--muted)] hover:text-[var(--foreground)]"
            }`}
            title="Toggle Logs"
          >
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z" />
            </svg>
            <span className="hidden sm:inline">Logs</span>
          </button>
        </header>

        {/* Main content */}
        <div className="flex-1 flex overflow-hidden relative">
          <main className={`flex-1 overflow-y-auto hide-scrollbar transition-all duration-200 ${sidebarOpen ? "mr-0 md:mr-80" : ""}`}>
            <div className="min-h-full p-2.5 sm:p-3 md:p-4 lg:p-5">
              {children}
            </div>
          </main>

          <LogSidebar open={sidebarOpen} onToggle={() => setSidebarOpen(v => !v)} />
        </div>
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
