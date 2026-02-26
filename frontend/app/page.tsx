"use client";

import { Component, type ReactNode, useEffect, useState, useCallback } from "react";
import BountyPanel from "@/components/BountyPanel";
import VulnPanel from "@/components/VulnPanel";
import { fetchHealth, type HealthInfo } from "@/lib/api";

class ErrorBoundary extends Component<{ children: ReactNode }, { error: string | null }> {
  state = { error: null as string | null };
  static getDerivedStateFromError(err: Error) {
    return { error: err.message };
  }
  render() {
    if (this.state.error) {
      return (
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-300">
          Erro no componente: {this.state.error}
        </div>
      );
    }
    return this.props.children;
  }
}

function StatusBar() {
  const [health, setHealth] = useState<HealthInfo | null>(null);

  const load = useCallback(async () => {
    try {
      setHealth(await fetchHealth());
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [load]);

  if (!health) return null;

  const blocked = health.apis.filter((a) => a.blocked);
  const ss = health.scan_stats;
  const hitRate = ss && ss.tested > 0 ? ((ss.alive / ss.tested) * 100).toFixed(1) : "0";

  return (
    <div className="mb-4 space-y-2">
      {/* API Status */}
      <div className="flex flex-wrap gap-1.5">
        {health.apis.map((api) => (
          <div
            key={api.name}
            className={`rounded-lg border px-2.5 py-1.5 text-[11px] ${
              api.blocked
                ? "border-red-500/40 bg-red-500/10"
                : "border-emerald-500/30 bg-emerald-500/5"
            }`}
          >
            <div className="flex items-center gap-1.5">
              <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${api.blocked ? "bg-red-500 animate-pulse" : "bg-emerald-500"}`} />
              <span className="font-semibold">{api.name}</span>
              {api.blocked ? (
                <span className="text-red-400 font-bold">{api.remaining_seconds}s</span>
              ) : (
                <span className="text-emerald-400 font-semibold">OK</span>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Blocked alert */}
      {blocked.length > 0 && (
        <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-300">
          <span className="font-bold">BLOQUEADO:</span>{" "}
          {blocked.map((b) => `${b.name} (${b.remaining_seconds}s)`).join(", ")}
          <span className="text-red-400/70 ml-2">— rate limit 429, cooldown automático</span>
        </div>
      )}

      {/* Scanner stats */}
      {health.network_scanner_enabled && ss && (
        <div className="flex flex-wrap gap-2 text-[11px]">
          <div className="rounded border border-slate-700/50 bg-slate-800/40 px-2 py-1">
            <span className="text-slate-300 font-bold">{health.workers}</span>
            <span className="text-slate-500 ml-1">workers</span>
          </div>
          <div className="rounded border border-slate-700/50 bg-slate-800/40 px-2 py-1">
            <span className="text-slate-300 font-bold">{ss.tested.toLocaleString("pt-BR")}</span>
            <span className="text-slate-500 ml-1">testados</span>
          </div>
          <div className="rounded border border-emerald-500/30 bg-emerald-500/5 px-2 py-1">
            <span className="text-emerald-400 font-bold">{ss.alive.toLocaleString("pt-BR")}</span>
            <span className="text-slate-500 ml-1">vivos ({hitRate}%)</span>
          </div>
          <div className="rounded border border-sky-500/30 bg-sky-500/5 px-2 py-1">
            <span className="text-sky-400 font-bold">{ss.saved.toLocaleString("pt-BR")}</span>
            <span className="text-slate-500 ml-1">salvos</span>
          </div>
          <div className="rounded border border-red-500/30 bg-red-500/5 px-2 py-1">
            <span className="text-red-400 font-bold">{ss.dead.toLocaleString("pt-BR")}</span>
            <span className="text-slate-500 ml-1">mortos</span>
          </div>
        </div>
      )}
    </div>
  );
}

export default function Home() {
  return (
    <>
      <StatusBar />

      <ErrorBoundary>
        <BountyPanel />
      </ErrorBoundary>

      <section className="mt-5 sm:mt-6">
        <ErrorBoundary>
          <VulnPanel />
        </ErrorBoundary>
      </section>
    </>
  );
}
