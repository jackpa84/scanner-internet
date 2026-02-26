"use client";

import { Component, type ReactNode, useEffect, useState, useCallback } from "react";
import BountyPanel from "@/components/BountyPanel";
import VulnPanel from "@/components/VulnPanel";
import {
  fetchHealth,
  fetchBountyStats,
  fetchVulnStats,
  type HealthInfo,
  type BountyStats,
  type VulnStats,
} from "@/lib/api";

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

function DashboardHeader() {
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [bounty, setBounty] = useState<BountyStats | null>(null);
  const [vuln, setVuln] = useState<VulnStats | null>(null);

  const load = useCallback(async () => {
    try {
      const [h, b, v] = await Promise.all([
        fetchHealth().catch(() => null),
        fetchBountyStats().catch(() => null),
        fetchVulnStats().catch(() => null),
      ]);
      if (h) setHealth(h);
      if (b) setBounty(b);
      if (v) setVuln(v);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [load]);

  const blocked = health?.apis?.filter((a) => a.blocked) ?? [];
  const ss = health?.scan_stats;
  const hitRate = ss && ss.tested > 0 ? ((ss.alive / ss.tested) * 100).toFixed(1) : "0";
  const recon = bounty?.recon;
  const programs = bounty?.programs ?? 0;
  const reconDone = recon?.recons_completed ?? 0;
  const reconPct = programs > 0 ? Math.round((reconDone / programs) * 100) : 0;

  return (
    <div className="mb-5 space-y-3">
      {/* Top stats row */}
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
        <div className="rounded-lg border border-slate-700/50 bg-slate-800/40 px-3 py-2 text-center">
          <div className="text-lg font-bold text-white tabular-nums">{programs}</div>
          <div className="text-[9px] text-slate-500 uppercase">Programas</div>
        </div>
        <div className="rounded-lg border border-slate-700/50 bg-slate-800/40 px-3 py-2 text-center">
          <div className="text-lg font-bold text-emerald-400 tabular-nums">{bounty?.alive_targets ?? 0}</div>
          <div className="text-[9px] text-slate-500 uppercase">Alive</div>
        </div>
        <div className="rounded-lg border border-slate-700/50 bg-slate-800/40 px-3 py-2 text-center">
          <div className="text-lg font-bold text-amber-400 tabular-nums">{bounty?.targets ?? 0}</div>
          <div className="text-[9px] text-slate-500 uppercase">Targets</div>
        </div>
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2 text-center">
          <div className="text-lg font-bold text-red-400 tabular-nums">{vuln?.by_severity?.critical ?? 0}</div>
          <div className="text-[9px] text-slate-500 uppercase">Critical</div>
        </div>
        <div className="rounded-lg border border-orange-500/30 bg-orange-500/5 px-3 py-2 text-center">
          <div className="text-lg font-bold text-orange-400 tabular-nums">{vuln?.by_severity?.high ?? 0}</div>
          <div className="text-[9px] text-slate-500 uppercase">High</div>
        </div>
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-center">
          <div className="text-lg font-bold text-amber-300 tabular-nums">{vuln?.total_vulns ?? 0}</div>
          <div className="text-[9px] text-slate-500 uppercase">Vulns</div>
        </div>
      </div>

      {/* Recon progress bar */}
      {programs > 0 && (
        <div className="rounded-lg border border-slate-700/50 bg-slate-800/30 px-3 py-2">
          <div className="flex items-center justify-between text-[11px] mb-1.5">
            <span className="text-slate-400">Recon: <span className="text-white font-bold">{reconDone}/{programs}</span> programas</span>
            <span className="text-slate-500">{reconPct}%</span>
          </div>
          <div className="h-1.5 rounded-full bg-slate-700 overflow-hidden">
            <div
              className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-cyan-400 transition-all duration-500"
              style={{ width: `${Math.max(reconPct, 1)}%` }}
            />
          </div>
          {recon && (
            <div className="flex flex-wrap gap-3 mt-2 text-[10px] text-slate-500">
              <span><span className="text-slate-300 font-semibold">{recon.subdomains_found}</span> subdomínios</span>
              <span><span className="text-emerald-400 font-semibold">{recon.hosts_alive}</span> vivos</span>
              {(recon.crtsh_subdomains ?? 0) > 0 && (
                <span><span className="text-cyan-400 font-semibold">{recon.crtsh_subdomains}</span> crt.sh</span>
              )}
              {(recon.asns_discovered ?? 0) > 0 && (
                <span><span className="text-violet-400 font-semibold">{recon.asns_discovered}</span> ASNs</span>
              )}
              {(recon.rdns_subdomains ?? 0) > 0 && (
                <span><span className="text-pink-400 font-semibold">{recon.rdns_subdomains}</span> rDNS</span>
              )}
              {(recon.new_subdomains_detected ?? 0) > 0 && (
                <span><span className="text-lime-400 font-semibold">{recon.new_subdomains_detected}</span> novos</span>
              )}
              {(recon.errors ?? 0) > 0 && (
                <span><span className="text-red-400 font-semibold">{recon.errors}</span> erros</span>
              )}
            </div>
          )}
        </div>
      )}

      {/* Nuclei scanner status */}
      {vuln?.scanner && (
        <div className="rounded-lg border border-slate-700/50 bg-slate-800/30 px-3 py-2">
          <div className="flex items-center gap-2 text-[11px]">
            <span className="text-slate-400">Nuclei:</span>
            <span className="text-amber-400 font-bold">{vuln.scanner.queue_size}</span>
            <span className="text-slate-500">fila</span>
            <span className="text-slate-600">|</span>
            <span className="text-blue-400 font-bold">{vuln.scanner.scanning}</span>
            <span className="text-slate-500">scanning</span>
            <span className="text-slate-600">|</span>
            <span className="text-emerald-400 font-bold">{vuln.scanner.completed}</span>
            <span className="text-slate-500">completos</span>
            <span className="text-slate-600">|</span>
            <span className="text-red-400 font-bold">{vuln.scanner.vulns_found}</span>
            <span className="text-slate-500">vulns</span>
          </div>
        </div>
      )}

      {/* API Status */}
      <div className="flex flex-wrap gap-1.5">
        {health?.apis?.map((api) => (
          <div
            key={api.name}
            className={`rounded-lg border px-2 py-1 text-[10px] ${
              api.blocked
                ? "border-red-500/40 bg-red-500/10"
                : "border-emerald-500/30 bg-emerald-500/5"
            }`}
          >
            <div className="flex items-center gap-1">
              <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${api.blocked ? "bg-red-500 animate-pulse" : "bg-emerald-500"}`} />
              <span className="font-semibold">{api.name}</span>
              {api.blocked ? (
                <span className="text-red-400 font-bold">{api.remaining_seconds}s</span>
              ) : (
                <span className="text-emerald-400">OK</span>
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

      {/* Network scanner stats */}
      {health?.network_scanner_enabled && ss && (
        <div className="flex flex-wrap gap-2 text-[10px]">
          <span className="text-slate-500">Net scanner:</span>
          <span className="text-slate-300 font-bold">{health.workers} workers</span>
          <span className="text-slate-500">|</span>
          <span className="text-slate-300">{ss.tested.toLocaleString("pt-BR")} testados</span>
          <span className="text-emerald-400">{ss.alive.toLocaleString("pt-BR")} vivos ({hitRate}%)</span>
          <span className="text-sky-400">{ss.saved.toLocaleString("pt-BR")} salvos</span>
        </div>
      )}
    </div>
  );
}

export default function Home() {
  return (
    <>
      <DashboardHeader />

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
