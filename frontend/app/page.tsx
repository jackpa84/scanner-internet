"use client";

import { Component, type ReactNode, useEffect, useState, useCallback } from "react";
import BountyPanel from "@/components/BountyPanel";
import VulnPanel from "@/components/VulnPanel";
import EligibleReportsPanel from "@/components/EligibleReportsPanel";
import SubmittedReportsPanel from "@/components/SubmittedReportsPanel";
import Modal from "@/components/Modal";
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
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-6 text-lg text-red-400">
          Erro: {this.state.error}
        </div>
      );
    }
    return this.props.children;
  }
}

function InfoLine({ label, value, color }: { label: string; value: number | string; color?: string }) {
  return (
    <div className="flex items-center justify-between gap-4 py-1">
      <span className="text-lg text-[var(--muted)]">{label}</span>
      <span className={`text-lg font-semibold tabular-nums ${color ?? "text-[var(--foreground)]"}`}>{typeof value === "number" ? value.toLocaleString("pt-BR") : value}</span>
    </div>
  );
}

/* ── Mini SVG charts ─── */

function DonutChart({ value, total, color, size = 56 }: { value: number; total: number; color: string; size?: number }) {
  const r = (size - 8) / 2;
  const c = 2 * Math.PI * r;
  const pct = total > 0 ? value / total : 0;
  return (
    <svg width={size} height={size} className="shrink-0">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--border)" strokeWidth={6} />
      <circle
        cx={size / 2} cy={size / 2} r={r} fill="none"
        stroke={color} strokeWidth={6} strokeLinecap="round"
        strokeDasharray={`${c * pct} ${c * (1 - pct)}`}
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
      />
      <text x={size / 2} y={size / 2} textAnchor="middle" dominantBaseline="central" className="fill-[var(--foreground)] text-xs font-bold">
        {total > 0 ? `${Math.round(pct * 100)}%` : "–"}
      </text>
    </svg>
  );
}

function BarSegments({ segments, height = 10 }: { segments: { value: number; color: string }[]; height?: number }) {
  const total = segments.reduce((s, seg) => s + seg.value, 0);
  if (total === 0) return <div className="rounded-full bg-[var(--border)]" style={{ height }} />;
  return (
    <div className="flex rounded-full overflow-hidden" style={{ height }}>
      {segments.map((seg, i) => (
        <div key={i} style={{ width: `${(seg.value / total) * 100}%`, background: seg.color }} />
      ))}
    </div>
  );
}

function MiniBarChart({ bars, height = 36 }: { bars: { value: number; color: string; label: string }[]; height?: number }) {
  const max = Math.max(...bars.map(b => b.value), 1);
  return (
    <div className="flex items-end gap-1.5" style={{ height }}>
      {bars.map((b, i) => (
        <div key={i} className="flex-1 flex flex-col items-center gap-0.5">
          <div className="w-full rounded-t" style={{ height: `${(b.value / max) * 100}%`, background: b.color, minHeight: 2 }} />
          <span className="text-[10px] text-[var(--muted)] leading-none">{b.label}</span>
        </div>
      ))}
    </div>
  );
}

function ProgressBar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.min(value / max, 1) * 100 : 0;
  return (
    <div className="w-full rounded-full bg-[var(--border)] h-2.5 overflow-hidden">
      <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: color }} />
    </div>
  );
}

/* ── Dashboard Card (clickable) ─── */

function DashboardCard({
  title,
  accent,
  onClick,
  graphic,
  children,
}: {
  title: string;
  accent: string;
  onClick: () => void;
  graphic: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="rounded-2xl border border-[var(--border)] bg-[var(--card)] p-7 flex flex-col gap-5 text-left hover:border-[var(--accent)]/40 hover:bg-[var(--card-hover)] transition-all group w-full"
    >
      <div className="flex items-center justify-between gap-4">
        <h2 className={`text-xl font-bold tracking-tight ${accent}`}>{title}</h2>
        <span className="text-sm font-medium text-[var(--accent-light)] opacity-0 group-hover:opacity-100 transition-opacity">
          Ver detalhes →
        </span>
      </div>
      <div className="flex items-center gap-6">
        <div className="shrink-0">{graphic}</div>
        <div className="flex-1 space-y-2">{children}</div>
      </div>
    </button>
  );
}

function MetricBig({ value, label, color }: { value: number | string; label: string; color: string }) {
  return (
    <div>
      <div className={`text-4xl font-extrabold tabular-nums leading-none ${color}`}>
        {typeof value === "number" ? value.toLocaleString("pt-BR") : value}
      </div>
      <div className="text-base text-[var(--muted)] mt-1">{label}</div>
    </div>
  );
}

function DashboardHeader() {
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [bounty, setBounty] = useState<BountyStats | null>(null);
  const [vuln, setVuln] = useState<VulnStats | null>(null);
  const [detailModal, setDetailModal] = useState<string | null>(null);

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
    const id = setInterval(load, 8000);
    return () => clearInterval(id);
  }, [load]);

  const ss = health?.scan_stats;
  const recon = bounty?.recon;
  const scanner = vuln?.scanner;
  const sev = vuln?.by_severity;

  const totalVulnBySev = (sev?.critical ?? 0) + (sev?.high ?? 0) + (sev?.medium ?? 0) + (sev?.low ?? 0) + (sev?.info ?? 0);
  const aliveTargets = bounty?.alive_targets ?? 0;
  const totalTargets = bounty?.targets ?? 0;
  const reconDone = recon?.recons_completed ?? 0;
  const reconTotal = bounty?.programs ?? 0;
  const scanCompleted = scanner?.completed ?? 0;
  const scanQueue = scanner?.queue_size ?? 0;
  const scanTotal = scanCompleted + scanQueue + (scanner?.scanning ?? 0);
  const netAlive = ss?.alive ?? 0;
  const netTested = ss?.tested ?? 0;

  return (
    <div className="mb-8 space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">

        {/* ── Programas ── */}
        <DashboardCard
          title="Programas"
          accent="text-[var(--accent-light)]"
          onClick={() => setDetailModal("programas")}
          graphic={
            <div className="flex flex-col items-center gap-1">
              <MiniBarChart height={48} bars={[
                { value: bounty?.programs_with_bounty ?? 0, color: "#10b981", label: "$$" },
                { value: (bounty?.programs ?? 0) - (bounty?.programs_with_bounty ?? 0), color: "#6366f1", label: "Sem" },
                { value: bounty?.bounty_prefixes ?? 0, color: "#f59e0b", label: "Pfx" },
              ]} />
            </div>
          }
        >
          <MetricBig value={bounty?.programs ?? 0} label="Programas" color="text-[var(--accent-light)]" />
          <div className="flex gap-6 text-base">
            <span className="text-green-400 font-semibold">{bounty?.programs_with_bounty ?? 0} bounty</span>
            <span className="text-amber-400 font-semibold">{bounty?.bounty_prefixes ?? 0} prefixos</span>
          </div>
        </DashboardCard>

        {/* ── Targets ── */}
        <DashboardCard
          title="Targets"
          accent="text-emerald-400"
          onClick={() => setDetailModal("targets")}
          graphic={
            <DonutChart value={aliveTargets} total={totalTargets} color="#10b981" size={64} />
          }
        >
          <MetricBig value={totalTargets} label="Total targets" color="text-[var(--foreground)]" />
          <div className="flex gap-6 text-base">
            <span className="text-emerald-400 font-semibold">{aliveTargets} vivos</span>
            <span className="text-lime-400 font-semibold">{bounty?.new_targets ?? 0} novos</span>
          </div>
        </DashboardCard>

        {/* ── Recon ── */}
        <DashboardCard
          title="Recon"
          accent="text-cyan-400"
          onClick={() => setDetailModal("recon")}
          graphic={
            <DonutChart value={reconDone} total={reconTotal} color="#06b6d4" size={64} />
          }
        >
          <MetricBig value={recon?.subdomains_found ?? 0} label="Subdomínios" color="text-cyan-400" />
          <ProgressBar value={reconDone} max={reconTotal} color="#06b6d4" />
          <div className="text-base text-[var(--muted)]">{reconDone}/{reconTotal} recons completos</div>
        </DashboardCard>

        {/* ── Vulnerabilidades ── */}
        <DashboardCard
          title="Vulnerabilidades"
          accent="text-amber-400"
          onClick={() => setDetailModal("vulns")}
          graphic={
            <MiniBarChart height={56} bars={[
              { value: sev?.critical ?? 0, color: "#ef4444", label: "C" },
              { value: sev?.high ?? 0, color: "#f97316", label: "H" },
              { value: sev?.medium ?? 0, color: "#f59e0b", label: "M" },
              { value: sev?.low ?? 0, color: "#38bdf8", label: "L" },
              { value: sev?.info ?? 0, color: "#64748b", label: "I" },
            ]} />
          }
        >
          <MetricBig value={vuln?.total_vulns ?? 0} label="Total vulnerabilidades" color="text-amber-400" />
          <BarSegments segments={[
            { value: sev?.critical ?? 0, color: "#ef4444" },
            { value: sev?.high ?? 0, color: "#f97316" },
            { value: sev?.medium ?? 0, color: "#f59e0b" },
            { value: sev?.low ?? 0, color: "#38bdf8" },
            { value: sev?.info ?? 0, color: "#64748b" },
          ]} />
          <div className="flex gap-4 text-sm flex-wrap">
            {(sev?.critical ?? 0) > 0 && <span className="text-red-500 font-bold">{sev!.critical} critical</span>}
            {(sev?.high ?? 0) > 0 && <span className="text-orange-400 font-semibold">{sev!.high} high</span>}
            {(sev?.medium ?? 0) > 0 && <span className="text-amber-400">{sev!.medium} medium</span>}
          </div>
        </DashboardCard>

        {/* ── Network Scanner ── */}
        <DashboardCard
          title="Network Scanner"
          accent="text-blue-400"
          onClick={() => setDetailModal("network")}
          graphic={
            health?.network_scanner_enabled
              ? <DonutChart value={netAlive} total={netTested} color="#3b82f6" size={64} />
              : (
                <div className="w-16 h-16 flex items-center justify-center rounded-full bg-[var(--border)]">
                  <svg className="w-8 h-8 text-[var(--muted)]" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                  </svg>
                </div>
              )
          }
        >
          {health?.network_scanner_enabled ? (
            <>
              <MetricBig value={netTested} label="Testados" color="text-blue-400" />
              <div className="flex gap-6 text-base">
                <span className="text-emerald-400 font-semibold">{netAlive} vivos</span>
                <span className="text-red-400 font-semibold">{ss?.dead ?? 0} mortos</span>
              </div>
            </>
          ) : (
            <div className="text-lg text-[var(--muted)] italic">Scanner desabilitado</div>
          )}
        </DashboardCard>

        {/* ── Nuclei Scanner ── */}
        <DashboardCard
          title="Nuclei Scanner"
          accent="text-violet-400"
          onClick={() => setDetailModal("nuclei")}
          graphic={
            <div className="flex flex-col items-center gap-2">
              <DonutChart value={scanCompleted} total={scanTotal || 1} color="#8b5cf6" size={64} />
            </div>
          }
        >
          <MetricBig value={scanner?.vulns_found ?? 0} label="Vulns achadas" color="text-violet-400" />
          <ProgressBar value={scanCompleted} max={scanTotal || 1} color="#8b5cf6" />
          <div className="flex gap-5 text-base">
            <span className="text-amber-400">{scanQueue} na fila</span>
            <span className="text-emerald-400">{scanCompleted} ok</span>
          </div>
        </DashboardCard>

        {/* ── Recon Tools ── */}
        <DashboardCard
          title="Recon Tools"
          accent="text-pink-400"
          onClick={() => setDetailModal("tools")}
          graphic={
            <div className="w-16 h-16 flex items-center justify-center rounded-xl bg-pink-500/10 text-pink-400">
              <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" d="M11.42 15.17l-5.1-5.1M11.42 15.17l2.25 2.25M14.5 8l-5 5M12 2.25c-5.385 0-9.75 4.365-9.75 9.75s4.365 9.75 9.75 9.75 9.75-4.365 9.75-9.75S17.385 2.25 12 2.25z" />
              </svg>
            </div>
          }
        >
          <div className="text-lg font-bold text-[var(--foreground)]">Pipeline Ativo</div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
            <span className="text-cyan-400">subfinder</span>
            <span className="text-cyan-400">httpx</span>
            <span className="text-pink-400">katana</span>
            <span className="text-pink-400">gau</span>
            <span className="text-violet-400">nuclei</span>
            <span className="text-violet-400">nmap</span>
            <span className="text-amber-400">dnsx</span>
            <span className="text-emerald-400">crt.sh</span>
          </div>
        </DashboardCard>

        {/* ── JS Secrets ── */}
        <DashboardCard
          title="JS Secrets"
          accent="text-red-400"
          onClick={() => setDetailModal("tools")}
          graphic={
            <div className="w-16 h-16 flex items-center justify-center rounded-xl bg-red-500/10 text-red-400">
              <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
              </svg>
            </div>
          }
        >
          <div className="text-lg font-bold text-[var(--foreground)]">Deteccao de Secrets</div>
          <div className="space-y-1 text-sm">
            <span className="text-red-400">API Keys, Tokens, AWS Keys</span>
            <br />
            <span className="text-amber-400">DB URIs, Private Keys</span>
            <br />
            <span className="text-[var(--muted)]">14 patterns em JS files</span>
          </div>
        </DashboardCard>

        {/* ── Telegram ── */}
        <DashboardCard
          title="Telegram Alerts"
          accent="text-sky-400"
          onClick={() => setDetailModal("tools")}
          graphic={
            <div className="w-16 h-16 flex items-center justify-center rounded-xl bg-sky-500/10 text-sky-400">
              <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
              </svg>
            </div>
          }
        >
          <div className="text-lg font-bold text-[var(--foreground)]">Notificacoes</div>
          <div className="space-y-1 text-sm">
            <span className="text-red-400">Critical → alerta imediato</span>
            <br />
            <span className="text-orange-400">High → alerta imediato</span>
            <br />
            <span className="text-[var(--muted)]">Via Telegram Bot</span>
          </div>
        </DashboardCard>
      </div>


      {/* ── Detail Modals ── */}
      <Modal open={detailModal === "programas"} onClose={() => setDetailModal(null)} title="Programas - Detalhes">
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-5">
            <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-6 text-center">
              <div className="text-5xl font-extrabold text-[var(--accent-light)] tabular-nums">{bounty?.programs ?? 0}</div>
              <div className="text-lg text-[var(--muted)] mt-2">Total de Programas</div>
            </div>
            <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-6 text-center">
              <div className="text-5xl font-extrabold text-green-400 tabular-nums">{bounty?.programs_with_bounty ?? 0}</div>
              <div className="text-lg text-[var(--muted)] mt-2">Com Bounty</div>
            </div>
          </div>
          <div className="space-y-3">
            <InfoLine label="Prefixos de bounty" value={bounty?.bounty_prefixes ?? 0} color="text-amber-400" />
            <InfoLine label="Total de mudanças" value={bounty?.total_changes ?? 0} />
            <InfoLine label="Targets cadastrados" value={bounty?.targets ?? 0} />
            <InfoLine label="Targets vivos" value={bounty?.alive_targets ?? 0} color="text-emerald-400" />
            <InfoLine label="Targets novos" value={bounty?.new_targets ?? 0} color="text-lime-400" />
          </div>
        </div>
      </Modal>

      <Modal open={detailModal === "targets"} onClose={() => setDetailModal(null)} title="Targets - Detalhes">
        <div className="space-y-6">
          <div className="flex items-center justify-center py-4">
            <DonutChart value={aliveTargets} total={totalTargets} color="#10b981" size={120} />
          </div>
          <div className="grid grid-cols-3 gap-5">
            {[
              { label: "Total", value: totalTargets, color: "text-[var(--foreground)]" },
              { label: "Vivos", value: aliveTargets, color: "text-emerald-400" },
              { label: "Novos", value: bounty?.new_targets ?? 0, color: "text-lime-400" },
            ].map(({ label, value, color }) => (
              <div key={label} className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-5 text-center">
                <div className={`text-4xl font-extrabold tabular-nums ${color}`}>{value}</div>
                <div className="text-lg text-[var(--muted)] mt-2">{label}</div>
              </div>
            ))}
          </div>
        </div>
      </Modal>

      <Modal open={detailModal === "recon"} onClose={() => setDetailModal(null)} title="Recon - Detalhes">
        <div className="space-y-6">
          <div className="flex items-center gap-6 py-2">
            <DonutChart value={reconDone} total={reconTotal} color="#06b6d4" size={100} />
            <div>
              <div className="text-4xl font-extrabold text-cyan-400 tabular-nums">{reconDone}/{reconTotal}</div>
              <div className="text-lg text-[var(--muted)] mt-1">Recons completados</div>
            </div>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-5">
            {[
              { label: "Subdomínios", value: recon?.subdomains_found ?? 0, color: "text-[var(--foreground)]" },
              { label: "crt.sh", value: recon?.crtsh_subdomains ?? 0, color: "text-sky-400" },
              { label: "ASNs", value: recon?.asns_discovered ?? 0, color: "text-violet-400" },
              { label: "rDNS", value: recon?.rdns_subdomains ?? 0, color: "text-pink-400" },
              { label: "Novos Subs", value: recon?.new_subdomains_detected ?? 0, color: "text-lime-400" },
              { label: "Erros", value: recon?.errors ?? 0, color: (recon?.errors ?? 0) > 0 ? "text-red-400" : "text-[var(--muted)]" },
            ].map(({ label, value, color }) => (
              <div key={label} className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-5 text-center">
                <div className={`text-3xl font-bold tabular-nums ${color}`}>{value}</div>
                <div className="text-base text-[var(--muted)] mt-2">{label}</div>
              </div>
            ))}
          </div>
        </div>
      </Modal>

      <Modal open={detailModal === "vulns"} onClose={() => setDetailModal(null)} title="Vulnerabilidades - Detalhes">
        <div className="space-y-6">
          <div className="flex items-center gap-6 py-2">
            <MiniBarChart height={80} bars={[
              { value: sev?.critical ?? 0, color: "#ef4444", label: "Critical" },
              { value: sev?.high ?? 0, color: "#f97316", label: "High" },
              { value: sev?.medium ?? 0, color: "#f59e0b", label: "Medium" },
              { value: sev?.low ?? 0, color: "#38bdf8", label: "Low" },
              { value: sev?.info ?? 0, color: "#64748b", label: "Info" },
            ]} />
          </div>
          <BarSegments height={16} segments={[
            { value: sev?.critical ?? 0, color: "#ef4444" },
            { value: sev?.high ?? 0, color: "#f97316" },
            { value: sev?.medium ?? 0, color: "#f59e0b" },
            { value: sev?.low ?? 0, color: "#38bdf8" },
            { value: sev?.info ?? 0, color: "#64748b" },
          ]} />
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-5">
            {[
              { label: "Critical", value: sev?.critical ?? 0, color: "text-red-500" },
              { label: "High", value: sev?.high ?? 0, color: "text-orange-400" },
              { label: "Medium", value: sev?.medium ?? 0, color: "text-amber-400" },
              { label: "Low", value: sev?.low ?? 0, color: "text-sky-400" },
              { label: "Info", value: sev?.info ?? 0, color: "text-slate-400" },
              { label: "Total", value: vuln?.total_vulns ?? 0, color: "text-amber-400" },
            ].map(({ label, value, color }) => (
              <div key={label} className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-5 text-center">
                <div className={`text-3xl font-bold tabular-nums ${value > 0 ? color : "text-[var(--muted)]"}`}>{value}</div>
                <div className="text-base text-[var(--muted)] mt-2">{label}</div>
              </div>
            ))}
          </div>
          <InfoLine label="IPs escaneados" value={vuln?.unique_ips_scanned ?? 0} />
        </div>
      </Modal>

      <Modal open={detailModal === "network"} onClose={() => setDetailModal(null)} title="Network Scanner - Detalhes">
        <div className="space-y-6">
          {health?.network_scanner_enabled ? (
            <>
              <div className="flex items-center gap-6 py-2">
                <DonutChart value={netAlive} total={netTested} color="#3b82f6" size={100} />
                <div>
                  <div className="text-4xl font-extrabold text-blue-400 tabular-nums">{netAlive}/{netTested}</div>
                  <div className="text-lg text-[var(--muted)] mt-1">Hosts vivos / testados</div>
                </div>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-5">
                {[
                  { label: "Testados", value: ss?.tested ?? 0, color: "text-[var(--foreground)]" },
                  { label: "Vivos", value: ss?.alive ?? 0, color: "text-emerald-400" },
                  { label: "Mortos", value: ss?.dead ?? 0, color: "text-red-400" },
                  { label: "Salvos", value: ss?.saved ?? 0, color: "text-sky-400" },
                  { label: "Workers", value: health?.workers ?? 0, color: "text-[var(--foreground)]" },
                  { label: "Intervalo", value: `${health?.scan_interval ?? 0}s`, color: "text-[var(--foreground)]" },
                ].map(({ label, value, color }) => (
                  <div key={label} className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-5 text-center">
                    <div className={`text-3xl font-bold tabular-nums ${color}`}>{value}</div>
                    <div className="text-base text-[var(--muted)] mt-2">{label}</div>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="rounded-xl border border-[var(--border)] bg-[var(--background)] p-10 text-center">
              <svg className="w-16 h-16 mx-auto text-[var(--muted)] mb-4" fill="none" viewBox="0 0 24 24" strokeWidth={1} stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
              </svg>
              <p className="text-xl text-[var(--muted)]">Network scanner está desabilitado</p>
            </div>
          )}
        </div>
      </Modal>

      <Modal open={detailModal === "nuclei"} onClose={() => setDetailModal(null)} title="Nuclei Scanner - Detalhes">
        <div className="space-y-6">
          <div className="flex items-center gap-6 py-2">
            <DonutChart value={scanCompleted} total={scanTotal || 1} color="#8b5cf6" size={100} />
            <div>
              <div className="text-4xl font-extrabold text-violet-400 tabular-nums">{scanner?.vulns_found ?? 0}</div>
              <div className="text-lg text-[var(--muted)] mt-1">Vulnerabilidades encontradas</div>
            </div>
          </div>
          <ProgressBar value={scanCompleted} max={scanTotal || 1} color="#8b5cf6" />
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-5">
            {[
              { label: "Na Fila", value: scanner?.queue_size ?? 0, color: (scanner?.queue_size ?? 0) > 0 ? "text-amber-400" : "text-[var(--muted)]" },
              { label: "Escaneando", value: scanner?.scanning ?? 0, color: (scanner?.scanning ?? 0) > 0 ? "text-blue-400" : "text-[var(--muted)]" },
              { label: "Completados", value: scanner?.completed ?? 0, color: "text-emerald-400" },
              { label: "Vulns Achadas", value: scanner?.vulns_found ?? 0, color: "text-amber-400" },
              { label: "Nuclei Runs", value: scanner?.nuclei_runs ?? 0, color: "text-[var(--foreground)]" },
              { label: "Nmap Runs", value: scanner?.nmap_runs ?? 0, color: "text-[var(--foreground)]" },
            ].map(({ label, value, color }) => (
              <div key={label} className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-5 text-center">
                <div className={`text-3xl font-bold tabular-nums ${color}`}>{value}</div>
                <div className="text-base text-[var(--muted)] mt-2">{label}</div>
              </div>
            ))}
          </div>
          {(scanner?.errors ?? 0) > 0 && (
            <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-5">
              <span className="text-lg text-red-400 font-semibold">{scanner?.errors} erro(s) durante scans</span>
            </div>
          )}
        </div>
      </Modal>

      <Modal open={detailModal === "tools"} onClose={() => setDetailModal(null)} title="Ferramentas de Recon & Scan">
        <div className="space-y-6">
          {/* Recon tools */}
          <div>
            <h3 className="text-lg font-bold text-[var(--foreground)] mb-3">Subdomain Enumeration</h3>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {[
                { name: "subfinder", desc: "Enumeracao passiva de subdomínios", color: "text-cyan-400", bg: "bg-cyan-500/10 border-cyan-500/20" },
                { name: "crt.sh", desc: "Certificate Transparency logs", color: "text-sky-400", bg: "bg-sky-500/10 border-sky-500/20" },
                { name: "AlienVault", desc: "Passive DNS via OTX API", color: "text-violet-400", bg: "bg-violet-500/10 border-violet-500/20" },
                { name: "RapidDNS", desc: "Servico de enumeracao", color: "text-purple-400", bg: "bg-purple-500/10 border-purple-500/20" },
                { name: "Anubis", desc: "Subdomain discovery", color: "text-indigo-400", bg: "bg-indigo-500/10 border-indigo-500/20" },
                { name: "Wayback", desc: "Subdomínios historicos", color: "text-amber-400", bg: "bg-amber-500/10 border-amber-500/20" },
                { name: "dnsx", desc: "Resolucao DNS massiva", color: "text-teal-400", bg: "bg-teal-500/10 border-teal-500/20" },
              ].map(t => (
                <div key={t.name} className={`rounded-xl border ${t.bg} p-3`}>
                  <div className={`text-base font-bold ${t.color}`}>{t.name}</div>
                  <div className="text-sm text-[var(--muted)]">{t.desc}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Crawling & URL discovery */}
          <div>
            <h3 className="text-lg font-bold text-[var(--foreground)] mb-3">Crawling & URL Discovery</h3>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {[
                { name: "katana", desc: "Web crawler: endpoints, JS, forms", color: "text-pink-400", bg: "bg-pink-500/10 border-pink-500/20" },
                { name: "gau", desc: "URLs de Wayback + CommonCrawl + OTX", color: "text-rose-400", bg: "bg-rose-500/10 border-rose-500/20" },
                { name: "httpx", desc: "HTTP probe + fingerprint", color: "text-emerald-400", bg: "bg-emerald-500/10 border-emerald-500/20" },
                { name: "ParamSpider", desc: "Parametros de URL via arquivos", color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/20" },
              ].map(t => (
                <div key={t.name} className={`rounded-xl border ${t.bg} p-3`}>
                  <div className={`text-base font-bold ${t.color}`}>{t.name}</div>
                  <div className="text-sm text-[var(--muted)]">{t.desc}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Vulnerability scanning */}
          <div>
            <h3 className="text-lg font-bold text-[var(--foreground)] mb-3">Vulnerability Scanning</h3>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {[
                { name: "nuclei", desc: "Scanner de vulns com templates", color: "text-violet-400", bg: "bg-violet-500/10 border-violet-500/20" },
                { name: "nmap NSE", desc: "Scripts de vuln e auth", color: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/20" },
                { name: "ffuf", desc: "Directory/path fuzzing", color: "text-lime-400", bg: "bg-lime-500/10 border-lime-500/20" },
                { name: "dalfox", desc: "XSS scanner", color: "text-red-400", bg: "bg-red-500/10 border-red-500/20" },
                { name: "testssl.sh", desc: "Analise SSL/TLS", color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/20" },
                { name: "wafw00f", desc: "WAF detection", color: "text-slate-400", bg: "bg-slate-500/10 border-slate-500/20" },
              ].map(t => (
                <div key={t.name} className={`rounded-xl border ${t.bg} p-3`}>
                  <div className={`text-base font-bold ${t.color}`}>{t.name}</div>
                  <div className="text-sm text-[var(--muted)]">{t.desc}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Secret detection */}
          <div>
            <h3 className="text-lg font-bold text-[var(--foreground)] mb-3">Secret Detection & Intel</h3>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {[
                { name: "JS Secrets", desc: "API keys, tokens, URIs em JS", color: "text-red-400", bg: "bg-red-500/10 border-red-500/20" },
                { name: "GitHub Dorking", desc: "Secrets vazados em repos", color: "text-slate-300", bg: "bg-slate-500/10 border-slate-500/20" },
                { name: "Shodan", desc: "Enrichment de IPs", color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/20" },
                { name: "ThreatFox", desc: "IOC / malware detection", color: "text-rose-400", bg: "bg-rose-500/10 border-rose-500/20" },
              ].map(t => (
                <div key={t.name} className={`rounded-xl border ${t.bg} p-3`}>
                  <div className={`text-base font-bold ${t.color}`}>{t.name}</div>
                  <div className="text-sm text-[var(--muted)]">{t.desc}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Security checks */}
          <div>
            <h3 className="text-lg font-bold text-[var(--foreground)] mb-3">40+ Security Checks</h3>
            <div className="flex flex-wrap gap-2">
              {[
                "CORS", "SSTI", "CRLF", "Host Header", "JWT", "S3 Buckets",
                "Subdomain Takeover", "Zone Transfer", "Missing Headers",
                ".git exposed", ".env exposed", "phpMyAdmin", "Jenkins",
                "Swagger/OpenAPI", "GraphQL", "Debug endpoints",
                "Directory listing", "Server-status", "Actuator",
              ].map(c => (
                <span key={c} className="rounded-lg bg-[var(--background)] border border-[var(--border)] px-3 py-1.5 text-sm text-[var(--foreground)]">{c}</span>
              ))}
            </div>
          </div>

          {/* Notifications */}
          <div>
            <h3 className="text-lg font-bold text-[var(--foreground)] mb-3">Notificacoes</h3>
            <div className="rounded-xl bg-sky-500/10 border border-sky-500/20 p-4">
              <div className="flex items-center gap-3 mb-2">
                <svg className="w-6 h-6 text-sky-400" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
                </svg>
                <span className="text-base font-bold text-sky-400">Telegram Bot</span>
              </div>
              <p className="text-base text-[var(--muted)]">
                Alertas em tempo real no celular para findings Critical e High.
                Configure <code className="text-sky-300">TELEGRAM_BOT_TOKEN</code> e <code className="text-sky-300">TELEGRAM_CHAT_ID</code> no .env
              </p>
            </div>
          </div>
        </div>
      </Modal>
    </div>
  );
}

function StatsPanel() {
  const [bounty, setBounty] = useState<BountyStats | null>(null);

  const load = useCallback(async () => {
    try {
      const b = await fetchBountyStats().catch(() => null);
      if (b) setBounty(b);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 10_000);
    return () => clearInterval(id);
  }, [load]);

  if (!bounty) return null;

  const recon = bounty.recon;

  type Badge = { value: number; label: string; border: string; bg: string; text: string };
  const badges: Badge[] = [
    { value: bounty.new_targets ?? 0, label: "Novos", border: "border-emerald-500/30", bg: "bg-emerald-500/5", text: "text-emerald-400" },
    { value: recon?.crtsh_subdomains ?? 0, label: "crt.sh", border: "border-cyan-500/30", bg: "bg-cyan-500/5", text: "text-cyan-400" },
    { value: recon?.asns_discovered ?? 0, label: "ASNs", border: "border-violet-500/30", bg: "bg-violet-500/5", text: "text-violet-400" },
    { value: bounty.bounty_prefixes ?? 0, label: "Prefixos", border: "border-amber-500/30", bg: "bg-amber-500/5", text: "text-amber-400" },
    { value: recon?.rdns_subdomains ?? 0, label: "rDNS", border: "border-pink-500/30", bg: "bg-pink-500/5", text: "text-pink-400" },
    { value: recon?.new_subdomains_detected ?? 0, label: "Novos subs", border: "border-lime-500/30", bg: "bg-lime-500/5", text: "text-lime-400" },
    { value: bounty.total_changes ?? 0, label: "Changes", border: "border-slate-600/50", bg: "bg-slate-800/40", text: "text-slate-300" },
  ].filter(b => b.value > 0);

  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:gap-5">
      <div className="flex items-center gap-4">
        {[
          { label: "Programas", value: bounty.programs, color: "text-[var(--accent-light)]" },
          { label: "Targets", value: bounty.targets, color: "text-[var(--foreground)]" },
          { label: "Vivos", value: bounty.alive_targets, color: "text-emerald-400" },
          { label: "Recons OK", value: recon?.recons_completed ?? 0, color: "text-cyan-400" },
        ].map(({ label, value, color }) => (
          <div key={label} className="rounded-xl bg-[var(--card)] border border-[var(--border)] px-5 py-3 text-center">
            <div className={`text-3xl font-extrabold tabular-nums leading-none ${color}`}>{value.toLocaleString("pt-BR")}</div>
            <div className="text-xs text-[var(--muted)] mt-1 uppercase tracking-wider">{label}</div>
          </div>
        ))}
      </div>

      {badges.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {badges.map((b) => (
            <div key={b.label} className={`rounded border ${b.border} ${b.bg} px-2.5 py-1.5 text-sm`}>
              <span className={`${b.text} font-semibold`}>{b.value.toLocaleString("pt-BR")}</span>
              <span className="text-slate-400 ml-1">{b.label}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function Home() {
  return (
    <div className="flex flex-col h-full">
      {/* Topo: Reports H1 + Elegiveis + Stats */}
      <div className="mb-8 space-y-4">
        <ErrorBoundary>
          <SubmittedReportsPanel />
        </ErrorBoundary>
        <ErrorBoundary>
          <EligibleReportsPanel />
        </ErrorBoundary>
        <ErrorBoundary>
          <StatsPanel />
        </ErrorBoundary>
      </div>

      <DashboardHeader />

      <div className="grid grid-cols-1 xl:grid-cols-[1fr_480px] gap-8 flex-1 min-h-0">
        <ErrorBoundary>
          <BountyPanel />
        </ErrorBoundary>

        <div className="xl:border-l xl:border-[var(--border)] xl:pl-8 space-y-6">
          <ErrorBoundary>
            <VulnPanel />
          </ErrorBoundary>
        </div>
      </div>
    </div>
  );
}
