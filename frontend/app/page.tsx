"use client";

import { Component, type ReactNode, useEffect, useState, useCallback, useRef } from "react";
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
  type HealthInfo,
  type BountyStats,
  type VulnStats,
  type ScannerStats,
  type ROIDashboard,
  type PrioritizedProgram,
  type BountyChange,
  type SubmittedReportsStats,
  type AIStats,
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

function Tooltip({ text, children, className = "" }: { text: string; children: ReactNode; className?: string }) {
  const [show, setShow] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleEnter = () => {
    timerRef.current = setTimeout(() => setShow(true), 2000);
  };
  const handleLeave = () => {
    if (timerRef.current) clearTimeout(timerRef.current);
    setShow(false);
  };

  return (
    <div className={`relative h-full ${className}`} onMouseEnter={handleEnter} onMouseLeave={handleLeave}>
      {children}
      {show && (
        <div className="absolute z-50 bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-2 rounded-lg bg-[#1a2436] border border-[var(--border-bright)] text-[11px] text-[var(--foreground)] leading-relaxed whitespace-pre-line max-w-[240px] shadow-xl shadow-black/40 pointer-events-none">
          {text}
          <div className="absolute top-full left-1/2 -translate-x-1/2 -mt-px w-2 h-2 bg-[#1a2436] border-r border-b border-[var(--border-bright)] rotate-45" />
        </div>
      )}
    </div>
  );
}

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
      <div className="text-[10px] text-[var(--muted)] mt-0.5 truncate h-4">{sub || ""}</div>
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
    <div className={`rounded-xl border border-[var(--border)] bg-[var(--card)] p-3 card-glow h-full ${className}`}
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

function MetricCard({ children, accentColor, bg, className = "" }: { children: ReactNode; accentColor: string; bg?: string; className?: string }) {
  return (
    <div className={`metric-card rounded-xl border border-[var(--border)] p-4 card-glow h-full ${className}`}
      style={{
        "--metric-accent": accentColor,
        background: bg || "var(--card)",
      } as React.CSSProperties}>
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

/* ═══════════════════════════════════════════════════════════════
   Report Submission — Expandable card
   ═══════════════════════════════════════════════════════════════ */

function ReportSubmissionCard({ reportStats, roi }: { reportStats: SubmittedReportsStats | null; roi: ROIDashboard | null }) {
  const [open, setOpen] = useState(false);

  const submitted = reportStats?.submitted ?? 0;
  const accepted = roi?.operations.reports_accepted ?? 0;
  const failed = reportStats?.errors ?? 0;
  const pending = reportStats?.pending ?? 0;
  const total = reportStats?.total ?? 0;
  const rate = roi?.operations.acceptance_rate ?? 0;

  return (
    <>
      <Tooltip className="lg:col-span-4" text={"Clique para ver detalhes completos.\nStatus, severidade, plataformas\ne guia passo a passo."}>
      <Card title="Report Submission" accent="text-violet-400" glow="rgba(139, 92, 246, 0.06)"
        action={<button onClick={() => setOpen(true)} className="text-[10px] text-violet-400 hover:text-violet-300 transition-colors">detalhes →</button>}>
        <div className="cursor-pointer" onClick={() => setOpen(true)}>
          <div className="flex items-center gap-3 mb-3">
            <Donut value={accepted} total={Math.max(total, 1)} color="#8b5cf6" size={56} />
            <div>
              <div className="text-2xl font-bold tabular-nums text-[var(--foreground)]">{total}</div>
              <div className="text-[10px] text-[var(--muted)] uppercase">Total reports</div>
            </div>
          </div>
          <div className="space-y-1.5">
            {[
              { label: "Submitted", val: submitted, c: "text-violet-400" },
              { label: "Accepted", val: accepted, c: "text-emerald-400" },
              { label: "Failed", val: failed, c: "text-red-400" },
              { label: "Pending", val: pending, c: "text-amber-400" },
              { label: "Acceptance Rate", val: `${rate}%`, c: rate > 50 ? "text-emerald-400" : "text-red-400" },
            ].map(r => (
              <div key={r.label} className="flex items-center justify-between text-xs">
                <span className="text-[var(--muted)]">{r.label}</span>
                <span className={`font-semibold tabular-nums ${r.c}`}>{r.val}</span>
              </div>
            ))}
          </div>
          {reportStats?.by_severity && Object.keys(reportStats.by_severity).length > 0 && (
            <div className="mt-2 pt-2 border-t border-[var(--border)] flex gap-1.5 flex-wrap">
              {Object.entries(reportStats.by_severity).map(([s, count]) => (
                <span key={s} className={`text-[9px] font-semibold px-1.5 py-0.5 rounded sev-${s}`}>{s}: {count as number}</span>
              ))}
            </div>
          )}
        </div>
      </Card>
      </Tooltip>

      {/* ── Modal with full details ── */}
      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={() => setOpen(false)}>
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
          <div
            className="relative bg-[var(--card)] border border-[var(--border)] rounded-2xl w-full max-w-2xl max-h-[85vh] overflow-y-auto hide-scrollbar shadow-2xl shadow-black/50"
            onClick={e => e.stopPropagation()}
            style={{ animation: "modalIn 0.3s ease-out" }}
          >
            {/* Header */}
            <div className="sticky top-0 z-10 bg-[var(--card)]/95 backdrop-blur-md border-b border-[var(--border)] px-6 py-4 flex items-center justify-between">
              <h2 className="text-base font-bold text-violet-400">Report Submission</h2>
              <button onClick={() => setOpen(false)} className="text-[var(--muted)] hover:text-[var(--foreground)] transition-colors p-1">
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="p-6 space-y-6">
              {/* Status cards */}
              <div>
                <div className="text-[11px] text-[var(--muted)] uppercase font-semibold mb-3">Status dos Reports</div>
                <div className="grid grid-cols-4 gap-3">
                  {[
                    { label: "Submitted", val: submitted, c: "text-violet-400", bg: "bg-violet-500/8 border-violet-500/15", desc: "Enviados com sucesso à plataforma de bug bounty." },
                    { label: "Accepted", val: accepted, c: "text-emerald-400", bg: "bg-emerald-500/8 border-emerald-500/15", desc: "Aceitos pelo triager. Elegíveis para receber bounty." },
                    { label: "Failed", val: failed, c: "text-red-400", bg: "bg-red-500/8 border-red-500/15", desc: "Erro no envio: credenciais inválidas, fora do escopo, ou duplicado." },
                    { label: "Pending", val: pending, c: "text-amber-400", bg: "bg-amber-500/8 border-amber-500/15", desc: "Aguardando análise do triager. Tempo médio: 1-7 dias." },
                  ].map(s => (
                    <Tooltip key={s.label} text={s.desc}>
                      <div className={`text-center p-4 rounded-xl border ${s.bg}`}>
                        <div className={`text-3xl font-bold tabular-nums ${s.c}`}>{s.val}</div>
                        <div className="text-[9px] text-[var(--muted)] uppercase mt-1">{s.label}</div>
                      </div>
                    </Tooltip>
                  ))}
                </div>
              </div>

              {/* Acceptance rate */}
              <div>
                <div className="text-[11px] text-[var(--muted)] uppercase font-semibold mb-3">Taxa de Aceitação</div>
                <div className="flex items-center gap-4 mb-2">
                  <div className="flex-1 h-4 rounded-full bg-white/5 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-1000 ${rate > 70 ? "bg-emerald-500" : rate > 40 ? "bg-amber-500" : "bg-red-500"}`}
                      style={{ width: `${Math.min(rate, 100)}%` }}
                    />
                  </div>
                  <span className={`text-lg font-bold tabular-nums ${rate > 50 ? "text-emerald-400" : "text-red-400"}`}>{rate}%</span>
                </div>
                <div className="text-xs text-[var(--muted)] leading-relaxed">
                  {rate === 0 && "Nenhum report processado ainda. Submeta seu primeiro report para começar a rastrear."}
                  {rate > 0 && rate <= 30 && "Taxa baixa. Dicas: inclua mais evidências (screenshots, cURL), escreva steps claros e detalhe o impacto de negócio."}
                  {rate > 30 && rate <= 60 && "Taxa razoável. Use a AI para melhorar a qualidade: ela adiciona CVSS, CWE, impacto regulatório e remediação."}
                  {rate > 60 && rate <= 85 && "Boa taxa! Seus reports estão acima da média. Continue focando em vulns critical/high para maximizar bounties."}
                  {rate > 85 && "Excelente! Taxa profissional. Seus reports são consistentemente aceitos. Foque em programas com bounty alto."}
                </div>
              </div>

              {/* By severity */}
              {reportStats?.by_severity && Object.keys(reportStats.by_severity).length > 0 && (
                <div>
                  <div className="text-[11px] text-[var(--muted)] uppercase font-semibold mb-3">Reports por Severidade</div>
                  <div className="space-y-2">
                    {Object.entries(reportStats.by_severity).sort(([a], [b]) => {
                      const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                      return (order[a] ?? 5) - (order[b] ?? 5);
                    }).map(([sev, count]) => {
                      const maxCount = Math.max(...Object.values(reportStats.by_severity).map(Number), 1);
                      const colors: Record<string, string> = { critical: "bg-red-500", high: "bg-orange-500", medium: "bg-amber-500", low: "bg-sky-500", info: "bg-slate-500" };
                      return (
                        <div key={sev} className="flex items-center gap-3">
                          <span className={`text-[10px] font-bold uppercase w-16 sev-${sev} px-2 py-1 rounded text-center`}>{sev}</span>
                          <div className="flex-1 h-2.5 rounded-full bg-white/5 overflow-hidden">
                            <div className={`h-full rounded-full transition-all duration-700 ${colors[sev] || "bg-slate-500"}`} style={{ width: `${(Number(count) / maxCount) * 100}%` }} />
                          </div>
                          <span className="text-sm font-bold text-[var(--foreground)] tabular-nums w-8 text-right">{count as number}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Platforms */}
              <div>
                <div className="text-[11px] text-[var(--muted)] uppercase font-semibold mb-3">Plataformas Suportadas</div>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { name: "HackerOne", icon: "🟢", c: "border-green-500/20 bg-green-500/5 text-green-400", auto: true, desc: "Envio automático via API. Configure HACKERONE_API_USERNAME e HACKERONE_API_TOKEN no .env." },
                    { name: "Bugcrowd", icon: "🟠", c: "border-orange-500/20 bg-orange-500/5 text-orange-400", auto: false, desc: "Sem API para researchers. Use o botão 'Copy for Bugcrowd' e cole no formulário do site." },
                    { name: "Intigriti", icon: "🔵", c: "border-blue-500/20 bg-blue-500/5 text-blue-400", auto: false, desc: "API para listar programas (configure INTIGRITI_API_TOKEN). Reports são copiados e colados." },
                    { name: "YesWeHack", icon: "🟡", c: "border-yellow-500/20 bg-yellow-500/5 text-yellow-400", auto: false, desc: "API com Personal Access Token. Reports formatados para copiar e colar no formulário." },
                  ].map(p => (
                    <div key={p.name} className={`rounded-xl border p-3 ${p.c}`}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-semibold">{p.icon} {p.name}</span>
                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${p.auto ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/20" : "bg-white/5 text-[var(--muted)] border border-white/10"}`}>
                          {p.auto ? "AUTO" : "MANUAL"}
                        </span>
                      </div>
                      <div className="text-[10px] opacity-70 leading-relaxed">{p.desc}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Step by step guide */}
              <div>
                <div className="text-[11px] text-[var(--muted)] uppercase font-semibold mb-3">Como Enviar um Report</div>
                <div className="space-y-3">
                  {[
                    { step: "1", title: "Rodar Recon", desc: "Vá na aba Programs, selecione um programa e clique no botão Recon. O pipeline descobre subdomínios, verifica quais estão vivos, e roda security checks automaticamente.", icon: "🔍" },
                    { step: "2", title: "Revisar Findings", desc: "Abra um target com findings (badge numérico). Revise cada vulnerabilidade: título, severidade e evidência. Filtre por HIGH/CRITICAL para focar nas que pagam mais.", icon: "🔎" },
                    { step: "3", title: "Gerar Report", desc: "Clique em 'Generate Report' no target. A AI (Ollama) ou o template engine cria um report profissional com título, CVSS 3.1, Steps to Reproduce, Proof of Concept e remediação.", icon: "🧠" },
                    { step: "4", title: "Copiar para a Plataforma", desc: "Escolha o botão da plataforma desejada (HackerOne, Bugcrowd, Intigriti, YesWeHack ou Markdown). O report é formatado especificamente para cada uma. Cole no formulário de submissão.", icon: "📋" },
                    { step: "5", title: "Acompanhar Status", desc: "Após enviar, acompanhe aqui o status: Submitted → Triaged → Accepted → Bounty Paid. A taxa de aceitação ajuda a medir a qualidade dos seus reports.", icon: "💰" },
                  ].map(s => (
                    <div key={s.step} className="flex gap-3">
                      <div className="shrink-0 w-8 h-8 rounded-full bg-violet-500/15 border border-violet-500/25 flex items-center justify-center text-sm font-bold text-violet-400">{s.step}</div>
                      <div className="min-w-0 pt-0.5">
                        <div className="text-sm font-semibold text-[var(--foreground)] mb-0.5">{s.icon} {s.title}</div>
                        <div className="text-xs text-[var(--muted)] leading-relaxed">{s.desc}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

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
  const [activeTab, setActiveTab] = useState<"overview" | "programs" | "vulns">("overview");

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
    ]);
    if (results[0].status === "fulfilled") setScanners(results[0].value);
    if (results[1].status === "fulfilled") setRoi(results[1].value);
    if (results[2].status === "fulfilled") setPrograms(results[2].value);
    if (results[3].status === "fulfilled") setChanges(results[3].value);
    if (results[4].status === "fulfilled") setReportStats(results[4].value);
    if (results[5].status === "fulfilled") setRecentCVEs(results[5].value);
    if (results[6].status === "fulfilled") setBlindVulns(results[6].value);
    if (results[7].status === "fulfilled") setAiStats(results[7].value);
  }, []);

  useEffect(() => {
    loadFast();
    loadSlow();
    const fastId = setInterval(loadFast, 15000);
    const slowId = setInterval(loadSlow, 30000);
    return () => { clearInterval(fastId); clearInterval(slowId); };
  }, [loadFast, loadSlow]);

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
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
            <Tooltip text={"Vulnerabilidades critical + high.\nSão as que geram os maiores bounties.\nFoque nelas para maximizar ganhos."}>
              <MetricCard accentColor="#ef4444" bg="linear-gradient(135deg, rgba(239,68,68,0.08) 0%, var(--card) 70%)" className="ring-1 ring-red-500/15">
                <Metric icon="🔴" label="Critical + High" value={(sev?.critical ?? 0) + (sev?.high ?? 0)} color="text-red-400" sub={`${sev?.critical ?? 0} crit / ${sev?.high ?? 0} high`} />
              </MetricCard>
            </Tooltip>

            <Tooltip text={"Total ganho em bounties.\nInclui todos os programas e plataformas.\nAtualizado automaticamente via ROI Tracker."}>
              <MetricCard accentColor="#10b981" bg="linear-gradient(135deg, rgba(16,185,129,0.08) 0%, var(--card) 70%)" className="ring-1 ring-emerald-500/15">
                <Metric icon="💰" label="Earnings" value={roi ? `$${roi.summary.total_earnings.toLocaleString()}` : "$0"} color="text-emerald-400" sub={roi?.summary.highest_payout ? `max $${roi.summary.highest_payout}` : ""} />
              </MetricCard>
            </Tooltip>

            <Tooltip text={"Total de vulnerabilidades detectadas.\nInclui critical, high, medium, low e info.\nDetectadas por Nuclei, Nmap, dalfox, sqlmap."}>
              <MetricCard accentColor="#f59e0b" bg="linear-gradient(135deg, rgba(245,158,11,0.06) 0%, var(--card) 70%)">
                <Metric icon="⚠️" label="Total Vulns" value={vuln?.total_vulns ?? 0} color="text-amber-400" sub={sev ? `${sev.critical}C ${sev.high}H ${sev.medium}M` : ""} />
              </MetricCard>
            </Tooltip>

            <Tooltip text={"Targets vivos (respondendo HTTP).\nSão os alvos ativos prontos para scan.\nTargets offline são ignorados."}>
              <MetricCard accentColor="#06b6d4" bg="linear-gradient(135deg, rgba(6,182,212,0.06) 0%, var(--card) 70%)">
                <Metric icon="🎯" label="Alive Targets" value={bounty?.alive_targets ?? 0} color="text-cyan-400" sub={`${bounty?.targets ?? 0} total / ${bounty?.new_targets ?? 0} novos`} />
              </MetricCard>
            </Tooltip>

            <Tooltip text={"Programas cadastrados de todas as plataformas.\nHackerOne, Bugcrowd, Intigriti, YesWeHack.\nUse Score Programs para priorizar."}>
              <MetricCard accentColor="#6366f1" bg="linear-gradient(135deg, rgba(99,102,241,0.06) 0%, var(--card) 70%)">
                <Metric icon="📋" label="Programs" value={bounty?.programs ?? 0} color="text-[var(--accent-light)]" sub={`${bounty?.programs_with_bounty ?? 0} com bounty`} />
              </MetricCard>
            </Tooltip>
          </div>

          {/* ══════════ ROW 1b: Secondary Metrics ══════════ */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
            <Tooltip text={"Reports submetidos às plataformas.\nInclui enviados, com erro e pendentes.\nGere reports em Programs > Target."}>
              <MetricCard accentColor="#8b5cf6" bg="linear-gradient(135deg, rgba(139,92,246,0.05) 0%, var(--card) 70%)">
                <Metric icon="📝" label="Reports" value={reportStats?.total ?? 0} color="text-violet-400" sub={`${reportStats?.submitted ?? 0} ok / ${reportStats?.errors ?? 0} err`} />
              </MetricCard>
            </Tooltip>

            <Tooltip text={"Taxa de aceitação dos reports.\nReports aceitos / total submetidos.\nAcima de 50% é considerado bom."}>
              <MetricCard accentColor={(roi?.operations.acceptance_rate ?? 0) > 50 ? "#10b981" : "#ef4444"} bg={`linear-gradient(135deg, ${(roi?.operations.acceptance_rate ?? 0) > 50 ? "rgba(16,185,129,0.05)" : "rgba(239,68,68,0.05)"} 0%, var(--card) 70%)`}>
                <Metric icon="✅" label="Acceptance" value={roi ? `${roi.operations.acceptance_rate}%` : "–"} color={(roi?.operations.acceptance_rate ?? 0) > 50 ? "text-emerald-400" : "text-red-400"} />
              </MetricCard>
            </Tooltip>

            <Tooltip text={"Subdomínios descobertos pelo recon.\nEncontrados via subfinder, crt.sh, rDNS, ASN.\nNovos subdomínios têm menos proteção."}>
              <MetricCard accentColor="#06b6d4" bg="linear-gradient(135deg, rgba(6,182,212,0.04) 0%, var(--card) 70%)">
                <Metric icon="🔍" label="Subdomains" value={recon?.subdomains_found ?? 0} color="text-cyan-400" sub={`${recon?.new_subdomains_detected ?? 0} novos`} />
              </MetricCard>
            </Tooltip>

            <Tooltip text={"Valor médio recebido por bounty.\nTotal earnings dividido por reports pagos.\nAjuda a escolher programas lucrativos."}>
              <MetricCard accentColor="#eab308" bg="linear-gradient(135deg, rgba(234,179,8,0.04) 0%, var(--card) 70%)">
                <Metric icon="📈" label="Avg Payout" value={roi ? `$${roi.summary.avg_payout}` : "$0"} color="text-yellow-400" />
              </MetricCard>
            </Tooltip>

            <Tooltip text={"Novos targets do último recon.\nSubdomínios que não existiam antes.\nAlvos novos costumam ter mais vulns."}>
              <MetricCard accentColor="#84cc16" bg="linear-gradient(135deg, rgba(132,204,22,0.04) 0%, var(--card) 70%)">
                <Metric icon="🆕" label="New Targets" value={bounty?.new_targets ?? 0} color="text-lime-400" sub={`${bounty?.total_changes ?? 0} changes`} />
              </MetricCard>
            </Tooltip>
          </div>

          {/* ══════════ ROW 2: Vulns + Recon + Report Submit ══════════ */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-2 items-stretch">

            {/* Vulnerabilities Breakdown */}
            <Tooltip className="lg:col-span-4" text={"Painel de vulnerabilidades por severidade.\nMostra total, breakdown CRIT/HIGH/MED/LOW,\ntop vulns encontradas e status do Nuclei/Nmap.\nBlind vulns são confirmadas via Interactsh."}>
            <Card title="Vulnerabilities" accent="text-amber-400" glow="rgba(245, 158, 11, 0.06)">
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
            </Tooltip>

            {/* Recon Pipeline */}
            <Tooltip className="lg:col-span-4" text={"Pipeline de reconhecimento automático.\nRoda subfinder, crt.sh, httpx, dnsx, rDNS.\nDescobre subdomínios e verifica quais estão vivos.\nNovos targets são priorizados para scan."}>
            <Card title="Recon Pipeline" accent="text-cyan-400" glow="rgba(6, 182, 212, 0.06)">
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
            </Tooltip>

            {/* Report Submission (expandable) */}
            <ReportSubmissionCard
              reportStats={reportStats}
              roi={roi}
            />

          </div>

          {/* ══════════ ROW 3: AI Analyzer ══════════ */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-2">
            <Tooltip className="lg:col-span-12" text={"Modelo de IA local (Ollama) para:\n• Gerar reports profissionais\n• Classificar true/false positives\n• Analisar HTTP responses\n• Encontrar vulnerability chains"}>
            <Card title="AI Analyzer" accent="text-fuchsia-400" glow="rgba(192, 38, 211, 0.06)">
              {aiStats ? (
                <div className="flex items-center gap-6 flex-wrap">
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${aiStats.enabled ? "bg-emerald-400 pulse-live" : "bg-red-400"}`} />
                    <span className={`text-xs font-medium ${aiStats.enabled ? "text-emerald-400" : "text-red-400"}`}>
                      {aiStats.enabled ? "Active" : "Disabled"}
                    </span>
                    {aiStats.model && (
                      <span className="text-[10px] text-[var(--muted)] bg-white/5 px-1.5 py-0.5 rounded font-mono">{aiStats.model}</span>
                    )}
                  </div>
                  <div className="flex items-center gap-4 text-xs">
                    <span className="text-[var(--muted)]">Reports <span className="text-fuchsia-400 font-bold">{aiStats.reports_generated}</span></span>
                    <span className="text-[var(--muted)]">Classified <span className="text-violet-400 font-bold">{aiStats.findings_classified}</span></span>
                    <span className="text-[var(--muted)]">Analyzed <span className="text-cyan-400 font-bold">{aiStats.responses_analyzed}</span></span>
                    <span className="text-[var(--muted)]">Requests <span className="text-[var(--foreground)] font-bold">{aiStats.requests}</span></span>
                    {aiStats.tokens_used > 0 && <span className="text-[var(--muted)]">Tokens <span className="text-amber-400 font-bold">{aiStats.tokens_used.toLocaleString()}</span></span>}
                    {aiStats.errors > 0 && <span className="text-[var(--muted)]">Errors <span className="text-red-400 font-bold">{aiStats.errors}</span></span>}
                  </div>
                </div>
              ) : (
                <div className="text-xs text-[var(--muted)]">Configure AI_PROVIDER in .env</div>
              )}
            </Card>
            </Tooltip>
          </div>

          {/* ══════════ ROW 4: Program Rankings + Activity Feed + Intelligence ══════════ */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-2">

            {/* Program Rankings */}
            <Tooltip className="lg:col-span-4" text={"Programas rankeados por atratividade.\nTier S/A = melhores oportunidades.\nScore considera: bounty, escopo,\ncompetição e targets ativos.\nUse 'Score Programs' para atualizar."}>
            <Card title="Program Rankings" accent="text-[var(--accent-light)]"
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
            </Tooltip>

            {/* Recent Activity */}
            <Tooltip className="lg:col-span-4" text={"Mudanças de subdomínios detectadas.\n+N = novos subdomínios encontrados.\n-N = subdomínios que sumiram.\nSubdomínios novos são priorizados."}>
            <Card title="Recent Activity" accent="text-lime-400">
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
            </Tooltip>

            {/* Intelligence */}
            <Tooltip className="lg:col-span-4" text={"Inteligência de ROI e mercado.\n• Earnings Trend: ganhos mensais.\n• Top Earners: programas mais lucrativos.\n• Best Vuln Types: tipos que pagam mais.\n• CVEs recentes para explorar."}>
            <Card title="Intelligence" accent="text-teal-400" glow="rgba(20, 184, 166, 0.06)">
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
            </Tooltip>
          </div>

          {/* ══════════ ROW 5: Reports + Tools Pipeline ══════════ */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-2">
            <Tooltip className="lg:col-span-4" text={"Estatísticas de reports enviados.\nSubmitted = aceitos pela plataforma.\nErrors = falha no envio.\nPending = aguardando processamento."}>
            <Card title="Report Stats" accent="text-violet-400" glow="rgba(139, 92, 246, 0.06)">
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
            </Tooltip>

            <Tooltip className="lg:col-span-8" text={"Todas as ferramentas do pipeline.\nRecon: subfinder, crt.sh, httpx, katana, gau.\nScan: nuclei, nmap, dalfox, ffuf, sqlmap.\nAvançado: IDOR, SSRF, GraphQL, Race.\nMonitor: CT logs, CVE feeds, Interactsh."}>
            <Card title="Tools Pipeline" accent="text-pink-400">
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
            </Tooltip>
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
