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
  fetchBountyPrograms,
  triggerBountyRecon,
  scoreAllPrograms,
  discoverH1Programs,
  triggerCTCheck,
  triggerCVECheck,
  recordEarning,
  importIntigrtiPrograms,
  type HealthInfo,
  type BountyStats,
  type VulnStats,
  type ScannerStats,
  type ROIDashboard,
  type PrioritizedProgram,
  type BountyChange,
  type SubmittedReportsStats,
  type AIStats,
  type BountyProgram,
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
  const [allPrograms, setAllPrograms] = useState<BountyProgram[]>([]);
  const [reconTriggering, setReconTriggering] = useState<Set<string>>(new Set());
  const [actionMsg, setActionMsg] = useState("");
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
      fetchBountyPrograms(),
    ]);
    if (results[0].status === "fulfilled") setScanners(results[0].value);
    if (results[1].status === "fulfilled") setRoi(results[1].value);
    if (results[2].status === "fulfilled") setPrograms(results[2].value);
    if (results[3].status === "fulfilled") setChanges(results[3].value);
    if (results[4].status === "fulfilled") setReportStats(results[4].value);
    if (results[5].status === "fulfilled") setRecentCVEs(results[5].value);
    if (results[6].status === "fulfilled") setBlindVulns(results[6].value);
    if (results[7].status === "fulfilled") setAiStats(results[7].value);
    if (results[8].status === "fulfilled") setAllPrograms(results[8].value);
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
          {/* ══════════ PIPELINE: 8 Etapas do Relatório ══════════ */}
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2">
            {[
              { step: 1, icon: "📋", label: "Programas", val: bounty?.programs ?? 0, done: (bounty?.programs ?? 0) > 0, sub: `${bounty?.programs_with_bounty ?? 0} bounty`, color: "#6366f1", bg: "rgba(99,102,241,0.06)", tip: "Programas importados de HackerOne,\nBugcrowd, Intigriti, YesWeHack, BugHunt.\nUse Quick Actions para importar mais." },
              { step: 2, icon: "🔍", label: "Recon", val: recon?.recons_completed ?? 0, done: (recon?.recons_completed ?? 0) > 0, sub: `${recon?.subdomains_found ?? 0} subs`, color: "#06b6d4", bg: "rgba(6,182,212,0.06)", tip: "Reconhecimento automático.\nsubfinder, crt.sh, httpx, dnsx, rDNS.\nDescobre subdomínios e verifica alive." },
              { step: 3, icon: "🎯", label: "Targets", val: bounty?.alive_targets ?? 0, done: (bounty?.alive_targets ?? 0) > 0, sub: `${bounty?.targets ?? 0} total`, color: "#10b981", bg: "rgba(16,185,129,0.06)", tip: "Targets vivos respondendo HTTP.\nAlvos ativos prontos para scan.\n+ novos = menos proteção." },
              { step: 4, icon: "⚠️", label: "Vulns", val: vuln?.total_vulns ?? 0, done: (vuln?.total_vulns ?? 0) > 0, sub: sev ? `${sev.critical}C ${sev.high}H` : "", color: "#f59e0b", bg: "rgba(245,158,11,0.06)", tip: "Vulnerabilidades encontradas.\nNuclei, Nmap, dalfox, sqlmap.\nCritical + High geram mais bounty." },
              { step: 5, icon: "📝", label: "Reports", val: reportStats?.total ?? 0, done: (reportStats?.total ?? 0) > 0, sub: `${reportStats?.submitted ?? 0} sent`, color: "#8b5cf6", bg: "rgba(139,92,246,0.06)", tip: "Reports gerados pela AI ou template.\nInclui título, CVSS, PoC, steps,\nimpacto e remediação." },
              { step: 6, icon: "📤", label: "Enviados", val: reportStats?.submitted ?? 0, done: (reportStats?.submitted ?? 0) > 0, sub: `${reportStats?.errors ?? 0} err`, color: "#3b82f6", bg: "rgba(59,130,246,0.06)", tip: "Reports submetidos às plataformas.\nHackerOne (auto), Bugcrowd (copy),\nIntigriti, YesWeHack, BugHunt." },
              { step: 7, icon: "✅", label: "Aceitos", val: roi?.operations.reports_accepted ?? 0, done: (roi?.operations.reports_accepted ?? 0) > 0, sub: `${roi?.operations.acceptance_rate ?? 0}%`, color: "#10b981", bg: "rgba(16,185,129,0.06)", tip: "Reports aceitos pelo triager.\nTaxa de aceitação acima de 50%\né considerada boa." },
              { step: 8, icon: "💰", label: "Bounty", val: roi ? `$${roi.summary.total_earnings}` : "$0", done: (roi?.summary.total_earnings ?? 0) > 0, sub: roi?.summary.highest_payout ? `max $${roi.summary.highest_payout}` : "", color: "#10b981", bg: "rgba(16,185,129,0.08)", tip: "Bounties recebidos.\nTotal ganho em todas as plataformas.\nAcompanhe seu ROI por programa." },
            ].map(s => (
              <Tooltip key={s.step} text={s.tip}>
                <div className={`metric-card rounded-xl border p-3 card-glow h-full ${s.done ? "border-[var(--border)]" : "border-[var(--border)] opacity-60"}`}
                  style={{ "--metric-accent": s.color, background: `linear-gradient(135deg, ${s.bg} 0%, var(--card) 70%)` } as React.CSSProperties}>
                  <div className="flex items-center gap-1 mb-1">
                    <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[9px] shrink-0 ${
                      s.done ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" : "bg-white/5 text-[var(--muted)] border border-[var(--border)]"
                    }`}>{s.done ? "✓" : s.step}</span>
                    <span className="text-base">{s.icon}</span>
                  </div>
                  <div className={`text-xl font-bold tabular-nums leading-none ${s.done ? "text-[var(--foreground)]" : "text-[var(--muted)]"}`}>
                    {typeof s.val === "number" ? s.val.toLocaleString() : s.val}
                  </div>
                  <div className="text-[9px] text-[var(--muted)] mt-1 uppercase tracking-wider truncate">{s.label}</div>
                  <div className="text-[9px] text-[var(--muted)] mt-0.5 truncate h-3">{s.sub}</div>
                </div>
              </Tooltip>
            ))}
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

          {/* ══════════ ROW 3b: Recon Live + Quick Actions ══════════ */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-2 items-stretch">

          <Tooltip className="lg:col-span-8" text={"Programas e status do recon.\nClique Recon para disparar manualmente.\nO auto-recon roda a cada 4 horas.\nVerde = com targets, azul = rodando."}>
          <Card title="Recon Live" accent="text-cyan-400"
            action={
              <div className="flex items-center gap-2">
                {allPrograms.filter(p => p.status === "reconning").length > 0 && (
                  <span className="flex items-center gap-1 text-[10px] text-blue-400">
                    <span className="w-1.5 h-1.5 rounded-full bg-blue-400 pulse-live" />
                    {allPrograms.filter(p => p.status === "reconning").length} running
                  </span>
                )}
                <span className="text-[10px] text-[var(--muted)]">{allPrograms.length} programs</span>
              </div>
            }>
            {allPrograms.length > 0 ? (
              <div className="space-y-1 max-h-48 overflow-y-auto hide-scrollbar">
                {allPrograms.map(p => {
                  const isRunning = p.status === "reconning" || reconTriggering.has(p.id);
                  const hasTargets = (p.target_count ?? 0) > 0;
                  const hasVulns = (p.vuln_count ?? 0) > 0;
                  return (
                    <div key={p.id} className="flex items-center gap-2 py-1.5 px-2 rounded-lg hover:bg-white/[0.02] transition-colors group">
                      <span className={`w-2 h-2 rounded-full shrink-0 ${
                        isRunning ? "bg-blue-400 animate-pulse" :
                        p.status === "error" ? "bg-red-400" :
                        hasTargets ? "bg-emerald-400" : "bg-[var(--muted)]"
                      }`} />
                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-medium text-[var(--foreground)] truncate">{p.name}</div>
                      </div>
                      <div className="flex items-center gap-2 text-[10px] tabular-nums shrink-0">
                        <span className="text-[var(--muted)]">{p.platform}</span>
                        {hasTargets && <span className="text-emerald-400">{p.alive_count}a/{p.target_count}t</span>}
                        {hasVulns && <span className="text-red-400">{p.vuln_count}v</span>}
                      </div>
                      <button
                        onClick={async () => {
                          if (isRunning) return;
                          setReconTriggering(prev => new Set(prev).add(p.id));
                          try { await triggerBountyRecon(p.id); } catch {}
                          setTimeout(() => setReconTriggering(prev => { const n = new Set(prev); n.delete(p.id); return n; }), 3000);
                        }}
                        disabled={isRunning}
                        className={`text-[10px] font-semibold px-2 py-1 rounded-md transition-all ${
                          isRunning
                            ? "bg-blue-500/10 text-blue-400 cursor-wait"
                            : "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 opacity-0 group-hover:opacity-100"
                        }`}
                      >
                        {isRunning ? "..." : "Recon"}
                      </button>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-xs text-[var(--muted)] text-center py-4">Nenhum programa cadastrado. Vá em Programs para adicionar.</div>
            )}
          </Card>
          </Tooltip>

          {/* Quick Actions */}
          <Tooltip className="lg:col-span-4" text={"Ações rápidas para o scanner.\nDescobrir programas, importar,\nscorear, verificar CT/CVE.\nRegistrar bounty recebido."}>
          <Card title="Quick Actions" accent="text-blue-400" glow="rgba(59, 130, 246, 0.06)">
            <div className="space-y-1">
              {[
                { label: "🔍 Discover H1 Programs", fn: async () => { const r = await discoverH1Programs(); setActionMsg(`Found ${r.new_programs_found}, imported ${r.auto_imported}`); } },
                { label: "📊 Score Programs", fn: async () => { const r = await scoreAllPrograms(); setActionMsg(`Scored ${r.scored} programs`); } },
                { label: "📜 Check CT Logs", fn: async () => { const r = await triggerCTCheck(); setActionMsg(`${r.new_domains_found} new domains`); } },
                { label: "🛡 Check CVE Feeds", fn: async () => { const r = await triggerCVECheck(); setActionMsg(`${r.templates_created} templates`); } },
                { label: "🔵 Import Intigriti", fn: async () => { const r = await importIntigrtiPrograms(); setActionMsg(`Intigriti: ${r.imported} new, ${r.updated} updated`); } },
                { label: "🔄 Recon All", fn: async () => {
                  const eligible = allPrograms.filter(p => p.status !== "reconning");
                  setActionMsg(`Starting recon on ${eligible.length} programs...`);
                  for (const p of eligible) {
                    try { await triggerBountyRecon(p.id); } catch {}
                  }
                  setActionMsg(`Recon started on ${eligible.length} programs`);
                }},
              ].map(a => (
                <button key={a.label} onClick={() => a.fn().catch(e => setActionMsg(`Error: ${e.message}`))}
                  className="w-full text-left text-xs px-2.5 py-2 rounded-lg hover:bg-white/[0.03] text-[var(--muted)] hover:text-[var(--foreground)] transition-all">
                  {a.label}
                </button>
              ))}
            </div>
            {actionMsg && <div className="text-[10px] text-emerald-400 px-2 py-1.5 mt-1 bg-emerald-500/5 rounded-lg">{actionMsg}</div>}

            {/* Record Earning */}
            <div className="border-t border-[var(--border)] pt-2 mt-2">
              <div className="text-[10px] text-[var(--muted)] uppercase font-semibold mb-1.5">Record Earning</div>
              <div className="flex gap-1">
                <input type="text" id="earn-prog" placeholder="Program"
                  className="flex-1 !text-xs !py-1 !px-2 !rounded-lg !border-[var(--border)] !bg-[var(--background)]" />
                <input type="number" id="earn-amt" placeholder="$"
                  className="w-16 !text-xs !py-1 !px-2 !rounded-lg !border-[var(--border)] !bg-[var(--background)]" />
                <button onClick={async () => {
                  const prog = (document.getElementById("earn-prog") as HTMLInputElement)?.value;
                  const amt = parseFloat((document.getElementById("earn-amt") as HTMLInputElement)?.value || "0");
                  if (!amt || !prog) return;
                  await recordEarning({ program_id: "", program_name: prog, amount: amt });
                  (document.getElementById("earn-prog") as HTMLInputElement).value = "";
                  (document.getElementById("earn-amt") as HTMLInputElement).value = "";
                  setActionMsg(`Recorded $${amt}`);
                }} className="text-[10px] px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-medium transition-colors">+</button>
              </div>
            </div>
          </Card>
          </Tooltip>

          </div>

          {/* ══════════ ROW 4: Rankings + Activity + Intelligence ══════════ */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-2 items-stretch">

            {/* Program Rankings */}
            <Tooltip className="lg:col-span-4" text={"Programas rankeados por atratividade.\nTier S/A = melhores oportunidades.\nScore considera: bounty, escopo,\ncompetição e targets ativos.\nUse 'Score Programs' para atualizar."}>
            <Card title="Program Rankings" accent="text-[var(--accent-light)]"
              action={<span className="text-[10px] text-[var(--muted)]">{programs.length}</span>}
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
