"use client";

import { Component, type ReactNode, useEffect, useState, useCallback, useRef } from "react";
import BountyPanel from "@/components/BountyPanel";
import VulnPanel from "@/components/VulnPanel";
import {
  fetchBountyStats,
  fetchVulnStats,
  fetchROIDashboard,
  fetchPrioritizedPrograms,
  fetchRecentChanges,
  fetchSubmittedReportsStats,
  fetchRecentCVEs,
  fetchAIStats,
  fetchBountyPrograms,
  triggerBountyRecon,
  scoreAllPrograms,
  discoverH1Programs,
  triggerCTCheck,
  triggerCVECheck,
  recordEarning,
  importIntigrtiPrograms,
  fetchVulnResults,
  fetchActivityLogs,
  type VulnResult,
  type ActivityLogEntry,
  type BountyStats,
  type VulnStats,
  type ROIDashboard,
  type PrioritizedProgram,
  type BountyChange,
  type SubmittedReportsStats,
  type AIStats,
  type BountyProgram,
  fetchWatcherStatus,
  triggerWatcherCheck,
  triggerWatcherCheckSingle,
  fetchBugHuntPrograms,
  type WatcherStatusResponse,
  type WatcherCheckResponse,
  type BugHuntProgram,
  fetchH1Stats,
  fetchH1Queue,
  triggerH1AutoSubmit,
  type H1Stats,
  type H1QueueItem,
} from "@/lib/api";
import Modal from "@/components/Modal";

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

function Card({ children, className = "", title, accent, action, glow, onClick, clickHint }: {
  children: ReactNode; className?: string; title?: string; accent?: string;
  action?: ReactNode; glow?: string; onClick?: () => void; clickHint?: string;
}) {
  return (
    <div className={`rounded-xl border border-[var(--border)] bg-[var(--card)] p-4 card-glow h-full ${onClick ? 'cursor-pointer hover:border-[var(--accent)]/30 transition-all duration-200 group/card' : ''} ${className}`}
      style={glow ? { boxShadow: `inset 0 1px 0 0 ${glow}` } : undefined}
      onClick={onClick}>
      {title && (
        <div className="flex items-center justify-between mb-3">
          <h3 className={`text-xs font-semibold uppercase tracking-wider ${accent || "text-[var(--muted)]"}`}>{title}</h3>
          <div className="flex items-center gap-2">
            {action}
            {onClick && (
              <span className="text-[9px] text-[var(--muted)] opacity-0 group-hover/card:opacity-100 transition-opacity flex items-center gap-1">
                {clickHint || "detalhes"} <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" /></svg>
              </span>
            )}
          </div>
        </div>
      )}
      {children}
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

            <div className="p-3 sm:p-4 md:p-6 space-y-4 sm:space-y-6">
              {/* Status cards */}
              <div>
                <div className="text-[11px] text-[var(--muted)] uppercase font-semibold mb-3">Status dos Reports</div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 sm:gap-3">
                  {[
                    { label: "Submitted", val: submitted, c: "text-violet-400", bg: "bg-violet-500/8 border-violet-500/15", desc: "Enviados com sucesso à plataforma de bug bounty." },
                    { label: "Accepted", val: accepted, c: "text-emerald-400", bg: "bg-emerald-500/8 border-emerald-500/15", desc: "Aceitos pelo triager. Elegíveis para receber bounty." },
                    { label: "Failed", val: failed, c: "text-red-400", bg: "bg-red-500/8 border-red-500/15", desc: "Erro no envio: credenciais inválidas, fora do escopo, ou duplicado." },
                    { label: "Pending", val: pending, c: "text-amber-400", bg: "bg-amber-500/8 border-amber-500/15", desc: "Aguardando análise do triager. Tempo médio: 1-7 dias." },
                  ].map(s => (
                    <Tooltip key={s.label} text={s.desc}>
                      <div className={`text-center p-2 sm:p-4 rounded-xl border ${s.bg}`}>
                        <div className={`text-xl sm:text-3xl font-bold tabular-nums ${s.c}`}>{s.val}</div>
                        <div className="text-[8px] sm:text-[9px] text-[var(--muted)] uppercase mt-1">{s.label}</div>
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
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 sm:gap-3">
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
  const [bounty, setBounty] = useState<BountyStats | null>(null);
  const [vuln, setVuln] = useState<VulnStats | null>(null);
  const [roi, setRoi] = useState<ROIDashboard | null>(null);
  const [programs, setPrograms] = useState<PrioritizedProgram[]>([]);
  const [changes, setChanges] = useState<BountyChange[]>([]);
  const [reportStats, setReportStats] = useState<SubmittedReportsStats | null>(null);
  const [recentCVEs, setRecentCVEs] = useState<any[]>([]);
  const [aiStats, setAiStats] = useState<AIStats | null>(null);
  const [allPrograms, setAllPrograms] = useState<BountyProgram[]>([]);
  const [reconTriggering, setReconTriggering] = useState<Set<string>>(new Set());
  const [actionMsg, setActionMsg] = useState("");
  const [activeTab, setActiveTab] = useState<"overview" | "programs" | "vulns">("overview");
  const [activityLogs, setActivityLogs] = useState<ActivityLogEntry[]>([]);
  const [logsPaused, setLogsPaused] = useState(false);
  const termRef = useRef<HTMLDivElement>(null);
  const [bughuntPrograms, setBughuntPrograms] = useState<BugHuntProgram[]>([]);
  const [bughuntExpanded, setBughuntExpanded] = useState<string | null>(null);
  const [h1Stats, setH1Stats] = useState<H1Stats | null>(null);
  const [h1Queue, setH1Queue] = useState<H1QueueItem[]>([]);
  const [h1Submitting, setH1Submitting] = useState(false);
  const [h1Msg, setH1Msg] = useState("");
  const [activeModal, setActiveModal] = useState<string | null>(null);

  const loadFast = useCallback(async () => {
    const results = await Promise.allSettled([
      fetchBountyStats(),
      fetchVulnStats(),
    ]);
    if (results[0].status === "fulfilled") setBounty(results[0].value);
    if (results[1].status === "fulfilled") setVuln(results[1].value);
  }, []);

  const loadSlow = useCallback(async () => {
    const results = await Promise.allSettled([
      fetchROIDashboard(),
      fetchPrioritizedPrograms(0),
      fetchRecentChanges(10),
      fetchSubmittedReportsStats(),
      fetchRecentCVEs(),
      fetchAIStats(),
      fetchBountyPrograms(),
    ]);
    if (results[0].status === "fulfilled") setRoi(results[0].value);
    if (results[1].status === "fulfilled") setPrograms(results[1].value);
    if (results[2].status === "fulfilled") setChanges(results[2].value);
    if (results[3].status === "fulfilled") setReportStats(results[3].value);
    if (results[4].status === "fulfilled") setRecentCVEs(results[4].value);
    if (results[5].status === "fulfilled") setAiStats(results[5].value);
    if (results[6].status === "fulfilled") setAllPrograms(results[6].value);
    // BugHunt programs
    try {
      const bh = await fetchBugHuntPrograms({ limit: 200 });
      setBughuntPrograms(bh.programs || []);
    } catch { /* silent */ }
    // H1 Auto-Submit stats
    try {
      const [stats, queue] = await Promise.all([fetchH1Stats(), fetchH1Queue()]);
      setH1Stats(stats);
      setH1Queue(queue.reports || []);
    } catch { /* silent */ }
  }, []);

  useEffect(() => {
    loadFast();
    loadSlow();
    const fastId = setInterval(loadFast, 15000);
    const slowId = setInterval(loadSlow, 30000);
    return () => { clearInterval(fastId); clearInterval(slowId); };
  }, [loadFast, loadSlow]);

  /* ── Activity log polling ── */
  useEffect(() => {
    if (logsPaused) return;
    let cancelled = false;
    const poll = async () => {
      try {
        const res = await fetchActivityLogs(60);
        if (!cancelled) {
          setActivityLogs(res.logs);
          // auto-scroll
          requestAnimationFrame(() => {
            if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
          });
        }
      } catch { /* silent */ }
    };
    poll();
    const id = setInterval(poll, 3000);
    return () => { cancelled = true; clearInterval(id); };
  }, [logsPaused]);

  const recon = bounty?.recon;
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
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            className={`px-4 py-2 text-xs font-medium rounded-lg transition-all flex items-center gap-1.5 ${
              activeTab === t.id
                ? "bg-[var(--accent)]/15 text-[var(--accent-light)] shadow-sm shadow-[var(--accent)]/10"
                : "text-[var(--muted)] hover:text-[var(--foreground)] hover:bg-white/[0.02]"
            }`}
          >
            <span>{t.icon}</span>
            {t.label}
          </button>
        ))}
      </div>

      {activeTab === "overview" && (
        <>
          {/* ══════════ PIPELINE → HackerOne ══════════ */}
          <div className="rounded-2xl border border-indigo-500/20 bg-gradient-to-br from-indigo-500/8 via-[var(--card)] to-purple-500/5 overflow-hidden relative glow-indigo">
            {/* Decorative blur elements */}
            <div className="absolute inset-0 pointer-events-none">
              <div className="absolute -top-32 -right-32 w-64 h-64 bg-indigo-500/10 rounded-full blur-3xl" />
              <div className="absolute -bottom-32 -left-32 w-64 h-64 bg-purple-500/8 rounded-full blur-3xl" />
            </div>
            
            {/* Header */}
            <div className="relative px-4 sm:px-6 py-4 sm:py-5 border-b border-indigo-500/15 flex items-center justify-between backdrop-blur-sm">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-indigo-500/25 border border-indigo-400/30 flex items-center justify-center text-base shadow-lg shadow-indigo-500/20">🚀</div>
                <div>
                  <h3 className="text-sm font-bold text-indigo-300 uppercase tracking-widest">Pipeline → HackerOne</h3>
                  <p className="text-[10px] text-indigo-400/70 mt-1">Descubra, Analise, Reporte, Ganhe 💰</p>
                </div>
              </div>
              <div className="flex items-center gap-3 sm:gap-4 text-[11px]">
                <div className="hidden sm:flex items-center gap-4 space-x-3">
                  <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 font-semibold">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />Ativo
                  </span>
                  <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 text-[var(--muted)]">
                    <span className="w-2 h-2 rounded-full bg-white/30" />Pendente
                  </span>
                </div>
                {/* Logout Button */}
                <button 
                  onClick={() => {
                    if (typeof window !== 'undefined') {
                      localStorage.clear();
                      sessionStorage.clear();
                      window.location.href = '/';
                    }
                  }}
                  className="group flex items-center gap-2 px-3 py-1.5 rounded-lg bg-gradient-to-r from-red-500/20 to-pink-500/20 border border-red-500/30 text-red-300 font-semibold hover:from-red-500/30 hover:to-pink-500/30 hover:border-red-500/50 hover:shadow-lg hover:shadow-red-500/20 transition-all duration-300"
                  title="Sair da aplicação"
                >
                  <span className="text-base group-hover:scale-110 transition-transform duration-300">🚪</span>
                  <span className="hidden sm:inline">Sair</span>
                </button>
              </div>
            </div>

            {/* Pipeline Steps */}
            <div className="relative px-4 sm:px-6 py-6 sm:py-8">
              {(function () {
                const pipelineVals = [
                  bounty?.programs ?? 0,
                  recon?.recons_completed ?? 0,
                  bounty?.alive_targets ?? 0,
                  vuln?.total_vulns ?? 0,
                  reportStats?.total ?? 0,
                  reportStats?.submitted ?? 0,
                  roi?.operations.reports_accepted ?? 0,
                  roi?.summary.total_earnings ?? 0,
                ];
                const pipelineMax = Math.max(...pipelineVals, 1);
                const steps = [
                  { n: 1, icon: "📋", label: "Programas", desc: "H1, Bugcrowd, Intigriti", val: pipelineVals[0], color: "indigo",  barCls: "bg-indigo-500",  ringCls: "ring-indigo-500/50",  bgCls: "bg-indigo-500/20",  textCls: "text-indigo-300" },
                  { n: 2, icon: "🔍", label: "Recon",     desc: "subfinder, crt.sh, httpx",val: pipelineVals[1], color: "cyan",    barCls: "bg-cyan-500",    ringCls: "ring-cyan-500/50",    bgCls: "bg-cyan-500/20",    textCls: "text-cyan-300"   },
                  { n: 3, icon: "🎯", label: "Targets",   desc: "Hosts vivos para scan",   val: pipelineVals[2], color: "teal",   barCls: "bg-teal-500",    ringCls: "ring-teal-500/50",    bgCls: "bg-teal-500/20",    textCls: "text-teal-300"   },
                  { n: 4, icon: "⚡", label: "Scan",      desc: "Nuclei, Nmap, SQLi...",   val: pipelineVals[3], color: "amber",  barCls: "bg-amber-500",   ringCls: "ring-amber-500/50",   bgCls: "bg-amber-500/20",   textCls: "text-amber-300"  },
                  { n: 5, icon: "📝", label: "Reports",   desc: "PoC + CVSS + Steps",      val: pipelineVals[4], color: "violet", barCls: "bg-violet-500",  ringCls: "ring-violet-500/50",  bgCls: "bg-violet-500/20",  textCls: "text-violet-300" },
                  { n: 6, icon: "📤", label: "Enviados",  desc: "Submit via API",           val: pipelineVals[5], color: "blue",   barCls: "bg-blue-500",    ringCls: "ring-blue-500/50",    bgCls: "bg-blue-500/20",    textCls: "text-blue-300"   },
                  { n: 7, icon: "✅", label: "Aceitos",   desc: "Triaged pelo programa",    val: pipelineVals[6], color: "emerald",barCls: "bg-emerald-500", ringCls: "ring-emerald-500/50", bgCls: "bg-emerald-500/20", textCls: "text-emerald-300"},
                  { n: 8, icon: "💰", label: "Bounty",    desc: "Recompensa paga",          val: pipelineVals[7], color: "green",  barCls: "bg-green-500",   ringCls: "ring-green-500/50",   bgCls: "bg-green-500/20",   textCls: "text-green-300", isMoney: true },
                ];
                return (
                  <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-x-0 gap-y-6 sm:gap-y-5">
                    {steps.map((s, i) => {
                      const active = (s.val as number) > 0;
                      const barPct = Math.max((s.val as number) / pipelineMax * 100, active ? 4 : 0);
                      return (
                        <div key={s.n} className="flex items-center relative group">
                          <div className="flex-1 flex flex-col items-center text-center relative z-10 gap-2">
                            {/* Circle */}
                            <div className={`relative w-16 h-16 sm:w-[72px] sm:h-[72px] rounded-2xl flex flex-col items-center justify-center ring-2 transition-all duration-300
                              ${active
                                ? `${s.ringCls} ${s.bgCls} shadow-lg group-hover:scale-110`
                                : "ring-white/10 bg-white/5 group-hover:bg-white/8"
                              }`}>
                              <span className="text-xl sm:text-2xl mb-0.5">{s.icon}</span>
                              <span className={`text-[11px] sm:text-xs font-bold tabular-nums ${active ? s.textCls : "text-[var(--muted)]"}`}>
                                {s.isMoney ? `$${(s.val as number).toLocaleString()}` : (s.val as number).toLocaleString()}
                              </span>
                              {/* Step badge */}
                              <span className={`absolute -top-2 -right-2 w-5 h-5 rounded-full text-[9px] font-bold flex items-center justify-center shadow-md
                                ${active
                                  ? "bg-emerald-500 text-white border border-emerald-300/50"
                                  : "bg-white/10 text-[var(--muted)] border border-white/15"
                                }`}>{active ? "✓" : s.n}
                              </span>
                            </div>
                            {/* Label */}
                            <span className={`text-[11px] sm:text-xs font-semibold ${active ? "text-[var(--foreground)]" : "text-[var(--muted)]"}`}>{s.label}</span>
                            {/* Progress bar */}
                            <div className="w-full h-2 rounded-full bg-white/5 overflow-hidden">
                              <div
                                className={`h-full rounded-full transition-all duration-700 ${active ? s.barCls : "bg-white/10"}`}
                                style={{ width: `${barPct}%` }}
                              />
                            </div>
                            {/* Desc */}
                            <span className="text-[9px] text-[var(--muted)] leading-tight max-w-[72px]">{s.desc}</span>
                          </div>
                          {/* Arrow */}
                          {i < 7 && (
                            <div className="hidden lg:flex items-center shrink-0 -mx-1 pb-10">
                              <svg width="18" height="8" viewBox="0 0 18 8" className="text-white/15">
                                <path d="M0 4h14m0 0l-3-2.5m3 2.5l-3 2.5" stroke="currentColor" strokeWidth="1.2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
                              </svg>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                );
              })()}
            </div>

            {/* Flow summary bar */}
            <div className="relative px-4 sm:px-6 py-3 sm:py-4 border-t border-indigo-500/15 bg-gradient-to-r from-indigo-500/5 via-transparent to-purple-500/5 flex items-center justify-center gap-1.5 sm:gap-2.5 text-[9px] sm:text-[10px] overflow-x-auto backdrop-blur-sm">
              <span className="text-indigo-300/70 font-semibold uppercase tracking-wider flex-shrink-0">📊 Fluxo:</span>
              {[
                { val: bounty?.programs ?? 0, c: "text-indigo-400" },
                { val: recon?.recons_completed ?? 0, c: "text-cyan-400" },
                { val: bounty?.alive_targets ?? 0, c: "text-teal-400" },
                { val: vuln?.total_vulns ?? 0, c: "text-amber-400" },
                { val: reportStats?.total ?? 0, c: "text-violet-400" },
                { val: reportStats?.submitted ?? 0, c: "text-blue-400" },
                { val: roi?.operations.reports_accepted ?? 0, c: "text-emerald-400" },
                { val: roi?.summary.total_earnings ?? 0, c: "text-green-400", money: true },
              ].map((s, i) => (
                <span key={i} className="flex items-center gap-1.5 shrink-0">
                  <span className={`font-bold tabular-nums ${s.c}`}>{s.money ? `$${s.val.toLocaleString()}` : s.val.toLocaleString()}</span>
                  {i < 7 && <span className="text-white/15 font-light">→</span>}
                </span>
              ))}
            </div>

            {/* Trilha do Sucesso */}
            <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
              {/* Header */}
              <div className="px-6 py-5 border-b border-white/10 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center text-base">🏆</div>
                  <div>
                    <span className="text-sm font-bold text-[var(--foreground)]">Trilha do Sucesso</span>
                    <p className="text-[10px] text-[var(--muted)] mt-0.5">Progresso da jornada completa</p>
                  </div>
                  <span className="text-[10px] font-semibold px-2.5 py-1 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">
                    Jornada Completa
                  </span>
                </div>
                {(roi?.summary.total_earnings ?? 0) > 0 && (
                  <div className="text-right">
                    <div className="text-base font-bold text-emerald-400">
                      ${((roi?.summary.total_earnings ?? 0) / Math.max(roi?.operations.reports_accepted ?? 1, 1)).toLocaleString(undefined, { maximumFractionDigits: 0 })}
                    </div>
                    <div className="text-[9px] text-[var(--muted)]">por aceitação</div>
                  </div>
                )}
              </div>

              {/* Funnel steps */}
              <div className="px-6 py-4 space-y-1">
                {(function () {
                  const stepData = [
                    { icon: "📋", label: "Programas", val: bounty?.programs ?? 0,               bar: "bg-indigo-500",  text: "text-indigo-400",  bg: "bg-indigo-500/10" },
                    { icon: "🔍", label: "Recon",     val: recon?.recons_completed ?? 0,        bar: "bg-cyan-500",    text: "text-cyan-400",    bg: "bg-cyan-500/10"   },
                    { icon: "🎯", label: "Targets",   val: bounty?.alive_targets ?? 0,          bar: "bg-teal-500",    text: "text-teal-400",    bg: "bg-teal-500/10"   },
                    { icon: "⚡", label: "Scans",     val: vuln?.total_vulns ?? 0,              bar: "bg-amber-500",   text: "text-amber-400",   bg: "bg-amber-500/10"  },
                    { icon: "📝", label: "Reports",   val: reportStats?.total ?? 0,             bar: "bg-violet-500",  text: "text-violet-400",  bg: "bg-violet-500/10" },
                    { icon: "📤", label: "Enviados",  val: reportStats?.submitted ?? 0,         bar: "bg-blue-500",    text: "text-blue-400",    bg: "bg-blue-500/10"   },
                    { icon: "✅", label: "Aceitos",   val: roi?.operations.reports_accepted ?? 0,bar: "bg-emerald-500", text: "text-emerald-400", bg: "bg-emerald-500/10"},
                  ];
                  const maxVal = Math.max(...stepData.map(s => s.val), 1);

                  return stepData.map((step, idx) => {
                    const barPct = Math.max((step.val / maxVal) * 100, step.val > 0 ? 2 : 0);
                    const nextVal = idx < 6 ? stepData[idx + 1].val : null;
                    const conv = nextVal !== null && step.val > 0 ? Math.round((nextVal / step.val) * 100) : null;

                    return (
                      <div key={idx}>
                        {/* Row */}
                        <div className={`flex items-center gap-4 py-2.5 px-3 rounded-lg transition-colors ${step.val > 0 ? `hover:${step.bg}` : "hover:bg-white/3"}`}>
                          {/* Step info */}
                          <div className="flex items-center gap-2.5 w-36 shrink-0">
                            <span className="text-[10px] font-bold text-[var(--muted)] w-4 text-right tabular-nums">{idx + 1}</span>
                            <span className="text-base leading-none">{step.icon}</span>
                            <span className={`text-xs font-semibold truncate ${step.val > 0 ? "text-[var(--foreground)]" : "text-[var(--muted)]"}`}>
                              {step.label}
                            </span>
                          </div>
                          {/* Bar */}
                          <div className="flex-1 h-3 bg-white/5 rounded-full overflow-hidden border border-white/5">
                            <div
                              className={`h-full ${step.bar} rounded-full transition-all duration-700 opacity-80`}
                              style={{ width: `${barPct}%` }}
                            />
                          </div>
                          {/* Value */}
                          <span className={`text-sm font-bold w-14 text-right tabular-nums ${step.val > 0 ? step.text : "text-[var(--muted)]"}`}>
                            {step.val.toLocaleString()}
                          </span>
                        </div>

                        {/* Conversion arrow */}
                        {idx < 6 && (
                          <div className="flex items-center gap-4 h-5 pl-3">
                            <div className="w-36 shrink-0" />
                            <div className="pl-9 flex items-center gap-2">
                              <div className="w-px h-5 bg-white/8" />
                              {conv !== null && (
                                <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full ${
                                  conv >= 50 ? "bg-emerald-500/15 text-emerald-400" :
                                  conv >= 20 ? "bg-amber-500/15 text-amber-400" :
                                  "bg-red-500/15 text-red-400"
                                }`}>
                                  {conv}% →
                                </span>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  });
                })()}
              </div>

              {/* Footer metrics */}
              <div className="px-6 py-4 border-t border-white/10">
                {(function () {
                  const vals = [
                    bounty?.programs ?? 0, recon?.recons_completed ?? 0,
                    bounty?.alive_targets ?? 0, vuln?.total_vulns ?? 0,
                    reportStats?.total ?? 0, reportStats?.submitted ?? 0,
                    roi?.operations.reports_accepted ?? 0,
                  ];
                  const activeIdx = vals.findIndex(v => v === 0);
                  const etapa = activeIdx === -1 ? "7/7" : `${activeIdx}/7`;
                  const progresso = Math.round(vals.filter(v => v > 0).length / 7 * 100);
                  const aceitacao = Math.round((roi?.operations.reports_accepted ?? 0) / Math.max(reportStats?.submitted ?? 1, 1) * 100);
                  const aceitacaoColor = aceitacao >= 50 ? "text-emerald-400" : aceitacao >= 20 ? "text-amber-400" : "text-[var(--muted)]";
                  const insight = (roi?.operations.reports_accepted ?? 0) === 0
                    ? "Envie seus primeiros relatórios para começar a trilha."
                    : ((reportStats?.submitted ?? 0) / Math.max(reportStats?.total ?? 1, 1)) * 100 < 50
                      ? "Aumente o fluxo de envios para melhorar a conversão."
                      : aceitacao < 30
                        ? "Melhore a qualidade dos POCs para aumentar a aceitação."
                        : "Ótima taxa! Escale a quantidade de descobertas.";

                  return (
                    <div className="flex items-center gap-0 divide-x divide-white/10">
                      {[
                        { label: "Etapa", value: etapa, color: "text-[var(--foreground)]" },
                        { label: "Progresso", value: `${progresso}%`, color: "text-emerald-400" },
                        { label: "Aceitação", value: `${aceitacao}%`, color: aceitacaoColor },
                      ].map(m => (
                        <div key={m.label} className="flex-none px-5 first:pl-0 text-center">
                          <div className={`text-lg font-bold ${m.color}`}>{m.value}</div>
                          <div className="text-[9px] text-[var(--muted)] uppercase tracking-wide">{m.label}</div>
                        </div>
                      ))}
                      <p className="flex-1 pl-5 text-[11px] text-[var(--muted)] leading-relaxed">{insight}</p>
                    </div>
                  );
                })()}
              </div>
            </div>

            {/* Métricas de Desempenho */}
            <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
              <div className="px-6 py-5 border-b border-white/10 flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-slate-500/20 border border-slate-500/30 flex items-center justify-center text-base">📊</div>
                <div>
                  <span className="text-sm font-bold text-[var(--foreground)]">Métricas de Desempenho</span>
                  <p className="text-[10px] text-[var(--muted)] mt-0.5">Indicadores chave do pipeline</p>
                </div>
              </div>

              <div className="px-6 py-5 space-y-4">
                {/* KPI bars */}
                {(function () {
                  const reconCov  = Math.min(Math.round((recon?.recons_completed ?? 0) / Math.max(bounty?.programs ?? 1, 1) * 100), 100);
                  const hostSurv  = Math.min(Math.round((bounty?.alive_targets ?? 0)   / Math.max(bounty?.targets ?? 1, 1) * 100), 100);
                  const reportCov = Math.min(Math.round((reportStats?.total ?? 0)       / Math.max(vuln?.total_vulns ?? 1, 1) * 100), 100);
                  const subRate   = Math.min(Math.round((reportStats?.submitted ?? 0)   / Math.max(reportStats?.total ?? 1, 1) * 100), 100);
                  const accRate   = Math.min(Math.round((roi?.operations.reports_accepted ?? 0) / Math.max(reportStats?.submitted ?? 1, 1) * 100), 100);

                  const kpis = [
                    { label: "Cobertura de Recon",    value: reconCov,  suffix: "%", bar: "bg-cyan-500",    desc: `${recon?.recons_completed ?? 0} de ${bounty?.programs ?? 0} programas`    },
                    { label: "Hosts Vivos",            value: hostSurv,  suffix: "%", bar: "bg-teal-500",    desc: `${bounty?.alive_targets ?? 0} de ${bounty?.targets ?? 0} targets`         },
                    { label: "Reports por Vuln",       value: reportCov, suffix: "%", bar: "bg-violet-500",  desc: `${reportStats?.total ?? 0} de ${vuln?.total_vulns ?? 0} vulns`            },
                    { label: "Taxa de Envio",          value: subRate,   suffix: "%", bar: "bg-blue-500",    desc: `${reportStats?.submitted ?? 0} de ${reportStats?.total ?? 0} reports`     },
                    { label: "Taxa de Aceitação",      value: accRate,   suffix: "%", bar: "bg-emerald-500", desc: `${roi?.operations.reports_accepted ?? 0} de ${reportStats?.submitted ?? 0} enviados` },
                  ];

                  return kpis.map(kpi => (
                    <div key={kpi.label}>
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-xs font-medium text-[var(--foreground)]">{kpi.label}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] text-[var(--muted)]">{kpi.desc}</span>
                          <span className={`text-sm font-bold tabular-nums ${kpi.value >= 60 ? "text-emerald-400" : kpi.value >= 30 ? "text-amber-400" : "text-[var(--muted)]"}`}>
                            {kpi.value}{kpi.suffix}
                          </span>
                        </div>
                      </div>
                      <div className="h-2.5 bg-white/5 rounded-full overflow-hidden border border-white/5">
                        <div
                          className={`h-full ${kpi.bar} rounded-full transition-all duration-700 opacity-80`}
                          style={{ width: `${Math.max(kpi.value, kpi.value > 0 ? 2 : 0)}%` }}
                        />
                      </div>
                    </div>
                  ));
                })()}

                {/* KPI summary row */}
                <div className="grid grid-cols-3 gap-3 pt-2 border-t border-white/10">
                  {[
                    { label: "Targets / Programa", value: Math.round((bounty?.alive_targets ?? 0) / Math.max(bounty?.programs ?? 1, 1)), color: "text-slate-300" },
                    { label: "Vulns / Host",        value: (Math.round((vuln?.total_vulns ?? 0) / Math.max(bounty?.alive_targets ?? 1, 1) * 10) / 10).toFixed(1), color: "text-amber-300" },
                    { label: "Reward Médio",        value: `$${((roi?.summary.total_earnings ?? 0) / Math.max(roi?.operations.reports_accepted ?? 1, 1)).toLocaleString(undefined, { maximumFractionDigits: 0 })}`, color: "text-emerald-300" },
                  ].map(m => (
                    <div key={m.label} className="text-center p-3 rounded-lg bg-white/5 border border-white/8">
                      <div className={`text-lg font-bold ${m.color}`}>{m.value}</div>
                      <div className="text-[9px] text-[var(--muted)] mt-0.5">{m.label}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* H1 Auto-Submit Pipeline Status */}
            <div className="relative px-6 py-6 rounded-xl border border-violet-500/20 bg-gradient-to-br from-violet-500/8 via-[var(--card)] to-blue-500/5 backdrop-blur-md overflow-hidden">
              <div className="absolute -top-20 -right-20 w-40 h-40 rounded-full bg-violet-500/15 blur-3xl pointer-events-none" />
              <div className="absolute -bottom-20 -left-20 w-40 h-40 rounded-full bg-blue-500/10 blur-3xl pointer-events-none" />
              
              <div className="relative z-10">
                {/* Header */}
                <div className="flex items-center justify-between mb-5">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-violet-500/25 border border-violet-400/30 flex items-center justify-center text-lg shadow-lg shadow-violet-500/20">📤</div>
                    <div>
                      <h3 className="text-sm font-bold text-violet-300 uppercase tracking-widest">Pipeline Auto-Submit → HackerOne</h3>
                      <p className="text-[10px] text-violet-400/70 mt-0.5">
                        Ciclo completo: Vulnerabilidades confirmadas → Relatórios formatados → Submissão automática via API HackerOne
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {h1Stats?.auto_submit_config?.enabled ? (
                      <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-[10px] font-semibold">
                        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                        {h1Stats?.auto_submit_config?.dry_run ? "DRY RUN" : "ATIVO"}
                      </span>
                    ) : (
                      <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-red-500/10 border border-red-500/20 text-red-300 text-[10px] font-semibold">
                        <span className="w-2 h-2 rounded-full bg-red-400" />DESATIVADO
                      </span>
                    )}
                    <button
                      disabled={h1Submitting}
                      onClick={async () => {
                        setH1Submitting(true);
                        setH1Msg("");
                        try {
                          const res = await triggerH1AutoSubmit({ limit: 10 });
                          setH1Msg(`✅ Ciclo completo: ${res.reports_generated} reports gerados de ${res.processed_vulns} vulns | ${res.submitted} enviados ao H1 | ${res.duplicates} duplicados | ${res.errors} erros`);
                          const [stats, queue] = await Promise.all([fetchH1Stats(), fetchH1Queue()]);
                          setH1Stats(stats);
                          setH1Queue(queue.reports || []);
                        } catch (e: any) {
                          setH1Msg(`❌ ${e.message || "Falha na execução do pipeline"}`);
                        } finally {
                          setH1Submitting(false);
                        }
                      }}
                      className="px-3 py-1.5 text-[10px] font-bold rounded-lg bg-violet-500/20 border border-violet-500/30 text-violet-300 hover:bg-violet-500/30 hover:border-violet-500/50 transition-all disabled:opacity-50"
                    >
                      {h1Submitting ? "⏳ Processando..." : "▶ Executar Agora"}
                    </button>
                  </div>
                </div>

                {/* Result message */}
                {h1Msg && (
                  <div className={`mb-4 p-3 rounded-lg border text-[10px] flex items-start gap-2 ${
                    h1Msg.startsWith("✅") ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-200/90"
                    : h1Msg.startsWith("❌") ? "bg-red-500/10 border-red-500/20 text-red-200/90"
                    : "bg-blue-500/10 border-blue-500/20 text-blue-200/90"
                  }`}>
                    <span className="flex-shrink-0 mt-0.5">{h1Msg.startsWith("✅") ? "✅" : h1Msg.startsWith("❌") ? "❌" : "ℹ️"}</span>
                    <span>{h1Msg.replace(/^[✅❌] /, "")}</span>
                  </div>
                )}

                {/* Pipeline visual flow */}
                <div className="mb-5 p-4 rounded-lg bg-white/3 border border-white/8">
                  <div className="text-[10px] font-bold text-[var(--muted)] uppercase mb-3">Como funciona o pipeline</div>
                  <div className="flex items-center justify-between gap-1">
                    {[
                      { icon: "🔍", label: "Scan", desc: "Nuclei detecta vulns", active: (vuln?.total_vulns ?? 0) > 0 },
                      { icon: "→", label: "", desc: "", arrow: true },
                      { icon: "📝", label: "Report", desc: "Gera relatório H1", active: (reportStats?.total ?? 0) > 0 },
                      { icon: "→", label: "", desc: "", arrow: true },
                      { icon: "✅", label: "Valida", desc: "CVSS + PoC + Scope", active: h1Queue.length > 0 || (reportStats?.submitted ?? 0) > 0 },
                      { icon: "→", label: "", desc: "", arrow: true },
                      { icon: "📤", label: "Submit", desc: "API HackerOne", active: (h1Stats?.successful ?? 0) > 0 },
                      { icon: "→", label: "", desc: "", arrow: true },
                      { icon: "💰", label: "Bounty", desc: "Recompensa", active: (roi?.summary.total_earnings ?? 0) > 0 },
                    ].map((s, i) => s.arrow ? (
                      <div key={i} className="text-white/20 text-xs flex-shrink-0">→</div>
                    ) : (
                      <div key={i} className={`flex flex-col items-center text-center flex-1 p-2 rounded-lg transition-all ${s.active ? "bg-violet-500/10 border border-violet-500/20" : "opacity-40"}`}>
                        <span className="text-base mb-1">{s.icon}</span>
                        <span className={`text-[9px] font-bold ${s.active ? "text-violet-300" : "text-[var(--muted)]"}`}>{s.label}</span>
                        <span className="text-[8px] text-[var(--muted)] mt-0.5">{s.desc}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Status grid */}
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-4">
                  <div className="p-3 rounded-lg bg-white/5 border border-white/10 text-center group hover:bg-white/8 transition-all">
                    <div className="text-[10px] font-bold text-violet-300 mb-1">Credenciais H1</div>
                    <div className={`text-xl font-bold ${h1Stats?.h1_credentials_configured ? "text-emerald-400" : "text-red-400"}`}>
                      {h1Stats?.h1_credentials_configured ? "✓" : "✗"}
                    </div>
                    <div className="text-[8px] text-[var(--muted)] mt-1">
                      {h1Stats?.h1_credentials_configured ? "Token + Username OK" : "HACKERONE_API_TOKEN ausente"}
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-white/5 border border-white/10 text-center group hover:bg-white/8 transition-all">
                    <div className="text-[10px] font-bold text-blue-300 mb-1">Na Fila</div>
                    <div className="text-xl font-bold text-blue-400">{h1Queue.length}</div>
                    <div className="text-[8px] text-[var(--muted)] mt-1">Reports draft aguardando envio</div>
                  </div>

                  <div className="p-3 rounded-lg bg-white/5 border border-white/10 text-center group hover:bg-white/8 transition-all">
                    <div className="text-[10px] font-bold text-emerald-300 mb-1">Enviados</div>
                    <div className="text-xl font-bold text-emerald-400">{h1Stats?.successful ?? 0}</div>
                    <div className="text-[8px] text-[var(--muted)] mt-1">Submetidos com sucesso ao H1</div>
                  </div>

                  <div className="p-3 rounded-lg bg-white/5 border border-white/10 text-center group hover:bg-white/8 transition-all">
                    <div className="text-[10px] font-bold text-red-300 mb-1">Falharam</div>
                    <div className="text-xl font-bold text-red-400">{h1Stats?.failed ?? 0}</div>
                    <div className="text-[8px] text-[var(--muted)] mt-1">HTTP error ou rejeição</div>
                  </div>

                  <div className="p-3 rounded-lg bg-white/5 border border-white/10 text-center group hover:bg-white/8 transition-all">
                    <div className="text-[10px] font-bold text-amber-300 mb-1">Total</div>
                    <div className="text-xl font-bold text-amber-400">{h1Stats?.total_submissions ?? 0}</div>
                    <div className="text-[8px] text-[var(--muted)] mt-1">Tentativas de submissão</div>
                  </div>
                </div>

                {/* Queue preview */}
                {h1Queue.length > 0 && (
                  <div className="mb-4 p-3 rounded-lg bg-white/5 border border-white/10">
                    <div className="text-[10px] font-bold text-[var(--muted)] uppercase mb-2">📋 Próximos na Fila ({h1Queue.length} reports)</div>
                    <div className="space-y-1.5 max-h-40 overflow-y-auto hide-scrollbar">
                      {h1Queue.slice(0, 8).map(r => (
                        <div key={r.id} className="flex items-center justify-between text-[10px] p-2 rounded-lg bg-white/3 hover:bg-white/5 transition-colors border border-white/5">
                          <div className="flex items-center gap-2 min-w-0">
                            <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold flex-shrink-0
                              ${r.severity === "critical" ? "bg-red-500/20 text-red-300 border border-red-500/20" :
                                r.severity === "high" ? "bg-orange-500/20 text-orange-300 border border-orange-500/20" :
                                r.severity === "medium" ? "bg-amber-500/20 text-amber-300 border border-amber-500/20" :
                                "bg-slate-500/20 text-slate-300 border border-slate-500/20"
                              }`}>{r.severity}</span>
                            <span className="text-[var(--foreground)] font-medium truncate">{r.title}</span>
                          </div>
                          <div className="flex items-center gap-2 flex-shrink-0 ml-2">
                            <span className="text-[8px] text-[var(--muted)] bg-white/5 px-1.5 py-0.5 rounded">{r.vulnerability_count} vuln{r.vulnerability_count !== 1 ? "s" : ""}</span>
                            <span className="text-[var(--muted)] font-mono text-[9px]">{r.ip}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Detailed explanation */}
                <div className="space-y-2 mb-4">
                  <div className="text-[10px] font-bold text-[var(--muted)] uppercase">📖 Detalhes do Pipeline</div>
                  
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    <div className="p-2.5 rounded-lg bg-violet-500/5 border border-violet-500/15">
                      <div className="flex items-start gap-2">
                        <span className="text-sm flex-shrink-0">1️⃣</span>
                        <div className="text-[10px]">
                          <strong className="text-violet-300">Geração de Reports</strong>
                          <p className="text-violet-200/60 mt-0.5">
                            Vulnerabilidades com status &quot;confirmed&quot; na collection <code className="text-violet-400/80 bg-violet-500/10 px-1 rounded">vuln_results</code> são 
                            convertidas em relatórios HackerOne com título, PoC, CVSS, steps to reproduce e impacto. Agrupadas por IP/host.
                          </p>
                        </div>
                      </div>
                    </div>

                    <div className="p-2.5 rounded-lg bg-blue-500/5 border border-blue-500/15">
                      <div className="flex items-start gap-2">
                        <span className="text-sm flex-shrink-0">2️⃣</span>
                        <div className="text-[10px]">
                          <strong className="text-blue-300">Validação de Elegibilidade</strong>
                          <p className="text-blue-200/60 mt-0.5">
                            Cada report precisa atender critérios: ter evidência (URL, curl, HTTP req/res), 
                            CVSS válido, steps to reproduce, impacto descrito, remediação, e estar in-scope no programa.
                          </p>
                        </div>
                      </div>
                    </div>

                    <div className="p-2.5 rounded-lg bg-cyan-500/5 border border-cyan-500/15">
                      <div className="flex items-start gap-2">
                        <span className="text-sm flex-shrink-0">3️⃣</span>
                        <div className="text-[10px]">
                          <strong className="text-cyan-300">Verificação de Duplicatas</strong>
                          <p className="text-cyan-200/60 mt-0.5">
                            Antes de enviar, o sistema consulta a API H1 para verificar se já existe um report 
                            similar (mesmo IP/título) no programa-alvo, evitando duplicatas e penalizações.
                          </p>
                        </div>
                      </div>
                    </div>

                    <div className="p-2.5 rounded-lg bg-emerald-500/5 border border-emerald-500/15">
                      <div className="flex items-start gap-2">
                        <span className="text-sm flex-shrink-0">4️⃣</span>
                        <div className="text-[10px]">
                          <strong className="text-emerald-300">Submissão via API</strong>
                          <p className="text-emerald-200/60 mt-0.5">
                            Reports aprovados são enviados via <code className="text-emerald-400/80 bg-emerald-500/10 px-1 rounded">POST /v1/hackers/reports</code> com 
                            autenticação Basic Auth (username + token). O status é rastreado no MongoDB.
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Config info */}
                <div className="p-3 rounded-lg bg-violet-500/5 border border-violet-500/15">
                  <div className="text-[10px] font-bold text-violet-300 mb-2">⚙️ Configuração Atual</div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[9px]">
                    <div>
                      <span className="text-[var(--muted)]">Intervalo:</span>{" "}
                      <strong className="text-violet-300">{h1Stats?.auto_submit_config?.interval_seconds ?? 300}s</strong>
                      <div className="text-[8px] text-[var(--muted)]">Tempo entre cada ciclo</div>
                    </div>
                    <div>
                      <span className="text-[var(--muted)]">Batch size:</span>{" "}
                      <strong className="text-violet-300">{h1Stats?.auto_submit_config?.batch_size ?? 10}</strong>
                      <div className="text-[8px] text-[var(--muted)]">Reports por ciclo</div>
                    </div>
                    <div>
                      <span className="text-[var(--muted)]">Modo:</span>{" "}
                      <strong className={h1Stats?.auto_submit_config?.dry_run ? "text-amber-300" : "text-emerald-300"}>
                        {h1Stats?.auto_submit_config?.dry_run ? "Dry Run" : "Produção"}
                      </strong>
                      <div className="text-[8px] text-[var(--muted)]">{h1Stats?.auto_submit_config?.dry_run ? "Não envia de verdade" : "Envia para H1"}</div>
                    </div>
                    <div>
                      <span className="text-[var(--muted)]">Auto:</span>{" "}
                      <strong className={h1Stats?.auto_submit_config?.enabled ? "text-emerald-300" : "text-red-300"}>
                        {h1Stats?.auto_submit_config?.enabled ? "Ligado" : "Desligado"}
                      </strong>
                      <div className="text-[8px] text-[var(--muted)]">H1_AUTO_SUBMIT env var</div>
                    </div>
                  </div>
                  
                  {/* Setup guide if not configured */}
                  {!h1Stats?.h1_credentials_configured && (
                    <div className="mt-3 p-2 rounded bg-amber-500/10 border border-amber-500/20">
                      <div className="text-[10px] text-amber-200/90 flex items-start gap-2">
                        <span className="flex-shrink-0">⚠️</span>
                        <div>
                          <strong>Como configurar:</strong> Adicione estas variáveis no <code className="bg-amber-500/15 px-1 rounded text-amber-300">docker-compose.yml</code>:
                          <div className="mt-1.5 p-2 rounded bg-black/30 font-mono text-[9px] text-amber-100/80 space-y-0.5">
                            <div>HACKERONE_API_TOKEN: &quot;seu-token-api&quot;</div>
                            <div>HACKERONE_API_USERNAME: &quot;seu-username&quot;</div>
                            <div>H1_AUTO_SUBMIT: &quot;true&quot;</div>
                          </div>
                          <p className="mt-1.5 text-[9px] text-amber-200/60">
                            Obtenha seu token em: hackerone.com → Settings → API Token. O username é seu handle no H1.
                          </p>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Taxa de Conversão */}
            <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden">
              <div className="px-6 py-5 border-b border-white/10 flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center text-base">🎯</div>
                <div>
                  <span className="text-sm font-bold text-[var(--foreground)]">Taxa de Conversão</span>
                  <p className="text-[10px] text-[var(--muted)] mt-0.5">Funil de progressão — cada barra mostra a % em relação à etapa anterior</p>
                </div>
              </div>

              <div className="px-6 py-5 space-y-4">
                {(function () {
                  const funnel = [
                    { icon: "📋", label: "Programas",       val: bounty?.programs ?? 0,              prev: bounty?.programs ?? 1,                    color: "from-indigo-500 to-indigo-400",  badge: "bg-indigo-500/20 text-indigo-300"  },
                    { icon: "🔍", label: "Recon Completado",val: recon?.recons_completed ?? 0,        prev: bounty?.programs ?? 1,                    color: "from-cyan-500 to-cyan-400",      badge: "bg-cyan-500/20 text-cyan-300"     },
                    { icon: "🎯", label: "Targets Vivos",   val: bounty?.alive_targets ?? 0,          prev: recon?.recons_completed ?? 1,             color: "from-teal-500 to-teal-400",      badge: "bg-teal-500/20 text-teal-300"     },
                    { icon: "⚡", label: "Vulnerabilidades",val: vuln?.total_vulns ?? 0,              prev: bounty?.alive_targets ?? 1,               color: "from-amber-500 to-amber-400",    badge: "bg-amber-500/20 text-amber-300"   },
                    { icon: "📝", label: "Relatórios",      val: reportStats?.total ?? 0,             prev: vuln?.total_vulns ?? 1,                   color: "from-violet-500 to-violet-400",  badge: "bg-violet-500/20 text-violet-300" },
                    { icon: "📤", label: "Enviados",        val: reportStats?.submitted ?? 0,         prev: reportStats?.total ?? 1,                  color: "from-blue-500 to-blue-400",      badge: "bg-blue-500/20 text-blue-300"     },
                    { icon: "✅", label: "Aceitos",         val: roi?.operations.reports_accepted ?? 0,prev: reportStats?.submitted ?? 1,             color: "from-emerald-500 to-emerald-400",badge: "bg-emerald-500/20 text-emerald-300"},
                  ];

                  return funnel.map((s, i) => {
                    const pct = Math.min(Math.max(i === 0 ? 100 : (s.val / Math.max(s.prev, 1)) * 100, 0), 100);
                    const displayPct = Math.min(Math.max(pct, s.val > 0 ? 3 : 0), 100);
                    return (
                      <div key={i} className="group">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2.5">
                            <span className="text-base">{s.icon}</span>
                            <span className="text-xs font-semibold text-[var(--foreground)]">{s.label}</span>
                          </div>
                          <div className="flex items-center gap-2.5">
                            <span className="text-sm font-bold text-[var(--foreground)] tabular-nums">{s.val.toLocaleString()}</span>
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${s.badge}`}>
                              {Math.round(pct)}%
                            </span>
                          </div>
                        </div>
                        <div className="relative h-8 rounded-lg overflow-hidden bg-white/5 border border-white/8 group-hover:border-white/15 transition-all duration-300">
                          <div
                            className={`absolute inset-y-0 left-0 rounded-lg bg-gradient-to-r ${s.color} transition-all duration-700`}
                            style={{ width: `${displayPct}%`, opacity: 0.85 }}
                          />
                          {displayPct > 12 && (
                            <div className="absolute inset-0 flex items-center px-3 text-[11px] font-bold text-white/90">
                              {Math.round(pct)}%
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  });
                })()}

                {/* Summary */}
                <div className="grid grid-cols-3 gap-3 pt-3 border-t border-white/10">
                  {[
                    { label: "Conversão Total",   value: `${Math.round(((roi?.operations.reports_accepted ?? 0) / Math.max(bounty?.programs ?? 1, 1)) * 100)}%`, color: "text-emerald-400" },
                    { label: "Taxa de Aceitação", value: `${Math.round(((roi?.operations.reports_accepted ?? 0) / Math.max(reportStats?.submitted ?? 1, 1)) * 100)}%`, color: "text-violet-400" },
                    { label: "Média por Aceito",  value: `$${roi?.operations.reports_accepted ? (roi.summary.total_earnings / roi.operations.reports_accepted).toLocaleString("en-US", { maximumFractionDigits: 0 }) : "0"}`, color: "text-green-400" },
                  ].map(m => (
                    <div key={m.label} className="text-center p-3 rounded-lg bg-white/5 border border-white/8 hover:bg-white/8 transition-colors">
                      <div className={`text-xl font-bold ${m.color}`}>{m.value}</div>
                      <div className="text-[9px] text-[var(--muted)] uppercase tracking-wide mt-0.5">{m.label}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* ══════════ ROW 2: Recon + Live Terminal + Report Submit ══════════ */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-2 items-stretch">

            {/* Recon Pipeline */}
            <Tooltip className="lg:col-span-4" text={"Pipeline de reconhecimento automático.\nRoda subfinder, crt.sh, httpx, dnsx, rDNS.\nDescobre subdomínios e verifica quais estão vivos.\nNovos targets são priorizados para scan."}>
            <Card title="Recon Pipeline" accent="text-cyan-400" glow="rgba(6, 182, 212, 0.06)" onClick={() => setActiveModal('recon')} clickHint="ver recon">
              <div className="flex items-center gap-3 mb-3">
                <Donut value={recon?.recons_completed ?? 0} total={bounty?.programs ?? 1} color="#06b6d4" size={56} />
                <div>
                  <div className="text-sm font-semibold text-[var(--foreground)]">
                    {recon?.recons_completed ?? 0}<span className="text-[var(--muted)]">/{bounty?.programs ?? 0}</span>
                  </div>
                  <div className="text-[10px] text-[var(--muted)] uppercase">Recons done</div>
                  <div className="text-[9px] text-cyan-400/70 mt-0.5">
                    {Math.round((recon?.recons_completed ?? 0) / Math.max(bounty?.programs ?? 1, 1) * 100)}% cobertura
                  </div>
                </div>
              </div>
              {/* Quick Insight */}
              <div className="mb-2 p-1.5 rounded-lg bg-cyan-500/5 border border-cyan-500/10 text-[9px] text-cyan-300/70 flex items-center gap-1.5">
                <span>💡</span>
                {(recon?.new_subdomains_detected ?? 0) > 0 
                  ? <span>{recon!.new_subdomains_detected} novos subdomínios detectados!</span>
                  : <span>subfinder + crt.sh + httpx + rDNS</span>}
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
              {/* Survival rate bar */}
              <div className="mt-2 pt-2 border-t border-[var(--border)]">
                <div className="flex items-center justify-between text-[9px] mb-1">
                  <span className="text-[var(--muted)]">Taxa de sobrevivência</span>
                  <span className="text-emerald-400 font-bold">{Math.round(((bounty?.alive_targets ?? 0) / Math.max(bounty?.targets ?? 1, 1)) * 100)}%</span>
                </div>
                <div className="h-1.5 rounded-full bg-white/5 overflow-hidden">
                  <div className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-emerald-500 transition-all" style={{ width: `${Math.round(((bounty?.alive_targets ?? 0) / Math.max(bounty?.targets ?? 1, 1)) * 100)}%` }} />
                </div>
              </div>
              {(recon?.errors ?? 0) > 0 && (
                <div className="mt-2 text-xs text-red-400">Errors: {recon!.errors}</div>
              )}
            </Card>
            </Tooltip>

            {/* ── Live Activity Terminal ── */}
            <div className="lg:col-span-4 flex flex-col">
              <div className="rounded-xl border border-emerald-500/20 bg-[#0a0e14] flex flex-col h-full overflow-hidden">
                {/* title bar */}
                <div className="flex items-center justify-between px-3 py-2 border-b border-emerald-500/15 bg-[#0d1117]">
                  <div className="flex items-center gap-2">
                    <span className="flex gap-1">
                      <span className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
                      <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/80" />
                      <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
                    </span>
                    <span className="text-[10px] font-mono text-emerald-400/70 uppercase tracking-widest">Live API Activity</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`w-1.5 h-1.5 rounded-full ${logsPaused ? "bg-yellow-400" : "bg-emerald-400 animate-pulse"}`} />
                    <button
                      onClick={() => setLogsPaused(p => !p)}
                      className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-emerald-500/20 text-emerald-400/60 hover:text-emerald-300 hover:border-emerald-500/40 transition-colors"
                    >
                      {logsPaused ? "▶ resume" : "⏸ pause"}
                    </button>
                  </div>
                </div>
                {/* log area */}
                <div ref={termRef} className="flex-1 overflow-y-auto px-3 py-2 font-mono text-[10px] leading-[1.6] min-h-[200px] max-h-[340px] scrollbar-thin scrollbar-thumb-emerald-500/20 scrollbar-track-transparent">
                  {activityLogs.length === 0 ? (
                    <div className="flex items-center justify-center h-full text-emerald-500/30 text-xs">
                      <span className="animate-pulse">aguardando eventos...</span>
                    </div>
                  ) : (
                    activityLogs.map((log, i) => {
                      const lvl = log.level?.toUpperCase() ?? "INFO";
                      const color =
                        lvl === "ERROR" ? "text-red-400" :
                        lvl === "WARNING" ? "text-amber-400" :
                        lvl === "DEBUG" ? "text-slate-500" :
                        "text-emerald-400/80";
                      const tagColor =
                        (log.tag ?? "").includes("VULN") ? "text-red-400 bg-red-500/10" :
                        (log.tag ?? "").includes("SCAN") ? "text-cyan-400 bg-cyan-500/10" :
                        (log.tag ?? "").includes("RECON") ? "text-blue-400 bg-blue-500/10" :
                        (log.tag ?? "").includes("REPORT") ? "text-violet-400 bg-violet-500/10" :
                        (log.tag ?? "").includes("CVE") ? "text-orange-400 bg-orange-500/10" :
                        "text-slate-400 bg-slate-500/10";
                      const time = log.ts ? new Date(log.ts).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "";
                      return (
                        <div key={`${log.ts}-${i}`} className="flex gap-1.5 hover:bg-white/[0.02] rounded px-1 -mx-1">
                          <span className="text-slate-600 shrink-0 select-none">{time}</span>
                          <span className={`font-bold shrink-0 w-[42px] text-right ${color}`}>{lvl.slice(0, 4)}</span>
                          {log.tag && <span className={`shrink-0 px-1 rounded text-[9px] font-semibold ${tagColor}`}>{log.tag}</span>}
                          <span className="text-slate-300/90 break-all">{log.msg}</span>
                        </div>
                      );
                    })
                  )}
                </div>
                {/* status bar */}
                <div className="px-3 py-1 border-t border-emerald-500/10 bg-[#0d1117] flex items-center justify-between">
                  <span className="text-[9px] font-mono text-slate-600">{activityLogs.length} eventos</span>
                  <span className="text-[9px] font-mono text-emerald-500/40">polling 3s</span>
                </div>
              </div>
            </div>

            {/* Report Submission (expandable) */}
            <ReportSubmissionCard
              reportStats={reportStats}
              roi={roi}
            />

          </div>

          {/* ══════════ ROW 3: AI Analyzer ══════════ */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-2">
            <Tooltip className="lg:col-span-12" text={"Modelo de IA local (Ollama) para:\n• Gerar reports profissionais\n• Classificar true/false positives\n• Analisar HTTP responses\n• Encontrar vulnerability chains"}>
            <Card title="AI Analyzer" accent="text-fuchsia-400" glow="rgba(192, 38, 211, 0.06)" onClick={() => setActiveModal('ai')} clickHint="ver AI">
              {aiStats ? (
                <div className="space-y-2">
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
                  {/* AI summary bar */}
                  <div className="flex items-center gap-2 text-[9px] text-fuchsia-300/60 pt-1 border-t border-[var(--border)]">
                    <span>🧠</span>
                    <span>Gera reports • Classifica findings • Analisa responses • CVSS automático</span>
                    {aiStats.errors > 0 && (
                      <span className="ml-auto text-red-400/70">Taxa de erro: {Math.round(aiStats.errors / Math.max(aiStats.requests, 1) * 100)}%</span>
                    )}
                  </div>
                </div>
              ) : (
                <div className="text-xs text-[var(--muted)]">Configure AI_PROVIDER in .env — Habilita geração automática de reports e classificação de vulns.</div>
              )}
            </Card>
            </Tooltip>
          </div>

          {/* ══════════ ROW 3b: Recon Live + Quick Actions ══════════ */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-2 items-stretch">

          <Tooltip className="lg:col-span-8" text={"Programas e status do recon.\nClique Recon para disparar manualmente.\nO auto-recon roda a cada 4 horas.\nVerde = com targets, azul = rodando."}>
          <Card title="Recon Live" accent="text-cyan-400" onClick={() => setActiveModal('recon-live')} clickHint="ver todos"
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
                        onClick={async (e) => {
                          e.stopPropagation();
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
          <Card title="Quick Actions" accent="text-blue-400" glow="rgba(59, 130, 246, 0.06)" onClick={() => setActiveModal('actions')} clickHint="ver ações">
            <div className="space-y-1" onClick={e => e.stopPropagation()}>
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
            <div className="border-t border-[var(--border)] pt-2 mt-2" onClick={e => e.stopPropagation()}>
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
            <Card title="Program Rankings" accent="text-[var(--accent-light)]" onClick={() => setActiveModal('rankings')} clickHint="ver ranking"
              action={<span className="text-[10px] text-[var(--muted)]">{programs.length}</span>}
              glow="rgba(99, 102, 241, 0.06)">
              {/* Tier distribution mini */}
              {programs.length > 0 && (
                <div className="flex items-center gap-1 mb-2">
                  {["S", "A", "B", "C", "D"].map(tier => {
                    const count = programs.filter(p => p.tier === tier).length;
                    if (count === 0) return null;
                    return <span key={tier} className={`text-[8px] font-bold px-1.5 py-0.5 rounded border ${TIER_COLORS[tier] || "bg-slate-700 text-slate-300 border-slate-600"}`}>{tier}:{count}</span>;
                  })}
                </div>
              )}
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
              {/* Best program highlight */}
              {programs.length > 0 && programs[0].has_bounty && (
                <div className="mt-2 pt-2 border-t border-[var(--border)] text-[9px] text-[var(--muted)] flex items-center gap-1.5">
                  <span>🏆</span>
                  <span>Melhor: <strong className="text-[var(--foreground)]">{programs[0].name}</strong> — Score {programs[0].score}{programs[0].bounty_max ? ` • $${programs[0].bounty_max.toLocaleString()}` : ""}</span>
                </div>
              )}
            </Card>
            </Tooltip>

            {/* Recent Activity */}
            <Tooltip className="lg:col-span-4" text={"Mudanças de subdomínios detectadas.\n+N = novos subdomínios encontrados.\n-N = subdomínios que sumiram.\nSubdomínios novos são priorizados."}>
            <Card title="Recent Activity" accent="text-lime-400" onClick={() => setActiveModal('activity')} clickHint="ver atividade">
              {/* Summary badges */}
              {changes.length > 0 && (
                <div className="flex items-center gap-2 mb-2 text-[9px]">
                  <span className="px-1.5 py-0.5 rounded bg-lime-500/10 text-lime-400 font-bold">{changes.length} mudanças</span>
                  <span className="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-bold">+{changes.reduce((a, c) => a + (c.new_subdomains?.length ?? 0), 0)} novos</span>
                  {changes.reduce((a, c) => a + (c.removed_subdomains?.length ?? 0), 0) > 0 && (
                    <span className="px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 font-bold">-{changes.reduce((a, c) => a + (c.removed_subdomains?.length ?? 0), 0)}</span>
                  )}
                </div>
              )}
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
            <Card title="Intelligence" accent="text-teal-400" glow="rgba(20, 184, 166, 0.06)" onClick={() => setActiveModal('intelligence')} clickHint="ver ROI">
              {/* Earnings headline */}
              {roi && (roi.summary.total_earnings > 0 || roi.top_programs.length > 0) && (
                <div className="mb-3 p-2 rounded-lg bg-green-500/5 border border-green-500/10 flex items-center justify-between">
                  <span className="text-[10px] text-[var(--muted)]">Total Earnings</span>
                  <span className="text-sm font-bold text-green-400">${roi.summary.total_earnings.toLocaleString()}</span>
                </div>
              )}
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

          {/* ═══ BugHunt Programs 🇧🇷 ═══ */}
          {bughuntPrograms.length > 0 && (
            <div className="rounded-xl border border-[var(--border)] bg-[var(--card)] overflow-hidden">
              <div className="px-4 py-3 border-b border-[var(--border)] flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-base">🇧🇷</span>
                  <span className="text-xs font-semibold">BugHunt</span>
                  <span className="text-[10px] text-[var(--muted)]">{bughuntPrograms.length} programas</span>
                </div>
                <a href="/bughunt" className="text-[10px] text-[var(--accent-light)] hover:underline">Ver dashboard →</a>
              </div>
              <div className="divide-y divide-[var(--border)]">
                {bughuntPrograms.map(prog => {
                  const isExp = bughuntExpanded === prog.program_id;
                  return (
                    <div key={prog.program_id}>
                      <button
                        onClick={() => setBughuntExpanded(isExp ? null : prog.program_id)}
                        className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-white/[0.02] transition-colors text-left"
                      >
                        <div className="flex items-center gap-3 min-w-0">
                          <div className="flex items-center justify-center w-7 h-7 rounded-lg bg-green-500/10 text-green-400 text-xs font-bold shrink-0">
                            {prog.name.charAt(0).toUpperCase()}
                          </div>
                          <div className="min-w-0">
                            <div className="text-xs font-medium text-[var(--foreground)] truncate">{prog.name}</div>
                            <div className="flex items-center gap-2 mt-0.5">
                              <span className="text-[10px] text-cyan-400">{prog.scope.length} alvos</span>
                              <span className={`text-[10px] px-1.5 py-0.5 rounded font-semibold ${
                                prog.reward_type === "vdp" || prog.max_bounty === 0
                                  ? "bg-gray-500/15 text-gray-400"
                                  : "bg-amber-500/15 text-amber-400"
                              }`}>{prog.max_bounty > 0 ? `R$ ${prog.max_bounty.toLocaleString("pt-BR")}` : prog.reward_type === "vdp" ? "VDP" : "Bounty"}</span>
                            </div>
                          </div>
                        </div>
                        <svg className={`w-3.5 h-3.5 text-[var(--muted)] transition-transform shrink-0 ${isExp ? "rotate-180" : ""}`}
                          fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
                        </svg>
                      </button>
                      {isExp && (
                        <div className="px-4 pb-3 pt-1 bg-[var(--background)]/30 space-y-2">
                          {prog.scope.length > 0 ? (
                            <div className="flex flex-wrap gap-1.5">
                              {prog.scope.map((s, i) => (
                                <span key={i} className="px-2 py-0.5 rounded text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/15 font-mono">{s}</span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-[10px] text-[var(--muted)]">Sem scope</span>
                          )}
                          <a href={prog.url} target="_blank" rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-[10px] text-green-400 hover:underline">
                            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
                            </svg>
                            Abrir na BugHunt
                          </a>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* ═══════════════════════════════════════════════════════════════
             DETAIL MODALS — One per card section
             ═══════════════════════════════════════════════════════════════ */}

          {/* ── Recon Pipeline Modal ── */}
          <Modal open={activeModal === 'recon'} onClose={() => setActiveModal(null)} title="🔍 Recon Pipeline — Detalhes" maxWidth="max-w-3xl">
            <div className="space-y-6">
              {/* Summary Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                  { label: "Recons Completos", val: recon?.recons_completed ?? 0, total: bounty?.programs ?? 0, c: "text-cyan-400", bg: "bg-cyan-500/10 border-cyan-500/20", desc: "Programas com reconhecimento finalizado" },
                  { label: "Subdomínios", val: recon?.subdomains_found ?? 0, c: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/20", desc: "Total de subdomínios descobertos via subfinder + crt.sh + rDNS" },
                  { label: "Hosts Vivos", val: recon?.hosts_alive ?? 0, c: "text-emerald-400", bg: "bg-emerald-500/10 border-emerald-500/20", desc: "Hosts que responderam a probe HTTP/HTTPS" },
                  { label: "Novos Subs", val: recon?.new_subdomains_detected ?? 0, c: "text-lime-400", bg: "bg-lime-500/10 border-lime-500/20", desc: "Subdomínios descobertos na última execução" },
                ].map(s => (
                  <div key={s.label} className={`p-3 rounded-xl border ${s.bg} text-center`}>
                    <div className={`text-2xl font-bold tabular-nums ${s.c}`}>{s.val.toLocaleString()}</div>
                    <div className="text-[10px] text-[var(--muted)] uppercase mt-1 font-semibold">{s.label}</div>
                    {s.total !== undefined && s.total > 0 && <div className="text-[9px] text-[var(--muted)] mt-0.5">de {s.total} programas</div>}
                    <div className="text-[9px] text-[var(--muted)] mt-1 leading-tight">{s.desc}</div>
                  </div>
                ))}
              </div>

              {/* Tool Breakdown */}
              <div>
                <h4 className="text-xs font-bold text-[var(--foreground)] mb-3 uppercase tracking-wider">Ferramentas de Reconhecimento</h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {[
                    { icon: "🔍", tool: "subfinder", desc: "Enumeração passiva de subdomínios via DNS, APIs públicas (SecurityTrails, VirusTotal, Shodan, etc.)", val: recon?.subdomains_found ?? 0, unit: "subs" },
                    { icon: "📜", tool: "crt.sh", desc: "Consulta Certificate Transparency logs para descobrir domínios em certificados SSL/TLS emitidos.", val: recon?.crtsh_subdomains ?? 0, unit: "certs" },
                    { icon: "🌐", tool: "httpx", desc: "Prova de vida HTTP/HTTPS. Detecta status, título, tecnologias (Wappalyzer), CDN e webserver.", val: recon?.hosts_alive ?? 0, unit: "alive" },
                    { icon: "🔄", tool: "Reverse DNS", desc: "Resolução reversa de IPs para descobrir domínios adicionais hospedados no mesmo servidor.", val: recon?.rdns_subdomains ?? 0, unit: "rDNS" },
                    { icon: "🏢", tool: "ASN Discovery", desc: "Identifica Autonomous System Numbers das organizações para mapear toda a infraestrutura IP.", val: recon?.asns_discovered ?? 0, unit: "ASNs" },
                    { icon: "⚡", tool: "Nuclei", desc: "Scanner de vulnerabilidades baseado em templates YAML. Detecta CVEs, misconfigs, exposures.", val: vuln?.total_vulns ?? 0, unit: "findings" },
                  ].map(t => (
                    <div key={t.tool} className="flex items-start gap-3 p-3 rounded-lg bg-white/3 border border-white/8 hover:border-white/15 transition-colors">
                      <span className="text-base mt-0.5">{t.icon}</span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-[var(--foreground)]">{t.tool}</span>
                          <span className="text-xs font-bold text-cyan-400 tabular-nums">{t.val.toLocaleString()} <span className="text-[var(--muted)] font-normal">{t.unit}</span></span>
                        </div>
                        <p className="text-[10px] text-[var(--muted)] mt-1 leading-relaxed">{t.desc}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Stats breakdown */}
              <div>
                <h4 className="text-xs font-bold text-[var(--foreground)] mb-3 uppercase tracking-wider">Métricas Detalhadas</h4>
                <div className="space-y-2">
                  {[
                    { label: "Programs total", val: bounty?.programs ?? 0, c: "text-indigo-400" },
                    { label: "Programs com bounty", val: bounty?.programs_with_bounty ?? 0, c: "text-emerald-400" },
                    { label: "Total targets", val: bounty?.targets ?? 0, c: "text-slate-300" },
                    { label: "Targets vivos", val: bounty?.alive_targets ?? 0, c: "text-emerald-400" },
                    { label: "Targets novos", val: bounty?.new_targets ?? 0, c: "text-lime-400" },
                    { label: "Taxa de sobrevivência", val: `${Math.round((bounty?.alive_targets ?? 0) / Math.max(bounty?.targets ?? 1, 1) * 100)}%`, c: ((bounty?.alive_targets ?? 0) / Math.max(bounty?.targets ?? 1, 1)) > 0.5 ? "text-emerald-400" : "text-amber-400" },
                    { label: "Mudanças detectadas", val: bounty?.total_changes ?? 0, c: "text-slate-300" },
                    { label: "Erros no recon", val: recon?.errors ?? 0, c: (recon?.errors ?? 0) > 0 ? "text-red-400" : "text-emerald-400" },
                  ].map(r => (
                    <div key={r.label} className="flex items-center justify-between text-xs px-2 py-1.5 rounded-lg hover:bg-white/3">
                      <span className="text-[var(--muted)]">{r.label}</span>
                      <span className={`font-bold tabular-nums ${r.c}`}>{typeof r.val === 'number' ? r.val.toLocaleString() : r.val}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Tips */}
              <div className="p-3 rounded-lg bg-cyan-500/5 border border-cyan-500/15">
                <div className="text-[10px] font-bold text-cyan-300 mb-2">💡 Dicas para Melhorar o Recon</div>
                <ul className="text-[10px] text-cyan-200/70 space-y-1.5 list-disc pl-4">
                  <li>Execute recon em horários alternados para detectar infraestrutura efêmera (staging, dev)</li>
                  <li>Monitore crt.sh regularmente — novos certificados indicam novos serviços sendo deployados</li>
                  <li>Subdomínios novos têm maior chance de ter vulnerabilidades (menos hardening)</li>
                  <li>Combine subfinder + Amass para máxima cobertura de enumeração passiva</li>
                  <li>ASN discovery pode revelar ranges de IP inteiros que são in-scope</li>
                </ul>
              </div>
            </div>
          </Modal>

          {/* ── AI Analyzer Modal ── */}
          <Modal open={activeModal === 'ai'} onClose={() => setActiveModal(null)} title="🧠 AI Analyzer — Detalhes" maxWidth="max-w-3xl">
            <div className="space-y-6">
              {aiStats ? (
                <>
                  {/* Status & Model */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <div className="p-3 rounded-xl border bg-fuchsia-500/10 border-fuchsia-500/20 text-center">
                      <div className={`text-2xl font-bold ${aiStats.enabled ? "text-emerald-400" : "text-red-400"}`}>{aiStats.enabled ? "ON" : "OFF"}</div>
                      <div className="text-[10px] text-[var(--muted)] uppercase mt-1">Status</div>
                    </div>
                    <div className="p-3 rounded-xl border bg-violet-500/10 border-violet-500/20 text-center">
                      <div className="text-lg font-bold text-violet-400 truncate">{aiStats.model || "N/A"}</div>
                      <div className="text-[10px] text-[var(--muted)] uppercase mt-1">Modelo</div>
                    </div>
                    <div className="p-3 rounded-xl border bg-cyan-500/10 border-cyan-500/20 text-center">
                      <div className="text-2xl font-bold text-cyan-400 tabular-nums">{aiStats.requests}</div>
                      <div className="text-[10px] text-[var(--muted)] uppercase mt-1">Requests</div>
                    </div>
                    <div className="p-3 rounded-xl border bg-amber-500/10 border-amber-500/20 text-center">
                      <div className="text-2xl font-bold text-amber-400 tabular-nums">{aiStats.tokens_used.toLocaleString()}</div>
                      <div className="text-[10px] text-[var(--muted)] uppercase mt-1">Tokens</div>
                    </div>
                  </div>

                  {/* Operations */}
                  <div>
                    <h4 className="text-xs font-bold text-[var(--foreground)] mb-3 uppercase tracking-wider">Operações da AI</h4>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      {[
                        { icon: "📝", label: "Reports Gerados", val: aiStats.reports_generated, desc: "Relatórios profissionais criados automaticamente com título, CVSS, PoC, steps to reproduce e impacto.", c: "text-fuchsia-400", bg: "bg-fuchsia-500/10 border-fuchsia-500/20" },
                        { icon: "🔬", label: "Findings Classificados", val: aiStats.findings_classified, desc: "Vulnerabilidades analisadas para determinar true positive vs false positive com confiança.", c: "text-violet-400", bg: "bg-violet-500/10 border-violet-500/20" },
                        { icon: "📡", label: "Responses Analisadas", val: aiStats.responses_analyzed, desc: "Respostas HTTP analisadas para detectar padrões de vulnerabilidade e informações sensíveis.", c: "text-cyan-400", bg: "bg-cyan-500/10 border-cyan-500/20" },
                      ].map(op => (
                        <div key={op.label} className={`p-4 rounded-xl border ${op.bg}`}>
                          <div className="flex items-center gap-2 mb-2">
                            <span className="text-lg">{op.icon}</span>
                            <span className="text-xs font-bold text-[var(--foreground)]">{op.label}</span>
                          </div>
                          <div className={`text-3xl font-bold tabular-nums ${op.c} mb-2`}>{op.val}</div>
                          <p className="text-[10px] text-[var(--muted)] leading-relaxed">{op.desc}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Error rate */}
                  {aiStats.errors > 0 && (
                    <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-red-300 font-bold">⚠️ Erros: {aiStats.errors}</span>
                        <span className="text-[var(--muted)]">Taxa de erro: {Math.round(aiStats.errors / Math.max(aiStats.requests, 1) * 100)}%</span>
                      </div>
                      <p className="text-[10px] text-red-200/60 mt-1">Verifique se o Ollama está rodando, o modelo está carregado e há memória/GPU suficiente.</p>
                    </div>
                  )}

                  {/* Configuration Guide */}
                  <div className="p-4 rounded-lg bg-white/3 border border-white/10">
                    <h4 className="text-xs font-bold text-fuchsia-300 mb-3">⚙️ Configuração</h4>
                    <div className="grid grid-cols-2 gap-3 text-[10px]">
                      <div><span className="text-[var(--muted)]">Provider:</span> <strong className="text-fuchsia-300">{aiStats.provider || "ollama"}</strong></div>
                      <div><span className="text-[var(--muted)]">Model:</span> <strong className="text-fuchsia-300">{aiStats.model || "N/A"}</strong></div>
                    </div>
                    <div className="mt-3 p-2 rounded bg-black/30 font-mono text-[9px] text-fuchsia-100/70 space-y-0.5">
                      <div>AI_PROVIDER=ollama</div>
                      <div>OLLAMA_URL=http://host.docker.internal:11434</div>
                      <div>AI_MODEL=mistral  # ou llama3, codellama</div>
                    </div>
                  </div>

                  {/* AI Capabilities */}
                  <div>
                    <h4 className="text-xs font-bold text-[var(--foreground)] mb-3 uppercase tracking-wider">Capacidades da AI</h4>
                    <div className="space-y-2">
                      {[
                        { icon: "📝", title: "Geração de Reports", desc: "Cria relatórios profissionais com título atrativo, CVSS 3.1, CWE ID, steps detalhados, PoC com cURL/HTTP e remediação." },
                        { icon: "🔬", title: "Classificação True/False Positive", desc: "Analisa evidências para determinar se um finding é real ou falso positivo, com score de confiança." },
                        { icon: "🔗", title: "Vulnerability Chain Analysis", desc: "Identifica cadeias de vulnerabilidades (ex: SSRF → AWS metadata → RCE) para aumentar severidade e impacto." },
                        { icon: "📊", title: "CVSS Scoring Automático", desc: "Calcula score CVSS 3.1 baseado nos vetores AV/AC/PR/UI/S/C/I/A extraídos do contexto da vulnerabilidade." },
                        { icon: "💡", title: "Sugestão de Impacto", desc: "Gera descrições de impacto de negócio que triagers valorizam: compliance, data leak, financial loss, etc." },
                      ].map(cap => (
                        <div key={cap.title} className="flex gap-3 p-2 rounded-lg bg-white/3 hover:bg-white/5 transition-colors">
                          <span className="text-base mt-0.5 flex-shrink-0">{cap.icon}</span>
                          <div>
                            <span className="text-xs font-bold text-[var(--foreground)]">{cap.title}</span>
                            <p className="text-[10px] text-[var(--muted)] mt-0.5 leading-relaxed">{cap.desc}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              ) : (
                <div className="text-center py-8">
                  <div className="text-4xl mb-3">🤖</div>
                  <div className="text-sm text-[var(--muted)] mb-2">AI não configurada</div>
                  <p className="text-[10px] text-[var(--muted)] max-w-md mx-auto">Configure AI_PROVIDER=ollama e OLLAMA_URL no .env para habilitar geração automática de reports, classificação de findings e análise de responses.</p>
                </div>
              )}
            </div>
          </Modal>

          {/* ── Recon Live Modal ── */}
          <Modal open={activeModal === 'recon-live'} onClose={() => setActiveModal(null)} title="📡 Recon Live — Todos os Programas" maxWidth="max-w-4xl">
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="p-3 rounded-lg bg-indigo-500/10 border border-indigo-500/20">
                  <div className="text-xl font-bold text-indigo-400">{allPrograms.length}</div>
                  <div className="text-[9px] text-[var(--muted)] uppercase">Total Programas</div>
                </div>
                <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
                  <div className="text-xl font-bold text-blue-400">{allPrograms.filter(p => p.status === "reconning").length}</div>
                  <div className="text-[9px] text-[var(--muted)] uppercase">Em Execução</div>
                </div>
                <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                  <div className="text-xl font-bold text-emerald-400">{allPrograms.filter(p => (p.alive_count ?? 0) > 0).length}</div>
                  <div className="text-[9px] text-[var(--muted)] uppercase">Com Targets</div>
                </div>
              </div>
              <div className="border border-[var(--border)] rounded-xl overflow-hidden">
                <div className="overflow-x-auto">
                <div className="grid grid-cols-[minmax(120px,1fr)_80px_70px_70px_70px_70px] gap-0 px-3 py-2 bg-white/3 border-b border-[var(--border)] text-[9px] font-bold text-[var(--muted)] uppercase min-w-[480px]">
                  <span>Programa</span><span className="text-center">Plataforma</span><span className="text-center">Targets</span><span className="text-center">Alive</span><span className="text-center">Vulns</span><span className="text-center">Status</span>
                </div>
                <div className="max-h-[50vh] overflow-y-auto divide-y divide-[var(--border)] min-w-[480px]">
                  {allPrograms.map(p => {
                    const isRunning = p.status === "reconning";
                    const hasTargets = (p.alive_count ?? 0) > 0;
                    return (
                      <div key={p.id} className="grid grid-cols-[minmax(120px,1fr)_80px_70px_70px_70px_70px] gap-0 px-3 py-2.5 hover:bg-white/[0.02] transition-colors items-center">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className={`w-2 h-2 rounded-full shrink-0 ${isRunning ? "bg-blue-400 animate-pulse" : p.status === "error" ? "bg-red-400" : hasTargets ? "bg-emerald-400" : "bg-[var(--muted)]"}`} />
                          <span className="text-xs font-medium text-[var(--foreground)] truncate">{p.name}</span>
                        </div>
                        <span className="text-[10px] text-[var(--muted)] text-center">{p.platform}</span>
                        <span className="text-[10px] text-[var(--foreground)] text-center tabular-nums font-semibold">{p.target_count ?? 0}</span>
                        <span className={`text-[10px] text-center tabular-nums font-semibold ${hasTargets ? "text-emerald-400" : "text-[var(--muted)]"}`}>{p.alive_count ?? 0}</span>
                        <span className={`text-[10px] text-center tabular-nums font-semibold ${(p.vuln_count ?? 0) > 0 ? "text-red-400" : "text-[var(--muted)]"}`}>{p.vuln_count ?? 0}</span>
                        <span className={`text-[9px] text-center font-bold px-1.5 py-0.5 rounded ${
                          isRunning ? "bg-blue-500/15 text-blue-400" :
                          p.status === "error" ? "bg-red-500/15 text-red-400" :
                          p.status === "done" ? "bg-emerald-500/15 text-emerald-400" :
                          "bg-white/5 text-[var(--muted)]"
                        }`}>{p.status || "idle"}</span>
                      </div>
                    );
                  })}
                </div>
                </div>
              </div>
              {allPrograms.length === 0 && (
                <div className="text-center py-8 text-xs text-[var(--muted)]">Nenhum programa cadastrado. Vá em Programs para adicionar.</div>
              )}
            </div>
          </Modal>

          {/* ── Quick Actions Modal ── */}
          <Modal open={activeModal === 'actions'} onClose={() => setActiveModal(null)} title="⚡ Quick Actions — Guia Completo" maxWidth="max-w-3xl">
            <div className="space-y-4">
              {[
                { icon: "🔍", action: "Discover H1 Programs", desc: "Consulta a API pública da HackerOne para encontrar novos programas de bug bounty. Programas com bounty ativo e escopo web são importados automaticamente.", when: "Execute semanalmente para descobrir novos programas lançados." },
                { icon: "📊", action: "Score Programs", desc: "Calcula um score de 0-100 para cada programa baseado em: valor máximo de bounty, quantidade de targets vivos, competição (número de hackers), tipo de escopo e safe harbor.", when: "Execute após importar novos programas ou após recon para atualizar scores." },
                { icon: "📜", action: "Check CT Logs", desc: "Monitora Certificate Transparency logs para descobrir novos domínios emitidos por organizações dos seus programas. Domínios novos podem indicar serviços em staging/development.", when: "Execute diariamente — certificados novos indicam infraestrutura recém-deployada." },
                { icon: "🛡", action: "Check CVE Feeds", desc: "Consulta feeds de CVE recentes (NVD, MITRE) e cria templates Nuclei customizados para vulnerabilidades relevantes ao seu portfólio de targets.", when: "Execute quando novos CVEs críticos são publicados (recomendado: diariamente)." },
                { icon: "🔵", action: "Import Intigriti", desc: "Importa programas da plataforma Intigriti usando seu API token. Cria registros de programa com escopo, bounty range e informações de política.", when: "Execute ao configurar sua conta Intigriti ou semanalmente para atualizações." },
                { icon: "🔄", action: "Recon All", desc: "Dispara reconhecimento em TODOS os programas registrados. Executa subfinder, crt.sh, httpx, rDNS e ASN discovery para cada programa.", when: "Use com cuidado — pode demorar horas com muitos programas. Prefira recon individual." },
              ].map(a => (
                <div key={a.action} className="p-4 rounded-xl bg-white/3 border border-white/10 hover:border-white/20 transition-colors">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-lg">{a.icon}</span>
                    <span className="text-sm font-bold text-[var(--foreground)]">{a.action}</span>
                  </div>
                  <p className="text-xs text-[var(--muted)] leading-relaxed mb-2">{a.desc}</p>
                  <div className="flex items-start gap-1.5 p-2 rounded bg-blue-500/5 border border-blue-500/15">
                    <span className="text-[10px]">⏰</span>
                    <span className="text-[10px] text-blue-200/80">{a.when}</span>
                  </div>
                </div>
              ))}
              {/* Record Earning Guide */}
              <div className="p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/15">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-lg">💰</span>
                  <span className="text-sm font-bold text-emerald-300">Record Earning</span>
                </div>
                <p className="text-xs text-emerald-200/70 leading-relaxed">Registre bounties recebidos para rastrear seu ROI. Informe o nome do programa e o valor em USD. O sistema usa esses dados para calcular: taxa de retorno, programa mais lucrativo, tipo de vulnerabilidade mais rentável e recomendações personalizadas.</p>
              </div>
            </div>
          </Modal>

          {/* ── Program Rankings Modal ── */}
          <Modal open={activeModal === 'rankings'} onClose={() => setActiveModal(null)} title="🏆 Program Rankings — Detalhes" maxWidth="max-w-4xl">
            <div className="space-y-4">
              {/* Tier distribution */}
              <div className="grid grid-cols-5 gap-2">
                {["S", "A", "B", "C", "D"].map(tier => {
                  const count = programs.filter(p => p.tier === tier).length;
                  return (
                    <div key={tier} className={`p-3 rounded-xl border text-center ${TIER_COLORS[tier] || "bg-slate-700 text-slate-300 border-slate-600"}`}>
                      <div className="text-2xl font-bold">{tier}</div>
                      <div className="text-lg font-bold tabular-nums mt-1">{count}</div>
                      <div className="text-[9px] opacity-70 uppercase">programas</div>
                    </div>
                  );
                })}
              </div>

              {/* Full table */}
              <div className="border border-[var(--border)] rounded-xl overflow-hidden">
                <div className="overflow-x-auto">
                <div className="grid grid-cols-[30px_40px_minmax(100px,1fr)_60px_80px_60px_minmax(80px,1fr)] gap-0 px-3 py-2 bg-white/3 border-b border-[var(--border)] text-[9px] font-bold text-[var(--muted)] uppercase min-w-[520px]">
                  <span>#</span><span>Tier</span><span>Programa</span><span className="text-center">Score</span><span className="text-center">Bounty Max</span><span className="text-center">Targets</span><span>Recomendação</span>
                </div>
                <div className="max-h-[50vh] overflow-y-auto divide-y divide-[var(--border)] min-w-[520px]">
                  {programs.map((p, i) => (
                    <div key={p.program_id} className="grid grid-cols-[30px_40px_minmax(100px,1fr)_60px_80px_60px_minmax(80px,1fr)] gap-0 px-3 py-2.5 hover:bg-white/[0.02] transition-colors items-center">
                      <span className="text-[10px] text-[var(--muted)] tabular-nums">{i + 1}</span>
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border w-fit ${TIER_COLORS[p.tier] || "bg-slate-700 text-slate-300 border-slate-600"}`}>{p.tier}</span>
                      <span className="text-xs font-medium text-[var(--foreground)] truncate">{p.name}</span>
                      <span className="text-xs font-bold text-center tabular-nums text-[var(--accent-light)]">{p.score}</span>
                      <span className="text-[10px] text-center tabular-nums font-semibold text-emerald-400">{p.has_bounty && p.bounty_max ? `$${p.bounty_max.toLocaleString()}` : "—"}</span>
                      <span className="text-[10px] text-center tabular-nums">{p.alive_targets}</span>
                      <span className="text-[10px] text-[var(--muted)] truncate">{p.recommendation}</span>
                    </div>
                  ))}
                </div>
                </div>
              </div>
              {programs.length === 0 && (
                <div className="text-center py-8 text-xs text-[var(--muted)]">Nenhum programa pontuado. Use &quot;Score Programs&quot; nas Quick Actions.</div>
              )}

              {/* Scoring explanation */}
              <div className="p-4 rounded-lg bg-white/3 border border-white/10">
                <h4 className="text-xs font-bold text-[var(--foreground)] mb-2">📐 Como o Score é Calculado</h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[10px] text-[var(--muted)]">
                  <div>• <strong className="text-[var(--foreground)]">Bounty (40%)</strong>: Valor máximo do bounty do programa</div>
                  <div>• <strong className="text-[var(--foreground)]">Scope (25%)</strong>: Quantidade e tipo de assets in-scope</div>
                  <div>• <strong className="text-[var(--foreground)]">Targets (20%)</strong>: Hosts vivos e acessíveis para scan</div>
                  <div>• <strong className="text-[var(--foreground)]">Competição (15%)</strong>: Inverso do número de hackers ativos</div>
                </div>
              </div>
            </div>
          </Modal>

          {/* ── Recent Activity Modal ── */}
          <Modal open={activeModal === 'activity'} onClose={() => setActiveModal(null)} title="📋 Atividade Recente — Timeline" maxWidth="max-w-3xl">
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="p-3 rounded-lg bg-lime-500/10 border border-lime-500/20">
                  <div className="text-xl font-bold text-lime-400">{changes.length}</div>
                  <div className="text-[9px] text-[var(--muted)] uppercase">Mudanças</div>
                </div>
                <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                  <div className="text-xl font-bold text-emerald-400">{changes.reduce((acc, ch) => acc + (ch.new_subdomains?.length ?? 0), 0)}</div>
                  <div className="text-[9px] text-[var(--muted)] uppercase">Novos Subs</div>
                </div>
                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                  <div className="text-xl font-bold text-red-400">{changes.reduce((acc, ch) => acc + (ch.removed_subdomains?.length ?? 0), 0)}</div>
                  <div className="text-[9px] text-[var(--muted)] uppercase">Removidos</div>
                </div>
              </div>
              <div className="space-y-3 max-h-[60vh] overflow-y-auto">
                {changes.map((ch, i) => (
                  <div key={ch.id || i} className="p-4 rounded-xl bg-white/3 border border-white/10 hover:border-lime-500/20 transition-colors">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-bold text-[var(--foreground)]">{ch.program_name}</span>
                      <div className="flex items-center gap-2">
                        {ch.new_subdomains?.length > 0 && <span className="text-xs font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded">+{ch.new_subdomains.length}</span>}
                        {ch.removed_subdomains?.length > 0 && <span className="text-xs font-bold text-red-400 bg-red-500/10 px-2 py-0.5 rounded">-{ch.removed_subdomains.length}</span>}
                        <span className="text-[10px] text-[var(--muted)]">{ch.total_current} total</span>
                      </div>
                    </div>
                    {ch.timestamp && <div className="text-[9px] text-[var(--muted)] mb-2">{new Date(ch.timestamp).toLocaleString("pt-BR")}</div>}
                    {ch.new_subdomains?.length > 0 && (
                      <div className="mb-2">
                        <div className="text-[9px] text-emerald-400 font-semibold uppercase mb-1">Novos subdomínios:</div>
                        <div className="flex flex-wrap gap-1">
                          {ch.new_subdomains.map((s, j) => (
                            <span key={j} className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/15 font-mono">{s}</span>
                          ))}
                        </div>
                      </div>
                    )}
                    {ch.removed_subdomains?.length > 0 && (
                      <div>
                        <div className="text-[9px] text-red-400 font-semibold uppercase mb-1">Removidos:</div>
                        <div className="flex flex-wrap gap-1">
                          {ch.removed_subdomains.map((s, j) => (
                            <span key={j} className="text-[10px] px-2 py-0.5 rounded bg-red-500/10 text-red-300 border border-red-500/15 font-mono line-through">{s}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
                {changes.length === 0 && <div className="text-center py-8 text-xs text-[var(--muted)]">Nenhuma mudança detectada ainda. Execute recon para começar a monitorar.</div>}
              </div>
            </div>
          </Modal>

          {/* ── Intelligence / ROI Modal ── */}
          <Modal open={activeModal === 'intelligence'} onClose={() => setActiveModal(null)} title="📊 Intelligence & ROI — Dashboard Completo" maxWidth="max-w-4xl">
            <div className="space-y-6">
              {/* Earnings Summary */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-4 rounded-xl bg-green-500/10 border border-green-500/20 text-center">
                  <div className="text-2xl font-bold text-green-400">${(roi?.summary.total_earnings ?? 0).toLocaleString()}</div>
                  <div className="text-[9px] text-[var(--muted)] uppercase mt-1">Total Earnings</div>
                </div>
                <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-center">
                  <div className="text-2xl font-bold text-emerald-400">{roi?.summary.total_reports_paid ?? 0}</div>
                  <div className="text-[9px] text-[var(--muted)] uppercase mt-1">Reports Pagos</div>
                </div>
                <div className="p-4 rounded-xl bg-teal-500/10 border border-teal-500/20 text-center">
                  <div className="text-2xl font-bold text-teal-400">${(roi?.summary.avg_payout ?? 0).toLocaleString()}</div>
                  <div className="text-[9px] text-[var(--muted)] uppercase mt-1">Payout Médio</div>
                </div>
                <div className="p-4 rounded-xl bg-yellow-500/10 border border-yellow-500/20 text-center">
                  <div className="text-2xl font-bold text-yellow-400">${(roi?.summary.highest_payout ?? 0).toLocaleString()}</div>
                  <div className="text-[9px] text-[var(--muted)] uppercase mt-1">Maior Payout</div>
                </div>
              </div>

              {/* Operations metrics */}
              <div>
                <h4 className="text-xs font-bold text-[var(--foreground)] mb-3 uppercase tracking-wider">Operações</h4>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  {[
                    { label: "Programas Ativos", val: roi?.operations.active_programs ?? 0, c: "text-indigo-400" },
                    { label: "Reports Enviados", val: roi?.operations.reports_submitted ?? 0, c: "text-blue-400" },
                    { label: "Reports Aceitos", val: roi?.operations.reports_accepted ?? 0, c: "text-emerald-400" },
                    { label: "Taxa de Aceitação", val: `${roi?.operations.acceptance_rate ?? 0}%`, c: (roi?.operations.acceptance_rate ?? 0) > 50 ? "text-emerald-400" : "text-red-400" },
                  ].map(m => (
                    <div key={m.label} className="p-3 rounded-lg bg-white/5 border border-white/10 text-center">
                      <div className={`text-xl font-bold tabular-nums ${m.c}`}>{typeof m.val === 'number' ? m.val.toLocaleString() : m.val}</div>
                      <div className="text-[9px] text-[var(--muted)] uppercase mt-1">{m.label}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Monthly Trend (enlarged) */}
              {roi && Object.keys(roi.monthly_trend).length > 0 && (
                <div>
                  <h4 className="text-xs font-bold text-[var(--foreground)] mb-3 uppercase tracking-wider">Tendência Mensal</h4>
                  <div className="flex items-end gap-2 h-32 p-3 rounded-lg bg-white/3 border border-white/10">
                    {Object.entries(roi.monthly_trend).slice(-12).map(([month, v]) => {
                      const maxE = Math.max(...Object.values(roi.monthly_trend).map(x => x.earnings), 1);
                      return (
                        <div key={month} className="flex-1 flex flex-col items-center gap-1 h-full justify-end">
                          <span className="text-[9px] text-emerald-400 font-bold tabular-nums">${v.earnings}</span>
                          <div className="w-full rounded-t bg-gradient-to-t from-emerald-600 to-emerald-400 hover:from-emerald-500 hover:to-emerald-300 transition-colors min-h-[2px]"
                            style={{ height: `${Math.max((v.earnings / maxE) * 100, 4)}%` }}
                            title={`${month}: $${v.earnings} (${v.count} reports)`} />
                          <span className="text-[8px] text-[var(--muted)] tabular-nums">{month.slice(-5)}</span>
                          <span className="text-[8px] text-[var(--muted)]">{v.count}r</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Top Programs */}
              {roi && roi.top_programs.length > 0 && (
                <div>
                  <h4 className="text-xs font-bold text-[var(--foreground)] mb-3 uppercase tracking-wider">Programas Mais Lucrativos</h4>
                  <div className="space-y-2">
                    {roi.top_programs.map((p, i) => (
                      <div key={i} className="flex items-center gap-3 p-3 rounded-lg bg-white/3 border border-white/10 hover:border-emerald-500/20 transition-colors">
                        <span className="text-lg font-bold text-[var(--muted)] w-6 text-center">{i + 1}</span>
                        <div className="flex-1 min-w-0">
                          <div className="text-xs font-bold text-[var(--foreground)] truncate">{p.name}</div>
                          <div className="text-[10px] text-[var(--muted)]">{p.reports} reports • ${p.hourly_rate}/h • {p.efficiency}</div>
                        </div>
                        <span className="text-lg font-bold text-emerald-400 tabular-nums">${p.earned.toLocaleString()}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Most profitable vulns */}
              {roi && roi.most_profitable_vulns.length > 0 && (
                <div>
                  <h4 className="text-xs font-bold text-[var(--foreground)] mb-3 uppercase tracking-wider">Tipos de Vulnerabilidade Mais Rentáveis</h4>
                  <div className="space-y-2">
                    {roi.most_profitable_vulns.map((v, i) => {
                      const maxAvg = Math.max(...roi.most_profitable_vulns.map(x => x.avg_payout), 1);
                      return (
                        <div key={i} className="group">
                          <div className="flex items-center justify-between mb-1 text-xs">
                            <span className="font-semibold text-[var(--foreground)]">{v.type}</span>
                            <div className="flex items-center gap-3">
                              <span className="text-[var(--muted)]">{v.count} reports</span>
                              <span className="text-amber-400 font-bold tabular-nums">avg ${v.avg_payout}</span>
                              <span className="text-emerald-400 font-bold tabular-nums">${v.earnings}</span>
                            </div>
                          </div>
                          <div className="h-2 rounded-full bg-white/5 overflow-hidden">
                            <div className="h-full rounded-full bg-gradient-to-r from-amber-500 to-yellow-400 transition-all" style={{ width: `${(v.avg_payout / maxAvg) * 100}%` }} />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Recent CVEs */}
              {recentCVEs.length > 0 && (
                <div>
                  <h4 className="text-xs font-bold text-[var(--foreground)] mb-3 uppercase tracking-wider">CVEs Recentes</h4>
                  <div className="space-y-1.5">
                    {recentCVEs.slice(0, 10).map((cve: any, i: number) => (
                      <div key={i} className="flex items-center justify-between p-2 rounded-lg bg-white/3 hover:bg-white/5 transition-colors">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="text-xs font-mono font-bold text-[var(--foreground)]">{cve.id}</span>
                          {cve.description && <span className="text-[10px] text-[var(--muted)] truncate max-w-xs">{cve.description}</span>}
                        </div>
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                          cve.severity === "critical" ? "bg-red-500/15 text-red-400" :
                          cve.severity === "high" ? "bg-orange-500/15 text-orange-400" :
                          "bg-amber-500/15 text-amber-400"
                        }`}>{cve.cvss_score}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommendations */}
              {roi && roi.recommendations.length > 0 && (
                <div>
                  <h4 className="text-xs font-bold text-[var(--foreground)] mb-3 uppercase tracking-wider">Recomendações</h4>
                  <div className="space-y-2">
                    {roi.recommendations.map((r, i) => (
                      <div key={i} className="flex gap-2 p-3 rounded-lg bg-teal-500/5 border border-teal-500/15">
                        <span className="text-base flex-shrink-0">💡</span>
                        <span className="text-xs text-teal-200/80 leading-relaxed">{r}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </Modal>

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
