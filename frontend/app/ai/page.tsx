"use client";

import { useState, useCallback, useEffect, useRef } from "react";
import {
  fetchAIStats,
  fetchBountyPrograms,
  aiClassifyFinding,
  aiAnalyzeResponse,
  aiParseScope,
  aiAnalyzeJS,
  aiFindChains,
  aiClassifyTarget,
  fetchProgramAiAnalysis,
  fetchTargetAiAnalysis,
  triggerProgramAiAnalysis,
  type AIStats,
  type BountyProgram,
  type PrioritizedTarget,
  type TargetAiAnalysis,
  type AiReport,
} from "@/lib/api";

/* ═══════════════════════════════════════════════════════════════
   Helpers
   ═══════════════════════════════════════════════════════════════ */

const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#6b7280",
};

function Badge({ text, color }: { text: string; color: string }) {
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider"
      style={{ background: `${color}20`, color, border: `1px solid ${color}40` }}
    >
      {text}
    </span>
  );
}

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span className="relative flex h-2 w-2 shrink-0">
      {ok && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />}
      <span className={`relative inline-flex rounded-full h-2 w-2 ${ok ? "bg-emerald-500" : "bg-red-500"}`} />
    </span>
  );
}

function Card({ title, icon, children, className = "" }: { title: string; icon: React.ReactNode; children: React.ReactNode; className?: string }) {
  return (
    <div className={`rounded-2xl border border-[var(--border)] bg-[var(--card)] p-5 ${className}`}>
      <div className="flex items-center gap-2 mb-4">
        <span className="text-[var(--accent-light)]">{icon}</span>
        <h3 className="text-sm font-bold text-[var(--foreground)]">{title}</h3>
      </div>
      {children}
    </div>
  );
}

function StatBox({ label, value, sub, color = "var(--accent-light)" }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="text-center">
      <div className="text-2xl font-black tabular-nums" style={{ color }}>{value}</div>
      <div className="text-[10px] text-[var(--muted)] uppercase tracking-wider font-bold mt-0.5">{label}</div>
      {sub && <div className="text-[9px] text-[var(--muted)] mt-0.5">{sub}</div>}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   AI Analysis Page
   ═══════════════════════════════════════════════════════════════ */

export default function AIAnalysisPage() {
  /* ── State ── */
  const [stats, setStats] = useState<AIStats | null>(null);
  const [programs, setPrograms] = useState<BountyProgram[]>([]);
  const [activeTab, setActiveTab] = useState<"overview" | "classify" | "analyze" | "scope" | "js" | "programs">("overview");

  // Classify Finding
  const [classifyInput, setClassifyInput] = useState('{\n  "code": "xss-reflected",\n  "title": "Reflected XSS in search",\n  "severity": "medium",\n  "matched_at": "https://example.com/search?q=<script>alert(1)</script>",\n  "proof": "Reflected user input in HTML without encoding"\n}');
  const [classifyResult, setClassifyResult] = useState<Record<string, unknown> | null>(null);
  const [classifyLoading, setClassifyLoading] = useState(false);

  // Analyze Response
  const [analyzeUrl, setAnalyzeUrl] = useState("https://example.com/api/user");
  const [analyzeStatus, setAnalyzeStatus] = useState("200");
  const [analyzeHeaders, setAnalyzeHeaders] = useState('{"Content-Type": "application/json"}');
  const [analyzeBody, setAnalyzeBody] = useState('{"id": 1, "email": "user@test.com", "ssn": "123-45-6789"}');
  const [analyzeResult, setAnalyzeResult] = useState<any>(null);
  const [analyzeLoading, setAnalyzeLoading] = useState(false);

  // Parse Scope
  const [scopeText, setScopeText] = useState("");
  const [scopePolicy, setScopePolicy] = useState("");
  const [scopeResult, setScopeResult] = useState<any>(null);
  const [scopeLoading, setScopeLoading] = useState(false);

  // JS Analyzer
  const [jsCode, setJsCode] = useState("");
  const [jsUrl, setJsUrl] = useState("");
  const [jsResult, setJsResult] = useState<any>(null);
  const [jsLoading, setJsLoading] = useState(false);

  // Program AI Analysis
  const [selectedProgram, setSelectedProgram] = useState<string | null>(null);
  const [programAnalysis, setProgramAnalysis] = useState<{
    program_id: string;
    program_name: string;
    ai_report: AiReport | null;
    prioritized_targets: PrioritizedTarget[];
    ai_ready: boolean;
  } | null>(null);
  const [programLoading, setProgramLoading] = useState(false);
  const [triggerLoading, setTriggerLoading] = useState(false);

  // Console output
  const [consoleLogs, setConsoleLogs] = useState<{ ts: string; msg: string; type: "info" | "ok" | "err" | "warn" }[]>([]);
  const consoleRef = useRef<HTMLDivElement>(null);

  const log = useCallback((msg: string, type: "info" | "ok" | "err" | "warn" = "info") => {
    setConsoleLogs(prev => [...prev, { ts: new Date().toLocaleTimeString(), msg, type }]);
  }, []);

  useEffect(() => {
    if (consoleRef.current) consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
  }, [consoleLogs]);

  /* ── Fetch data ── */
  const loadData = useCallback(async () => {
    try {
      const [s, p] = await Promise.all([fetchAIStats(), fetchBountyPrograms()]);
      setStats(s);
      setPrograms(p);
    } catch (e) {
      console.error("[AI] Load error:", e);
    }
  }, []);

  useEffect(() => {
    loadData();
    const id = setInterval(loadData, 15000);
    return () => clearInterval(id);
  }, [loadData]);

  /* ── Actions ── */
  const handleClassify = async () => {
    setClassifyLoading(true);
    setClassifyResult(null);
    log("Enviando finding para classificação AI...");
    try {
      const finding = JSON.parse(classifyInput);
      const result = await aiClassifyFinding(finding);
      setClassifyResult(result);
      log(`Classificação: ${result.classification} | Severidade: ${result.real_severity} | Confiança: ${(result.confidence * 100).toFixed(0)}%`, "ok");
    } catch (e: any) {
      log(`Erro na classificação: ${e.message}`, "err");
    } finally {
      setClassifyLoading(false);
    }
  };

  const handleAnalyze = async () => {
    setAnalyzeLoading(true);
    setAnalyzeResult(null);
    log("Analisando resposta HTTP com AI...");
    try {
      const headers = JSON.parse(analyzeHeaders);
      const result = await aiAnalyzeResponse({ url: analyzeUrl, status_code: parseInt(analyzeStatus), headers, body: analyzeBody });
      setAnalyzeResult(result);
      log(`Análise completa: ${result?.findings?.length || 0} findings identificados`, "ok");
    } catch (e: any) {
      log(`Erro na análise: ${e.message}`, "err");
    } finally {
      setAnalyzeLoading(false);
    }
  };

  const handleParseScope = async () => {
    setScopeLoading(true);
    setScopeResult(null);
    log("Parseando scope do programa com AI...");
    try {
      const result = await aiParseScope({ description: scopeText, policy: scopePolicy || undefined });
      setScopeResult(result);
      log(`Scope parseado: ${result?.in_scope?.length || 0} in-scope, ${result?.out_of_scope?.length || 0} out-of-scope`, "ok");
    } catch (e: any) {
      log(`Erro no parse de scope: ${e.message}`, "err");
    } finally {
      setScopeLoading(false);
    }
  };

  const handleAnalyzeJS = async () => {
    setJsLoading(true);
    setJsResult(null);
    log("Analisando JavaScript com AI...");
    try {
      const result = await aiAnalyzeJS({ code: jsCode, source_url: jsUrl || undefined });
      setJsResult(result);
      log(`JS analisado: ${result?.findings?.length || 0} findings`, "ok");
    } catch (e: any) {
      log(`Erro na análise JS: ${e.message}`, "err");
    } finally {
      setJsLoading(false);
    }
  };

  const handleProgramAnalysis = async (programId: string) => {
    setProgramLoading(true);
    setProgramAnalysis(null);
    setSelectedProgram(programId);
    log(`Carregando análise AI do programa ${programId}...`);
    try {
      const result = await fetchProgramAiAnalysis(programId);
      setProgramAnalysis(result);
      log(`Programa "${result.program_name}" — ${result.prioritized_targets.length} targets priorizados`, "ok");
    } catch (e: any) {
      log(`Erro ao carregar análise: ${e.message}`, "err");
    } finally {
      setProgramLoading(false);
    }
  };

  const handleTriggerAI = async (programId: string) => {
    setTriggerLoading(true);
    log(`Disparando análise AI para programa ${programId}...`, "warn");
    try {
      await triggerProgramAiAnalysis(programId);
      log("Análise AI iniciada em background. Aguarde e recarregue.", "ok");
    } catch (e: any) {
      log(`Erro ao disparar análise: ${e.message}`, "err");
    } finally {
      setTriggerLoading(false);
    }
  };

  /* ── Tabs ── */
  const TABS = [
    { id: "overview" as const, label: "Visão Geral", icon: "📊" },
    { id: "classify" as const, label: "Classificar Finding", icon: "🎯" },
    { id: "analyze" as const, label: "Analisar Response", icon: "🔍" },
    { id: "scope" as const, label: "Parser de Scope", icon: "📋" },
    { id: "js" as const, label: "Análise JS", icon: "⚡" },
    { id: "programs" as const, label: "Programas AI", icon: "🏢" },
  ];

  /* ═══════════════════════════════════════════════════════════════
     RENDER
     ═══════════════════════════════════════════════════════════════ */

  return (
    <div className="h-full flex flex-col gap-4 p-4 overflow-y-auto hide-scrollbar">
      {/* Header */}
      <div className="flex items-start sm:items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-purple-500/15 border border-purple-500/30">
            <svg className="w-5 h-5 text-purple-400" fill="none" viewBox="0 0 24 24" strokeWidth={1.75} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.455 2.456L21.75 6l-1.036.259a3.375 3.375 0 00-2.455 2.456zM16.894 20.567L16.5 21.75l-.394-1.183a2.25 2.25 0 00-1.423-1.423L13.5 18.75l1.183-.394a2.25 2.25 0 001.423-1.423l.394-1.183.394 1.183a2.25 2.25 0 001.423 1.423l1.183.394-1.183.394a2.25 2.25 0 00-1.423 1.423z" />
            </svg>
          </div>
          <div>
            <h1 className="text-lg font-black text-[var(--foreground)] tracking-tight">AI Analysis</h1>
            <p className="text-[11px] text-[var(--muted)]">
              BugGenie — Análise inteligente de vulnerabilidades com LLM
            </p>
          </div>
        </div>

        {/* Status badge */}
        {stats && (
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-[var(--card)] border border-[var(--border)]">
              <StatusDot ok={stats.enabled} />
              <span className="text-[11px] font-bold text-[var(--foreground)]">{stats.provider.toUpperCase()}</span>
              <span className="text-[10px] text-[var(--muted)]">{stats.model}</span>
            </div>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-[var(--card)]/60 p-1 rounded-xl border border-[var(--border)] overflow-x-auto hide-scrollbar">
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === tab.id
                ? "bg-[var(--accent)]/15 text-[var(--accent-light)] shadow-sm"
                : "text-[var(--muted)] hover:text-[var(--foreground)] hover:bg-white/[0.03]"
            }`}
          >
            <span className="text-sm">{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Content + Console */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-4 min-h-0">
        {/* Main content — 8 cols */}
        <div className="lg:col-span-8 overflow-y-auto hide-scrollbar space-y-4">

          {/* ═══════ TAB: OVERVIEW ═══════ */}
          {activeTab === "overview" && (
            <>
              {/* Stats grid */}
              <Card title="Status do Motor AI" icon={
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.75} stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
                </svg>
              }>
                {stats ? (
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
                      <StatBox label="Requests" value={stats.requests} color="#8b5cf6" />
                      <StatBox label="Tokens" value={stats.tokens_used > 1000 ? `${(stats.tokens_used / 1000).toFixed(1)}k` : stats.tokens_used} color="#06b6d4" />
                      <StatBox label="Erros" value={stats.errors} color={stats.errors > 0 ? "#ef4444" : "#22c55e"} />
                      <StatBox label="Reports" value={stats.reports_generated} color="#f59e0b" />
                      <StatBox label="Classified" value={stats.findings_classified} color="#10b981" />
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <div className="rounded-xl bg-[var(--background)] p-3 border border-[var(--border)]">
                        <div className="flex items-center gap-2 mb-2">
                          <StatusDot ok={stats.enabled} />
                          <span className="text-[11px] font-bold text-[var(--foreground)]">Provider</span>
                        </div>
                        <div className="text-lg font-black text-purple-400">{stats.provider || "N/A"}</div>
                        <div className="text-[10px] text-[var(--muted)] mt-0.5">
                          {stats.enabled ? "Ativo e operacional" : "Desativado"}
                        </div>
                      </div>
                      <div className="rounded-xl bg-[var(--background)] p-3 border border-[var(--border)]">
                        <div className="flex items-center gap-2 mb-2">
                          <span className="text-purple-400">
                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" strokeWidth={1.75} stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 3v1.5M4.5 8.25H3m18 0h-1.5M4.5 12H3m18 0h-1.5m-15 3.75H3m18 0h-1.5M8.25 19.5V21M12 3v1.5m0 15V21m3.75-18v1.5m0 15V21m-9-1.5h10.5a2.25 2.25 0 002.25-2.25V6.75a2.25 2.25 0 00-2.25-2.25H6.75A2.25 2.25 0 004.5 6.75v10.5a2.25 2.25 0 002.25 2.25z" />
                            </svg>
                          </span>
                          <span className="text-[11px] font-bold text-[var(--foreground)]">Modelo</span>
                        </div>
                        <div className="text-sm font-bold text-[var(--foreground)] truncate">{stats.model || "N/A"}</div>
                        <div className="text-[10px] text-[var(--muted)] mt-0.5">LLM ativo</div>
                      </div>
                      <div className="rounded-xl bg-[var(--background)] p-3 border border-[var(--border)]">
                        <div className="flex items-center gap-2 mb-2">
                          <span className="text-cyan-400">
                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" strokeWidth={1.75} stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" d="M7.5 14.25v2.25m3-4.5v4.5m3-6.75v6.75m3-9v9M6 20.25h12A2.25 2.25 0 0020.25 18V6A2.25 2.25 0 0018 3.75H6A2.25 2.25 0 003.75 6v12A2.25 2.25 0 006 20.25z" />
                            </svg>
                          </span>
                          <span className="text-[11px] font-bold text-[var(--foreground)]">Análises</span>
                        </div>
                        <div className="text-lg font-black text-cyan-400">{stats.responses_analyzed}</div>
                        <div className="text-[10px] text-[var(--muted)] mt-0.5">Responses analisadas</div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-[var(--muted)] text-xs">Carregando stats...</div>
                )}
              </Card>

              {/* Capabilities info */}
              <Card title="Capacidades AI" icon={
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.75} stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
                </svg>
              }>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { title: "Classificar Findings", desc: "Filtra falsos positivos e identifica severidade real", icon: "🎯", color: "#8b5cf6" },
                    { title: "Analisar HTTP Response", desc: "Detecta vulns em headers, body e status codes", icon: "🔍", color: "#06b6d4" },
                    { title: "Parser de Scope", desc: "Extrai in-scope, out-of-scope e regras do programa", icon: "📋", color: "#f59e0b" },
                    { title: "Análise JavaScript", desc: "Encontra secrets, API keys e flaws no código JS", icon: "⚡", color: "#10b981" },
                    { title: "Vulnerability Chains", desc: "Conecta achados isolados em cadeias de exploração", icon: "🔗", color: "#ef4444" },
                    { title: "Report Writer", desc: "Gera reports profissionais para HackerOne", icon: "📝", color: "#ec4899" },
                  ].map(cap => (
                    <div key={cap.title} className="rounded-xl bg-[var(--background)] p-3 border border-[var(--border)] flex items-start gap-3">
                      <div className="text-xl mt-0.5">{cap.icon}</div>
                      <div>
                        <div className="text-xs font-bold text-[var(--foreground)]">{cap.title}</div>
                        <div className="text-[10px] text-[var(--muted)] mt-0.5 leading-relaxed">{cap.desc}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </Card>
            </>
          )}

          {/* ═══════ TAB: CLASSIFY ═══════ */}
          {activeTab === "classify" && (
            <Card title="Classificar Finding" icon={<span className="text-base">🎯</span>}>
              <div className="space-y-4">
                <div>
                  <label className="block text-[10px] uppercase tracking-wider font-bold text-[var(--muted)] mb-1.5">
                    Finding JSON
                  </label>
                  <textarea
                    value={classifyInput}
                    onChange={e => setClassifyInput(e.target.value)}
                    rows={8}
                    className="w-full rounded-xl bg-[var(--background)] border border-[var(--border)] text-xs text-[var(--foreground)] p-3 font-mono focus:outline-none focus:border-purple-500/50 resize-none"
                    placeholder='{"code": "xss-reflected", "title": "...", "severity": "medium", ...}'
                  />
                </div>
                <button
                  onClick={handleClassify}
                  disabled={classifyLoading || !stats?.enabled}
                  className="px-4 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-xs font-bold transition-all flex items-center gap-2"
                >
                  {classifyLoading ? (
                    <svg className="animate-spin w-3.5 h-3.5" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  ) : (
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
                    </svg>
                  )}
                  Classificar com AI
                </button>

                {classifyResult && (
                  <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-4 space-y-3">
                    <div className="flex items-center gap-2">
                    {classifyResult.classification ? (
                      <Badge
                        text={classifyResult.classification as string}
                        color={classifyResult.classification === "true_positive" ? "#22c55e" : "#ef4444"}
                      />
                    ) : null}
                      <Badge text={classifyResult.real_severity as string} color={SEV_COLORS[(classifyResult.real_severity as string) || "info"]} />
                      {classifyResult.worth_reporting ? (
                        <Badge text="REPORTAR" color="#8b5cf6" />
                      ) : null}
                    </div>
                    <div className="flex items-center gap-4">
                      <div>
                        <span className="text-[10px] text-[var(--muted)] uppercase">Confiança</span>
                        <div className="text-lg font-black text-purple-400">{((classifyResult.confidence as number) * 100).toFixed(0)}%</div>
                      </div>
                      {classifyResult.suggested_title ? (
                        <div className="flex-1">
                          <span className="text-[10px] text-[var(--muted)] uppercase">Título Sugerido</span>
                          <div className="text-xs text-[var(--foreground)] font-medium">{classifyResult.suggested_title as string}</div>
                        </div>
                      ) : null}
                    </div>
                    <div>
                      <span className="text-[10px] text-[var(--muted)] uppercase">Reasoning</span>
                      <div className="text-xs text-[var(--foreground)] leading-relaxed mt-1 whitespace-pre-wrap">{classifyResult.reasoning as string}</div>
                    </div>
                  </div>
                )}
              </div>
            </Card>
          )}

          {/* ═══════ TAB: ANALYZE RESPONSE ═══════ */}
          {activeTab === "analyze" && (
            <Card title="Analisar HTTP Response" icon={<span className="text-base">🔍</span>}>
              <div className="space-y-3">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="sm:col-span-2">
                    <label className="block text-[10px] uppercase tracking-wider font-bold text-[var(--muted)] mb-1">URL</label>
                    <input
                      value={analyzeUrl}
                      onChange={e => setAnalyzeUrl(e.target.value)}
                      className="w-full rounded-lg bg-[var(--background)] border border-[var(--border)] text-xs text-[var(--foreground)] px-3 py-2 font-mono focus:outline-none focus:border-cyan-500/50"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] uppercase tracking-wider font-bold text-[var(--muted)] mb-1">Status</label>
                    <input
                      value={analyzeStatus}
                      onChange={e => setAnalyzeStatus(e.target.value)}
                      className="w-full rounded-lg bg-[var(--background)] border border-[var(--border)] text-xs text-[var(--foreground)] px-3 py-2 font-mono focus:outline-none focus:border-cyan-500/50"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-[10px] uppercase tracking-wider font-bold text-[var(--muted)] mb-1">Headers (JSON)</label>
                  <textarea
                    value={analyzeHeaders}
                    onChange={e => setAnalyzeHeaders(e.target.value)}
                    rows={3}
                    className="w-full rounded-xl bg-[var(--background)] border border-[var(--border)] text-xs text-[var(--foreground)] p-3 font-mono focus:outline-none focus:border-cyan-500/50 resize-none"
                  />
                </div>
                <div>
                  <label className="block text-[10px] uppercase tracking-wider font-bold text-[var(--muted)] mb-1">Response Body</label>
                  <textarea
                    value={analyzeBody}
                    onChange={e => setAnalyzeBody(e.target.value)}
                    rows={5}
                    className="w-full rounded-xl bg-[var(--background)] border border-[var(--border)] text-xs text-[var(--foreground)] p-3 font-mono focus:outline-none focus:border-cyan-500/50 resize-none"
                  />
                </div>
                <button
                  onClick={handleAnalyze}
                  disabled={analyzeLoading || !stats?.enabled}
                  className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-xs font-bold transition-all flex items-center gap-2"
                >
                  {analyzeLoading ? (
                    <svg className="animate-spin w-3.5 h-3.5" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  ) : (
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
                    </svg>
                  )}
                  Analisar Response
                </button>

                {analyzeResult?.findings && analyzeResult.findings.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-[10px] uppercase tracking-wider font-bold text-[var(--muted)]">
                      {analyzeResult.findings.length} Findings Identificados
                    </div>
                    {analyzeResult.findings.map((f: any, i: number) => (
                      <div key={i} className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-3">
                        <div className="flex items-center gap-2 mb-1">
                          <Badge text={f.severity || "info"} color={SEV_COLORS[f.severity] || SEV_COLORS.info} />
                          <span className="text-xs font-bold text-[var(--foreground)]">{f.title || f.code || "Finding"}</span>
                        </div>
                        {f.description && <div className="text-[10px] text-[var(--muted)] leading-relaxed">{f.description}</div>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </Card>
          )}

          {/* ═══════ TAB: SCOPE PARSER ═══════ */}
          {activeTab === "scope" && (
            <Card title="Parser de Scope" icon={<span className="text-base">📋</span>}>
              <div className="space-y-3">
                <div>
                  <label className="block text-[10px] uppercase tracking-wider font-bold text-[var(--muted)] mb-1">
                    Descrição do Programa
                  </label>
                  <textarea
                    value={scopeText}
                    onChange={e => setScopeText(e.target.value)}
                    rows={6}
                    placeholder="Cole aqui a descrição do programa de bug bounty, incluindo scope, regras, etc..."
                    className="w-full rounded-xl bg-[var(--background)] border border-[var(--border)] text-xs text-[var(--foreground)] p-3 font-mono focus:outline-none focus:border-amber-500/50 resize-none"
                  />
                </div>
                <div>
                  <label className="block text-[10px] uppercase tracking-wider font-bold text-[var(--muted)] mb-1">
                    Policy (opcional)
                  </label>
                  <textarea
                    value={scopePolicy}
                    onChange={e => setScopePolicy(e.target.value)}
                    rows={3}
                    placeholder="Texto adicional de política/regras..."
                    className="w-full rounded-xl bg-[var(--background)] border border-[var(--border)] text-xs text-[var(--foreground)] p-3 font-mono focus:outline-none focus:border-amber-500/50 resize-none"
                  />
                </div>
                <button
                  onClick={handleParseScope}
                  disabled={scopeLoading || !stats?.enabled || !scopeText.trim()}
                  className="px-4 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-xs font-bold transition-all flex items-center gap-2"
                >
                  {scopeLoading ? (
                    <svg className="animate-spin w-3.5 h-3.5" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  ) : "📋"}
                  Parsear Scope
                </button>

                {scopeResult && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {scopeResult.in_scope?.length > 0 && (
                      <div className="rounded-xl bg-emerald-500/5 border border-emerald-500/20 p-3">
                        <div className="text-[10px] uppercase font-bold text-emerald-400 mb-2">In Scope ({scopeResult.in_scope.length})</div>
                        <ul className="space-y-1">
                          {scopeResult.in_scope.map((s: string, i: number) => (
                            <li key={i} className="text-[10px] text-[var(--foreground)] font-mono flex items-center gap-1">
                              <span className="text-emerald-400">✓</span> {s}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {scopeResult.out_of_scope?.length > 0 && (
                      <div className="rounded-xl bg-red-500/5 border border-red-500/20 p-3">
                        <div className="text-[10px] uppercase font-bold text-red-400 mb-2">Out of Scope ({scopeResult.out_of_scope.length})</div>
                        <ul className="space-y-1">
                          {scopeResult.out_of_scope.map((s: string, i: number) => (
                            <li key={i} className="text-[10px] text-[var(--foreground)] font-mono flex items-center gap-1">
                              <span className="text-red-400">✗</span> {s}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {scopeResult.priority_vulns?.length > 0 && (
                      <div className="rounded-xl bg-purple-500/5 border border-purple-500/20 p-3">
                        <div className="text-[10px] uppercase font-bold text-purple-400 mb-2">Priority Vulns</div>
                        <ul className="space-y-1">
                          {scopeResult.priority_vulns.map((v: string, i: number) => (
                            <li key={i} className="text-[10px] text-[var(--foreground)]">• {v}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {scopeResult.bounty_range && (
                      <div className="rounded-xl bg-amber-500/5 border border-amber-500/20 p-3">
                        <div className="text-[10px] uppercase font-bold text-amber-400 mb-2">Bounty Range</div>
                        <div className="text-lg font-black text-amber-400">
                          ${scopeResult.bounty_range.min} – ${scopeResult.bounty_range.max}
                        </div>
                        <div className="text-[10px] text-[var(--muted)]">{scopeResult.bounty_range.currency}</div>
                        {scopeResult.tips?.length > 0 && (
                          <div className="mt-2 space-y-1">
                            {scopeResult.tips.map((t: string, i: number) => (
                              <div key={i} className="text-[10px] text-[var(--muted)]">💡 {t}</div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </Card>
          )}

          {/* ═══════ TAB: JS ANALYZER ═══════ */}
          {activeTab === "js" && (
            <Card title="Análise de JavaScript" icon={<span className="text-base">⚡</span>}>
              <div className="space-y-3">
                <div>
                  <label className="block text-[10px] uppercase tracking-wider font-bold text-[var(--muted)] mb-1">
                    Source URL (opcional)
                  </label>
                  <input
                    value={jsUrl}
                    onChange={e => setJsUrl(e.target.value)}
                    placeholder="https://example.com/static/app.js"
                    className="w-full rounded-lg bg-[var(--background)] border border-[var(--border)] text-xs text-[var(--foreground)] px-3 py-2 font-mono focus:outline-none focus:border-emerald-500/50"
                  />
                </div>
                <div>
                  <label className="block text-[10px] uppercase tracking-wider font-bold text-[var(--muted)] mb-1">
                    JavaScript Code
                  </label>
                  <textarea
                    value={jsCode}
                    onChange={e => setJsCode(e.target.value)}
                    rows={10}
                    placeholder="Cole aqui o código JavaScript para análise..."
                    className="w-full rounded-xl bg-[var(--background)] border border-[var(--border)] text-xs text-[var(--foreground)] p-3 font-mono focus:outline-none focus:border-emerald-500/50 resize-none"
                  />
                </div>
                <button
                  onClick={handleAnalyzeJS}
                  disabled={jsLoading || !stats?.enabled || !jsCode.trim()}
                  className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-xs font-bold transition-all flex items-center gap-2"
                >
                  {jsLoading ? (
                    <svg className="animate-spin w-3.5 h-3.5" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  ) : "⚡"}
                  Analisar JS
                </button>

                {jsResult?.findings && jsResult.findings.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-[10px] uppercase tracking-wider font-bold text-[var(--muted)]">
                      {jsResult.findings.length} Findings
                    </div>
                    {jsResult.findings.map((f: any, i: number) => (
                      <div key={i} className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-3">
                        <div className="flex items-center gap-2 mb-1">
                          <Badge text={f.severity || "info"} color={SEV_COLORS[f.severity] || SEV_COLORS.info} />
                          <span className="text-xs font-bold text-[var(--foreground)]">{f.title || f.type || "Secret Found"}</span>
                        </div>
                        {f.description && <div className="text-[10px] text-[var(--muted)] leading-relaxed">{f.description}</div>}
                        {f.line && <div className="text-[10px] text-purple-400 font-mono mt-1">Linha {f.line}</div>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </Card>
          )}

          {/* ═══════ TAB: PROGRAMS AI ═══════ */}
          {activeTab === "programs" && (
            <>
              <Card title="Programas — Análise AI" icon={<span className="text-base">🏢</span>}>
                {programs.length === 0 ? (
                  <div className="text-center py-8 text-[var(--muted)] text-xs">Nenhum programa encontrado</div>
                ) : (
                  <div className="space-y-2 max-h-72 overflow-y-auto hide-scrollbar">
                    {programs.slice(0, 30).map(p => (
                      <div
                        key={p.id}
                        className={`rounded-xl border p-3 flex items-center justify-between cursor-pointer transition-all hover:bg-white/[0.02] ${
                          selectedProgram === p.id ? "border-purple-500/40 bg-purple-500/5" : "border-[var(--border)]"
                        }`}
                        onClick={() => handleProgramAnalysis(p.id)}
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          <div className="w-6 h-6 rounded-lg bg-purple-500/10 flex items-center justify-center text-[10px]">🏢</div>
                          <div className="min-w-0">
                            <div className="text-xs font-bold text-[var(--foreground)] truncate">{p.name}</div>
                            <div className="text-[10px] text-[var(--muted)]">{p.platform} • {p.target_count || 0} targets</div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={e => { e.stopPropagation(); handleTriggerAI(p.id); }}
                            disabled={triggerLoading || !stats?.enabled}
                            className="px-2 py-1 rounded-lg bg-purple-600/80 hover:bg-purple-500 disabled:opacity-30 text-white text-[10px] font-bold transition-all"
                            title="Disparar análise AI"
                          >
                            🧠 Analisar
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </Card>

              {/* Program Analysis Result */}
              {programLoading && (
                <div className="text-center py-8 text-[var(--muted)] text-xs flex items-center justify-center gap-2">
                  <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Carregando análise...
                </div>
              )}

              {programAnalysis && !programLoading && (
                <Card title={`Análise: ${programAnalysis.program_name}`} icon={<span className="text-base">📊</span>}>
                  <div className="space-y-4">
                    {/* AI Report */}
                    {programAnalysis.ai_report ? (
                      <div className="space-y-3">
                        <div className="flex items-center gap-2">
                          <Badge text={programAnalysis.ai_report.overall_risk} color={SEV_COLORS[programAnalysis.ai_report.overall_risk] || "#6b7280"} />
                          <span className="text-xs text-[var(--muted)]">
                            {programAnalysis.ai_report.total_targets} targets • {programAnalysis.ai_report.total_findings} findings
                          </span>
                        </div>

                        <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-3">
                          <div className="text-[10px] uppercase font-bold text-[var(--muted)] mb-1">Sumário Executivo</div>
                          <div className="text-xs text-[var(--foreground)] leading-relaxed whitespace-pre-wrap">
                            {programAnalysis.ai_report.executive_summary}
                          </div>
                        </div>

                        {programAnalysis.ai_report.top_attack_strategies?.length > 0 && (
                          <div>
                            <div className="text-[10px] uppercase font-bold text-[var(--muted)] mb-2">Estratégias de Ataque</div>
                            <div className="space-y-1">
                              {programAnalysis.ai_report.top_attack_strategies.map((s, i) => (
                                <div key={i} className="text-[10px] text-[var(--foreground)] flex items-start gap-1.5">
                                  <span className="text-purple-400 mt-0.5">▸</span> {s}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {programAnalysis.ai_report.recommended_next_steps?.length > 0 && (
                          <div>
                            <div className="text-[10px] uppercase font-bold text-[var(--muted)] mb-2">Próximos Passos</div>
                            <div className="space-y-1">
                              {programAnalysis.ai_report.recommended_next_steps.map((s, i) => (
                                <div key={i} className="text-[10px] text-[var(--foreground)] flex items-start gap-1.5">
                                  <span className="text-cyan-400 mt-0.5">{i + 1}.</span> {s}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="text-center py-4 text-[var(--muted)] text-xs">
                        Nenhum relatório AI gerado ainda. Clique em &quot;🧠 Analisar&quot; para iniciar.
                      </div>
                    )}

                    {/* Prioritized Targets */}
                    {programAnalysis.prioritized_targets?.length > 0 && (
                      <div>
                        <div className="text-[10px] uppercase font-bold text-[var(--muted)] mb-2">
                          Targets Priorizados ({programAnalysis.prioritized_targets.length})
                        </div>
                        <div className="space-y-2 max-h-64 overflow-y-auto hide-scrollbar">
                          {programAnalysis.prioritized_targets.map((t, i) => (
                            <div key={i} className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-3 flex items-center gap-3">
                              <div className="w-8 h-8 rounded-lg bg-purple-500/10 flex items-center justify-center text-xs font-black text-purple-400">
                                #{t.rank || "?"}
                              </div>
                              <div className="flex-1 min-w-0">
                                <div className="text-xs font-bold text-[var(--foreground)] truncate">{t.domain}</div>
                                <div className="text-[10px] text-[var(--muted)]">
                                  {t.attack_angle || "—"} • Risk: {t.risk_score} • {t.finding_count} findings • {t.chain_count} chains
                                </div>
                                {t.reasoning && (
                                  <div className="text-[10px] text-purple-300/70 mt-0.5 truncate">{t.reasoning}</div>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </Card>
              )}
            </>
          )}
        </div>

        {/* Console — 4 cols */}
        <div className="lg:col-span-4 flex flex-col min-h-0">
          <div className="rounded-2xl border border-[var(--border)] bg-[#0a0e14] flex flex-col flex-1 min-h-0 overflow-hidden">
            {/* Console header */}
            <div className="shrink-0 flex items-center gap-2 px-4 py-2.5 border-b border-[var(--border)] bg-[#0d1117]">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
                <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/80" />
                <span className="w-2.5 h-2.5 rounded-full bg-green-500/80" />
              </div>
              <span className="text-[10px] text-[var(--muted)] font-mono ml-2">ai-console</span>
              <div className="flex-1" />
              <button
                onClick={() => setConsoleLogs([])}
                className="text-[10px] text-[var(--muted)] hover:text-[var(--foreground)] transition-colors"
              >
                clear
              </button>
            </div>

            {/* Console body */}
            <div ref={consoleRef} className="flex-1 overflow-y-auto hide-scrollbar p-3 space-y-0.5 font-mono text-[11px]">
              {consoleLogs.length === 0 ? (
                <div className="text-[var(--muted)] opacity-50">
                  <div>$ buggenie ai --interactive</div>
                  <div className="mt-1">BugGenie AI Console v1.0</div>
                  <div>Aguardando comandos...</div>
                  <div className="mt-2 animate-pulse">▊</div>
                </div>
              ) : (
                consoleLogs.map((log, i) => (
                  <div key={i} className="flex gap-2">
                    <span className="text-[var(--muted)] shrink-0">[{log.ts}]</span>
                    <span className={
                      log.type === "ok" ? "text-emerald-400" :
                      log.type === "err" ? "text-red-400" :
                      log.type === "warn" ? "text-amber-400" :
                      "text-[var(--foreground)]"
                    }>
                      {log.type === "ok" ? "✓" : log.type === "err" ? "✗" : log.type === "warn" ? "⚠" : "→"} {log.msg}
                    </span>
                  </div>
                ))
              )}
            </div>

            {/* Quick stats footer */}
            {stats && (
              <div className="shrink-0 px-4 py-2 border-t border-[var(--border)] bg-[#0d1117] flex items-center justify-between text-[9px] text-[var(--muted)] font-mono">
                <span>{stats.provider}:{stats.model}</span>
                <span>req:{stats.requests} err:{stats.errors} tok:{stats.tokens_used}</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
