"use client";

import { useState, useCallback, useEffect, useMemo } from "react";
import { RefreshBadge } from "@/components/RefreshBadge";
import {
  fetchBugHuntStatus,
  testBugHuntConnection,
  triggerBugHuntScrape,
  fetchBugHuntPrograms,
  bughuntAnalyzeScope,
  bughuntSuggestVulns,
  bughuntGenerateReport,
  type BugHuntStatus,
  type BugHuntProgram,
  type BugHuntTestResult,
  type BugHuntScrapeResult,
  type BugHuntScopeAnalysis,
  type BugHuntVulnSuggestions,
  type BugHuntReport,
} from "@/lib/api";

/* ═══════════════════════════════════════════════════════════════
   BugHunt Dashboard — plataforma brasileira de bug bounty
   ═══════════════════════════════════════════════════════════════ */

function formatDate(iso: string | null) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("pt-BR", {
    day: "2-digit", month: "2-digit", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function formatBounty(v: number) {
  if (!v) return "—";
  return `R$ ${v.toLocaleString("pt-BR", { minimumFractionDigits: 0 })}`;
}

/* ── Status badge ─────────────────────────────────────────── */
function StatusBadge({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold ${
      ok ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/25"
         : "bg-red-500/15 text-red-400 border border-red-500/25"
    }`}>
      <span className={`w-1.5 h-1.5 rounded-full ${ok ? "bg-emerald-400" : "bg-red-400"}`} />
      {label}
    </span>
  );
}

/* ── Card wrapper ─────────────────────────────────────────── */
function Card({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`rounded-xl border border-[var(--border)] bg-[var(--card)] p-5 ${className}`}>
      {children}
    </div>
  );
}

/* ── Stat box ─────────────────────────────────────────────── */
function Stat({ label, value, sub, color = "text-green-400" }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="flex flex-col">
      <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold mb-1">{label}</span>
      <span className={`text-2xl font-bold tabular-nums ${color}`}>{value}</span>
      {sub && <span className="text-[10px] text-[var(--muted)] mt-0.5">{sub}</span>}
    </div>
  );
}

export default function BugHuntPage() {
  const [status, setStatus] = useState<BugHuntStatus | null>(null);
  const [programs, setPrograms] = useState<BugHuntProgram[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [testResult, setTestResult] = useState<BugHuntTestResult | null>(null);
  const [scrapeResult, setScrapeResult] = useState<BugHuntScrapeResult | null>(null);
  const [testing, setTesting] = useState(false);
  const [scraping, setScraping] = useState(false);
  const [search, setSearch] = useState("");
  const [bountyOnly, setBountyOnly] = useState(false);
  const [activeTab, setActiveTab] = useState<"overview" | "programs" | "ai" | "reports" | "config">("overview");
  const [expandedProgram, setExpandedProgram] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState(0);

  /* ── Saved Reports state ──────────────────────────────── */
  type SavedReport = NonNullable<BugHuntReport["report"]> & { savedAt: string; id: string };
  const [savedReports, setSavedReports] = useState<SavedReport[]>(() => {
    if (typeof window === "undefined") return [];
    try {
      const raw = localStorage.getItem("bughunt_saved_reports");
      return raw ? JSON.parse(raw) : [];
    } catch { return []; }
  });
  const [expandedReport, setExpandedReport] = useState<string | null>(null);
  const [reportSearch, setReportSearch] = useState("");
  const [reportSevFilter, setReportSevFilter] = useState<string>("");

  const persistReports = (reports: SavedReport[]) => {
    setSavedReports(reports);
    try { localStorage.setItem("bughunt_saved_reports", JSON.stringify(reports)); } catch {}
  };

  const saveCurrentReport = () => {
    if (!reportData) return;
    const newReport: SavedReport = {
      ...reportData,
      id: `rpt_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      savedAt: new Date().toISOString(),
    };
    persistReports([newReport, ...savedReports]);
  };

  const deleteReport = (id: string) => {
    persistReports(savedReports.filter(r => r.id !== id));
    if (expandedReport === id) setExpandedReport(null);
  };

  const buildReportMarkdown = (r: SavedReport) => {
    const lines: string[] = [];
    lines.push(`# ${r.titulo}\n`);
    lines.push(`**Severidade:** ${r.severidade}`);
    if (r.cvss_score) lines.push(`**CVSS:** ${r.cvss_score} (${r.cvss_vector || ""})`);
    if (r.cwe) lines.push(`**CWE:** ${r.cwe}`);
    if (r.owasp_category) lines.push(`**OWASP:** ${r.owasp_category}`);
    lines.push("");
    lines.push(`## Resumo Executivo\n\n${r.resumo_executivo}\n`);
    if (r.passos_reproducao?.length) {
      lines.push(`## Passos para Reprodução\n`);
      r.passos_reproducao.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
      lines.push("");
    }
    if (r.poc) lines.push(`## Proof of Concept\n\n${r.poc}\n`);
    if (r.impacto) lines.push(`## Impacto\n\n${r.impacto}\n`);
    if (r.remediacao?.length) {
      lines.push(`## Remediação\n`);
      r.remediacao.forEach(rem => lines.push(`- ${rem}`));
      lines.push("");
    }
    if (r.referencias?.length) {
      lines.push(`## Referências\n`);
      r.referencias.forEach(ref => lines.push(`- ${ref}`));
    }
    return lines.join("\n");
  };

  const buildPlainTextReport = (r: SavedReport) => {
    const lines: string[] = [];
    lines.push(`TÍTULO: ${r.titulo}`);
    lines.push(`SEVERIDADE: ${r.severidade}`);
    if (r.cvss_score) lines.push(`CVSS: ${r.cvss_score} (${r.cvss_vector || ""})`);
    if (r.cwe) lines.push(`CWE: ${r.cwe}`);
    if (r.owasp_category) lines.push(`OWASP: ${r.owasp_category}`);
    lines.push("");
    lines.push(`--- RESUMO EXECUTIVO ---\n${r.resumo_executivo}`);
    lines.push("");
    if (r.passos_reproducao?.length) {
      lines.push(`--- PASSOS PARA REPRODUÇÃO ---`);
      r.passos_reproducao.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
      lines.push("");
    }
    if (r.poc) lines.push(`--- PROOF OF CONCEPT ---\n${r.poc}\n`);
    if (r.impacto) lines.push(`--- IMPACTO ---\n${r.impacto}\n`);
    if (r.remediacao?.length) {
      lines.push(`--- REMEDIAÇÃO ---`);
      r.remediacao.forEach(rem => lines.push(`• ${rem}`));
      lines.push("");
    }
    if (r.referencias?.length) {
      lines.push(`--- REFERÊNCIAS ---`);
      r.referencias.forEach(ref => lines.push(`• ${ref}`));
    }
    return lines.join("\n");
  };

  const filteredReports = useMemo(() => {
    let list = savedReports;
    if (reportSevFilter) {
      list = list.filter(r => r.severidade?.toLowerCase().includes(reportSevFilter.toLowerCase()));
    }
    if (reportSearch.trim()) {
      const s = reportSearch.toLowerCase();
      list = list.filter(r =>
        r.titulo?.toLowerCase().includes(s) ||
        r.programa?.toLowerCase().includes(s) ||
        r.tipo_vulnerabilidade?.toLowerCase().includes(s) ||
        r.resumo_executivo?.toLowerCase().includes(s)
      );
    }
    return list;
  }, [savedReports, reportSevFilter, reportSearch]);

  /* ── AI Report state ──────────────────────────────────── */
  const [aiSelectedProgram, setAiSelectedProgram] = useState<string>("");
  const [aiLoading, setAiLoading] = useState<string | null>(null); // "scope" | "vulns" | "report"
  const [scopeAnalysis, setScopeAnalysis] = useState<BugHuntScopeAnalysis["analysis"] | null>(null);
  const [vulnSuggestions, setVulnSuggestions] = useState<BugHuntVulnSuggestions["suggestions"] | null>(null);
  const [reportData, setReportData] = useState<BugHuntReport["report"] | null>(null);
  const [vulnType, setVulnType] = useState("");
  const [vulnDetails, setVulnDetails] = useState("");
  const [aiError, setAiError] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  /* ── Load status + programs ───────────────────────────── */
  const loadAll = useCallback(async () => {
    try {
      const [s, p] = await Promise.all([
        fetchBugHuntStatus(),
        fetchBugHuntPrograms({ limit: 200 }),
      ]);
      setStatus(s);
      setPrograms(p.programs || []);
      setTotalCount(p.count || 0);
      setLastUpdated(Date.now());
    } catch (e) {
      console.error("[BugHunt] load error:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAll();
    const id = setInterval(loadAll, 30000);
    return () => clearInterval(id);
  }, [loadAll]);

  /* ── Test connection ──────────────────────────────────── */
  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await testBugHuntConnection();
      setTestResult(res);
    } catch (e: any) {
      setTestResult({ ok: false, error: e.message || "Erro de rede" });
    }
    setTesting(false);
  };

  /* ── Scrape ───────────────────────────────────────────── */
  const handleScrape = async () => {
    setScraping(true);
    setScrapeResult(null);
    try {
      const res = await triggerBugHuntScrape();
      setScrapeResult(res);
      if (res.programs?.length) {
        setPrograms(res.programs);
        setTotalCount(res.programs.length);
      }
      await loadAll();
    } catch (e: any) {
      setScrapeResult({ ok: false, fetched: 0, new: 0, error: e.message, programs: [] });
    }
    setScraping(false);
  };

  /* ── Filter programs ──────────────────────────────────── */
  const filtered = useMemo(() => {
    let list = programs;
    if (bountyOnly) list = list.filter(p => p.max_bounty > 0);
    if (search.trim()) {
      const s = search.toLowerCase();
      list = list.filter(p =>
        p.name.toLowerCase().includes(s) ||
        p.program_id.toLowerCase().includes(s) ||
        p.scope.some(sc => sc.toLowerCase().includes(s))
      );
    }
    return list;
  }, [programs, bountyOnly, search]);

  /* ── Stats ────────────────────────────────────────────── */
  const bountyPrograms = programs.filter(p => p.max_bounty > 0);
  const maxBountyProg = bountyPrograms.length
    ? bountyPrograms.reduce((a, b) => a.max_bounty > b.max_bounty ? a : b)
    : null;
  const totalScope = programs.reduce((acc, p) => acc + p.scope.length, 0);

  /* ── AI handlers ──────────────────────────────────────── */
  const handleAnalyzeScope = async () => {
    if (!aiSelectedProgram) return;
    setAiLoading("scope");
    setAiError(null);
    setScopeAnalysis(null);
    try {
      const res = await bughuntAnalyzeScope(aiSelectedProgram);
      if (res.ok && res.analysis) {
        setScopeAnalysis(res.analysis);
      } else {
        setAiError(res.error || "Erro ao analisar escopo");
      }
    } catch (e: any) {
      setAiError(e.message || "Erro de rede");
    }
    setAiLoading(null);
  };

  const handleSuggestVulns = async () => {
    if (!aiSelectedProgram) return;
    setAiLoading("vulns");
    setAiError(null);
    setVulnSuggestions(null);
    try {
      const res = await bughuntSuggestVulns(aiSelectedProgram);
      if (res.ok && res.suggestions) {
        setVulnSuggestions(res.suggestions);
      } else {
        setAiError(res.error || "Erro ao sugerir vulnerabilidades");
      }
    } catch (e: any) {
      setAiError(e.message || "Erro de rede");
    }
    setAiLoading(null);
  };

  const handleGenerateReport = async () => {
    if (!aiSelectedProgram || !vulnType) return;
    setAiLoading("report");
    setAiError(null);
    setReportData(null);
    try {
      const res = await bughuntGenerateReport(aiSelectedProgram, vulnType, vulnDetails);
      if (res.ok && res.report) {
        setReportData(res.report);
      } else {
        setAiError(res.error || "Erro ao gerar relatório");
      }
    } catch (e: any) {
      setAiError(e.message || "Erro de rede");
    }
    setAiLoading(null);
  };

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 2000);
    });
  };

  const buildFullReportMarkdown = () => {
    if (!reportData) return "";
    const lines: string[] = [];
    lines.push(`# ${reportData.titulo}\n`);
    lines.push(`**Severidade:** ${reportData.severidade}`);
    if (reportData.cvss_score) lines.push(`**CVSS:** ${reportData.cvss_score} (${reportData.cvss_vector || ""})`);
    if (reportData.cwe) lines.push(`**CWE:** ${reportData.cwe}`);
    if (reportData.owasp_category) lines.push(`**OWASP:** ${reportData.owasp_category}`);
    lines.push("");
    lines.push(`## Resumo Executivo\n\n${reportData.resumo_executivo}\n`);
    if (reportData.passos_reproducao?.length) {
      lines.push(`## Passos para Reprodução\n`);
      reportData.passos_reproducao.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
      lines.push("");
    }
    if (reportData.poc) {
      lines.push(`## Proof of Concept\n\n${reportData.poc}\n`);
    }
    if (reportData.impacto) {
      lines.push(`## Impacto\n\n${reportData.impacto}\n`);
    }
    if (reportData.remediacao?.length) {
      lines.push(`## Remediação\n`);
      reportData.remediacao.forEach(r => lines.push(`- ${r}`));
      lines.push("");
    }
    if (reportData.referencias?.length) {
      lines.push(`## Referências\n`);
      reportData.referencias.forEach(r => lines.push(`- ${r}`));
    }
    return lines.join("\n");
  };

  const tabs = [
    { id: "overview" as const, label: "Visão Geral", icon: "📊" },
    { id: "programs" as const, label: "Programas", icon: "🎯" },
    { id: "ai" as const, label: "AI Reports", icon: "🤖" },
    { id: "reports" as const, label: `Relatórios (${savedReports.length})`, icon: "📋" },
    { id: "config" as const, label: "Configuração", icon: "⚙️" },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-green-500/30 border-t-green-400 rounded-full animate-spin" />
          <span className="text-sm text-[var(--muted)]">Carregando BugHunt...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* ── Header ───────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-green-500/15 border border-green-500/25">
            <span className="text-lg">🇧🇷</span>
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight flex items-center gap-2">
              BugHunt
              <RefreshBadge intervalSec={30} lastUpdated={lastUpdated} />
            </h1>
            <p className="text-xs text-[var(--muted)]">Plataforma brasileira de bug bounty</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <StatusBadge
            ok={status?.configured ?? false}
            label={status?.configured ? "Configurado" : "Não configurado"}
          />
          {status?.programs_cached ? (
            <StatusBadge ok={true} label={`${status.programs_cached} programas`} />
          ) : null}
        </div>
      </div>

      {/* ── Tab bar ──────────────────────────────────────── */}
      <div className="flex gap-1 bg-[var(--card)] rounded-lg p-1 border border-[var(--border)] w-fit">
        {tabs.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-md text-xs font-medium transition-all ${
              activeTab === t.id
                ? "bg-green-500/15 text-green-400 shadow-sm"
                : "text-[var(--muted)] hover:text-[var(--foreground)] hover:bg-white/[0.03]"
            }`}>
            <span>{t.icon}</span>
            {t.label}
          </button>
        ))}
      </div>

      {/* ═══ OVERVIEW TAB ═══════════════════════════════════ */}
      {activeTab === "overview" && (
        <div className="space-y-4">
          {/* Stats row */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
            <Card>
              <Stat label="Programas" value={totalCount} color="text-green-400" />
            </Card>
            <Card>
              <Stat label="Com Bounty" value={bountyPrograms.length} color="text-amber-400" />
            </Card>
            <Card>
              <Stat label="Alvos no Scope" value={totalScope} color="text-cyan-400" />
            </Card>
            <Card>
              <Stat
                label="Maior Bounty"
                value={maxBountyProg ? formatBounty(maxBountyProg.max_bounty) : "—"}
                sub={maxBountyProg?.name?.slice(0, 30)}
                color="text-emerald-400"
              />
            </Card>
            <Card>
              <Stat
                label="Último Check"
                value={status?.last_check ? formatDate(status.last_check) : "Nunca"}
                color="text-[var(--foreground)]"
              />
            </Card>
          </div>

          {/* Actions */}
          <div className="grid grid-cols-2 gap-4">
            {/* Test Connection */}
            <Card>
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold">🔌 Testar Conexão</h3>
                <button onClick={handleTest} disabled={testing}
                  className="px-3 py-1.5 rounded-lg text-xs font-medium bg-blue-500/15 text-blue-400 border border-blue-500/25 hover:bg-blue-500/25 transition-colors disabled:opacity-50">
                  {testing ? "Testando..." : "Testar"}
                </button>
              </div>
              <p className="text-[11px] text-[var(--muted)] mb-3">
                Tenta fazer login na BugHunt e verificar acesso à API.
              </p>
              {testResult && (
                <div className={`p-3 rounded-lg text-xs ${
                  testResult.ok
                    ? "bg-emerald-500/10 border border-emerald-500/20 text-emerald-400"
                    : "bg-red-500/10 border border-red-500/20 text-red-400"
                }`}>
                  {testResult.ok ? (
                    <div className="flex items-center gap-2">
                      <span>✅</span>
                      <span>{testResult.message}</span>
                    </div>
                  ) : (
                    <div className="flex items-center gap-2">
                      <span>❌</span>
                      <span>{testResult.error}</span>
                    </div>
                  )}
                </div>
              )}
            </Card>

            {/* Scrape */}
            <Card>
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold">🔄 Buscar Programas</h3>
                <button onClick={handleScrape} disabled={scraping || !status?.configured}
                  className="px-3 py-1.5 rounded-lg text-xs font-medium bg-green-500/15 text-green-400 border border-green-500/25 hover:bg-green-500/25 transition-colors disabled:opacity-50">
                  {scraping ? "Buscando..." : "Scrape"}
                </button>
              </div>
              <p className="text-[11px] text-[var(--muted)] mb-3">
                Login + buscar todos os programas disponíveis na BugHunt.
              </p>
              {scrapeResult && (
                <div className={`p-3 rounded-lg text-xs ${
                  scrapeResult.ok
                    ? "bg-emerald-500/10 border border-emerald-500/20 text-emerald-400"
                    : "bg-red-500/10 border border-red-500/20 text-red-400"
                }`}>
                  {scrapeResult.ok ? (
                    <span>✅ {scrapeResult.fetched} programas encontrados, {scrapeResult.new} novos</span>
                  ) : (
                    <span>❌ {scrapeResult.error || "Erro ao buscar"}</span>
                  )}
                </div>
              )}
            </Card>
          </div>

          {/* Top bounty programs */}
          {bountyPrograms.length > 0 && (
            <Card>
              <h3 className="text-sm font-semibold mb-3">💰 Top Bounties</h3>
              <div className="space-y-2">
                {[...bountyPrograms]
                  .sort((a, b) => b.max_bounty - a.max_bounty)
                  .slice(0, 8)
                  .map((p, i) => (
                  <div key={p.program_id} className="flex items-center justify-between py-2 px-3 rounded-lg bg-[var(--background)]/50 hover:bg-[var(--background)] transition-colors">
                    <div className="flex items-center gap-3">
                      <span className="text-[10px] font-bold text-[var(--muted)] w-5 text-right">#{i + 1}</span>
                      <div>
                        <a href={p.url} target="_blank" rel="noopener noreferrer"
                          className="text-xs font-medium text-[var(--foreground)] hover:text-green-400 transition-colors">
                          {p.name}
                        </a>
                        {p.scope.length > 0 && (
                          <span className="ml-2 text-[10px] text-[var(--muted)]">{p.scope.length} alvos</span>
                        )}
                      </div>
                    </div>
                    <span className="text-sm font-bold text-amber-400 tabular-nums">
                      {formatBounty(p.max_bounty)}
                    </span>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
      )}

      {/* ═══ PROGRAMS TAB ═══════════════════════════════════ */}
      {activeTab === "programs" && (
        <div className="space-y-4">
          {/* Filters */}
          <Card className="!p-3">
            <div className="flex items-center gap-3">
              <div className="flex-1 relative">
                <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--muted)]" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
                </svg>
                <input
                  type="text"
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="Buscar por nome, ID ou scope..."
                  className="w-full pl-9 pr-3 py-2 rounded-lg text-xs bg-[var(--background)] border border-[var(--border)] text-[var(--foreground)] placeholder:text-[var(--muted)] focus:outline-none focus:border-green-500/50"
                />
              </div>
              <button onClick={() => setBountyOnly(!bountyOnly)}
                className={`px-3 py-2 rounded-lg text-xs font-medium border transition-colors ${
                  bountyOnly
                    ? "bg-amber-500/15 text-amber-400 border-amber-500/25"
                    : "bg-[var(--background)] text-[var(--muted)] border-[var(--border)] hover:text-[var(--foreground)]"
                }`}>
                💰 Só com bounty
              </button>
              <span className="text-xs text-[var(--muted)] tabular-nums">{filtered.length} de {totalCount}</span>
            </div>
          </Card>

          {/* Programs list */}
          {filtered.length === 0 ? (
            <Card className="text-center py-12">
              {!status?.configured ? (
                <div className="space-y-2">
                  <span className="text-3xl">🔐</span>
                  <p className="text-sm text-[var(--muted)]">Configure BUGHUNT_EMAIL e BUGHUNT_PASSWORD no .env</p>
                  <p className="text-[10px] text-[var(--muted)]">Opcional: CAPSOLVER_API_KEY para resolver reCAPTCHA automaticamente</p>
                </div>
              ) : programs.length === 0 ? (
                <div className="space-y-2">
                  <span className="text-3xl">📭</span>
                  <p className="text-sm text-[var(--muted)]">Nenhum programa encontrado</p>
                  <button onClick={handleScrape} disabled={scraping}
                    className="mt-2 px-4 py-2 rounded-lg text-xs font-medium bg-green-500/15 text-green-400 border border-green-500/25 hover:bg-green-500/25 transition-colors disabled:opacity-50">
                    {scraping ? "Buscando..." : "🔄 Buscar programas"}
                  </button>
                </div>
              ) : (
                <div className="space-y-2">
                  <span className="text-3xl">🔍</span>
                  <p className="text-sm text-[var(--muted)]">Nenhum programa com esse filtro</p>
                </div>
              )}
            </Card>
          ) : (
            <div className="space-y-2">
              {filtered.map(prog => {
                const expanded = expandedProgram === prog.program_id;
                return (
                  <Card key={prog.program_id} className="!p-0 overflow-hidden">
                    <button
                      onClick={() => setExpandedProgram(expanded ? null : prog.program_id)}
                      className="w-full flex items-center justify-between p-4 hover:bg-white/[0.02] transition-colors text-left"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-green-500/10 text-green-400 text-sm font-bold shrink-0">
                          {prog.name.charAt(0).toUpperCase()}
                        </div>
                        <div className="min-w-0">
                          <div className="text-sm font-medium text-[var(--foreground)] truncate">
                            {prog.name}
                          </div>
                          <div className="flex items-center gap-2 mt-0.5">
                            <span className="text-[10px] text-[var(--muted)]">ID: {prog.program_id}</span>
                            {prog.scope.length > 0 && (
                              <span className="text-[10px] text-cyan-400">{prog.scope.length} alvos</span>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 shrink-0">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          prog.max_bounty > 0
                            ? "bg-amber-500/15 text-amber-400"
                            : "bg-gray-500/15 text-gray-400"
                        }`}>
                          {prog.max_bounty > 0 ? formatBounty(prog.max_bounty) : "VDP"}
                        </span>
                        <svg className={`w-4 h-4 text-[var(--muted)] transition-transform ${expanded ? "rotate-180" : ""}`}
                          fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
                        </svg>
                      </div>
                    </button>

                    {expanded && (
                      <div className="border-t border-[var(--border)] p-4 bg-[var(--background)]/30 space-y-3">
                        {/* Scope */}
                        {prog.scope.length > 0 ? (
                          <div>
                            <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Scope</span>
                            <div className="flex flex-wrap gap-1.5 mt-1.5">
                              {prog.scope.map((s, i) => (
                                <span key={i} className="px-2 py-1 rounded-md text-[11px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono">
                                  {s}
                                </span>
                              ))}
                            </div>
                          </div>
                        ) : (
                          <p className="text-[11px] text-[var(--muted)]">Sem informação de scope disponível</p>
                        )}

                        {/* Link */}
                        <div className="flex items-center gap-2 pt-1">
                          <a href={prog.url} target="_blank" rel="noopener noreferrer"
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium bg-green-500/15 text-green-400 border border-green-500/25 hover:bg-green-500/25 transition-colors">
                            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
                            </svg>
                            Abrir na BugHunt
                          </a>
                        </div>
                      </div>
                    )}
                  </Card>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ═══ AI REPORTS TAB ═══════════════════════════════════ */}
      {activeTab === "ai" && (
        <div className="space-y-4">
          {/* Program selector + actions */}
          <Card>
            <h3 className="text-sm font-semibold mb-3">🤖 Gerador de Relatórios AI</h3>
            <p className="text-[11px] text-[var(--muted)] mb-4">
              Selecione um programa e use a IA para analisar o escopo, sugerir vulnerabilidades e gerar relatórios profissionais para submissão.
            </p>

            {/* Program selector */}
            <div className="mb-4">
              <label className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold mb-1.5 block">
                Programa
              </label>
              <select
                value={aiSelectedProgram}
                onChange={e => {
                  setAiSelectedProgram(e.target.value);
                  setScopeAnalysis(null);
                  setVulnSuggestions(null);
                  setReportData(null);
                  setAiError(null);
                }}
                className="w-full px-3 py-2 rounded-lg text-xs bg-[var(--background)] border border-[var(--border)] text-[var(--foreground)] focus:outline-none focus:border-green-500/50"
              >
                <option value="">Selecione um programa...</option>
                {programs.map(p => (
                  <option key={p.program_id} value={p.program_id}>
                    {p.name} ({p.scope.length} alvos){p.max_bounty > 0 ? ` — R$ ${p.max_bounty}` : " — VDP"}
                  </option>
                ))}
              </select>
            </div>

            {/* Action buttons */}
            {aiSelectedProgram && (
              <div className="flex flex-wrap gap-2">
                <button onClick={handleAnalyzeScope} disabled={!!aiLoading}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-medium bg-purple-500/15 text-purple-400 border border-purple-500/25 hover:bg-purple-500/25 transition-colors disabled:opacity-50">
                  {aiLoading === "scope" ? (
                    <><span className="w-3 h-3 border border-purple-400/30 border-t-purple-400 rounded-full animate-spin" /> Analisando...</>
                  ) : (
                    <>🔍 Analisar Escopo</>
                  )}
                </button>
                <button onClick={handleSuggestVulns} disabled={!!aiLoading}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-medium bg-amber-500/15 text-amber-400 border border-amber-500/25 hover:bg-amber-500/25 transition-colors disabled:opacity-50">
                  {aiLoading === "vulns" ? (
                    <><span className="w-3 h-3 border border-amber-400/30 border-t-amber-400 rounded-full animate-spin" /> Gerando...</>
                  ) : (
                    <>💡 Sugerir Vulnerabilidades</>
                  )}
                </button>
              </div>
            )}
          </Card>

          {/* Error display */}
          {aiError && (
            <Card className="!bg-red-500/5 !border-red-500/20">
              <div className="flex items-start gap-2">
                <span>❌</span>
                <div>
                  <p className="text-xs font-medium text-red-400">Erro na AI</p>
                  <p className="text-[11px] text-red-400/80 mt-1">{aiError}</p>
                </div>
              </div>
            </Card>
          )}

          {/* Scope Analysis Result */}
          {scopeAnalysis && (
            <Card>
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold">🔍 Análise de Escopo — {scopeAnalysis.programa}</h3>
                <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                  scopeAnalysis.risco_geral === "critico" ? "bg-red-500/15 text-red-400" :
                  scopeAnalysis.risco_geral === "alto" ? "bg-orange-500/15 text-orange-400" :
                  scopeAnalysis.risco_geral === "medio" ? "bg-amber-500/15 text-amber-400" :
                  "bg-green-500/15 text-green-400"
                }`}>
                  Risco: {scopeAnalysis.risco_geral?.toUpperCase()}
                </span>
              </div>

              <div className="space-y-4">
                {/* Overview stats */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="p-3 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                    <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Tipo</span>
                    <p className="text-xs font-medium text-[var(--foreground)] mt-1">{scopeAnalysis.tipo_aplicacao || "—"}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                    <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Alvos</span>
                    <p className="text-xs font-medium text-[var(--foreground)] mt-1">{scopeAnalysis.alvos_analisados}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                    <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Estimativa</span>
                    <p className="text-xs font-medium text-[var(--foreground)] mt-1">{scopeAnalysis.estimativa_horas || "—"}h</p>
                  </div>
                </div>

                {/* Surface */}
                {scopeAnalysis.superficie_ataque && (
                  <div>
                    <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Superfície de Ataque</span>
                    <p className="text-xs text-[var(--foreground)] mt-1.5 leading-relaxed whitespace-pre-wrap">{scopeAnalysis.superficie_ataque}</p>
                  </div>
                )}

                {/* Technologies */}
                {scopeAnalysis.tecnologias_provaveis?.length > 0 && (
                  <div>
                    <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Tecnologias Prováveis</span>
                    <div className="flex flex-wrap gap-1.5 mt-1.5">
                      {scopeAnalysis.tecnologias_provaveis.map((t, i) => (
                        <span key={i} className="px-2 py-1 rounded-md text-[11px] bg-blue-500/10 text-blue-400 border border-blue-500/20">{t}</span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Top 5 vulns */}
                {scopeAnalysis.top_5_vulnerabilidades?.length > 0 && (
                  <div>
                    <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Top 5 Vulnerabilidades Prováveis</span>
                    <div className="space-y-2 mt-1.5">
                      {scopeAnalysis.top_5_vulnerabilidades.map((v, i) => (
                        <div key={i} className="flex items-start gap-3 p-2.5 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                          <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold shrink-0 mt-0.5 ${
                            v.severidade?.toLowerCase() === "critica" || v.severidade?.toLowerCase() === "critical" ? "bg-red-500/15 text-red-400" :
                            v.severidade?.toLowerCase() === "alta" || v.severidade?.toLowerCase() === "high" ? "bg-orange-500/15 text-orange-400" :
                            v.severidade?.toLowerCase() === "media" || v.severidade?.toLowerCase() === "medium" ? "bg-amber-500/15 text-amber-400" :
                            "bg-green-500/15 text-green-400"
                          }`}>{v.severidade?.toUpperCase()}</span>
                          <div>
                            <span className="text-xs font-medium text-[var(--foreground)]">{v.nome}</span>
                            <p className="text-[11px] text-[var(--muted)] mt-0.5">{v.justificativa}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Tips */}
                {scopeAnalysis.dicas_recompensa?.length > 0 && (
                  <div>
                    <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">💰 Dicas para Maximizar Recompensa</span>
                    <ul className="mt-1.5 space-y-1">
                      {scopeAnalysis.dicas_recompensa.map((d, i) => (
                        <li key={i} className="text-xs text-[var(--foreground)] flex items-start gap-2">
                          <span className="text-green-400 mt-0.5">▸</span> {d}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </Card>
          )}

          {/* Vulnerability Suggestions Result */}
          {vulnSuggestions && (
            <Card>
              <h3 className="text-sm font-semibold mb-3">💡 Sugestões de Vulnerabilidades — {vulnSuggestions.programa}</h3>

              <div className="space-y-4">
                {/* Quick wins */}
                {vulnSuggestions.quick_wins?.length > 0 && (
                  <div>
                    <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">⚡ Quick Wins</span>
                    <div className="space-y-2 mt-1.5">
                      {vulnSuggestions.quick_wins.map((qw, i) => (
                        <div key={i} className="p-2.5 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-medium text-emerald-400">{qw.vulnerabilidade}</span>
                            <span className="text-[10px] text-[var(--muted)]">{qw.tempo_estimado}</span>
                          </div>
                          <p className="text-[11px] text-[var(--muted)] mt-1">📍 {qw.onde_testar}</p>
                          <p className="text-[11px] text-[var(--muted)]">🔧 {qw.ferramenta}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Common bugs */}
                {vulnSuggestions.bugs_comuns?.length > 0 && (
                  <div>
                    <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">🐛 Bugs Comuns</span>
                    <div className="space-y-2 mt-1.5">
                      {vulnSuggestions.bugs_comuns.map((b, i) => (
                        <div key={i} className="p-2.5 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                          <div className="flex items-center gap-2">
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                              b.severidade?.toLowerCase() === "critica" || b.severidade?.toLowerCase() === "critical" ? "bg-red-500/15 text-red-400" :
                              b.severidade?.toLowerCase() === "alta" || b.severidade?.toLowerCase() === "high" ? "bg-orange-500/15 text-orange-400" :
                              b.severidade?.toLowerCase() === "media" || b.severidade?.toLowerCase() === "medium" ? "bg-amber-500/15 text-amber-400" :
                              "bg-green-500/15 text-green-400"
                            }`}>{b.severidade?.toUpperCase()}</span>
                            <span className="text-xs font-medium text-[var(--foreground)]">{b.tipo}</span>
                          </div>
                          <p className="text-[11px] text-[var(--muted)] mt-1">{b.descricao}</p>
                          <p className="text-[11px] text-amber-400/80 mt-0.5">Impacto: {b.impacto}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Advanced chains */}
                {vulnSuggestions.cadeias_avancadas?.length > 0 && (
                  <div>
                    <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">🔗 Cadeias Avançadas</span>
                    <div className="space-y-2 mt-1.5">
                      {vulnSuggestions.cadeias_avancadas.map((c, i) => (
                        <div key={i} className="p-2.5 rounded-lg bg-[var(--background)] border border-purple-500/20">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-medium text-purple-400">{c.cadeia}</span>
                            <span className="text-[10px] font-bold text-red-400">{c.severidade_resultante?.toUpperCase()}</span>
                          </div>
                          <div className="mt-1.5 space-y-0.5">
                            {c.passos?.map((p, j) => (
                              <p key={j} className="text-[11px] text-[var(--muted)]">{j + 1}. {p}</p>
                            ))}
                          </div>
                          <p className="text-[11px] text-amber-400/80 mt-1">→ {c.impacto_final}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Checklist */}
                {vulnSuggestions.checklist?.length > 0 && (
                  <div>
                    <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">✅ Checklist</span>
                    <div className="grid grid-cols-2 gap-1.5 mt-1.5">
                      {vulnSuggestions.checklist.map((item, i) => (
                        <div key={i} className="flex items-start gap-2 text-[11px] text-[var(--foreground)] p-2 rounded bg-[var(--background)]">
                          <span className="text-[var(--muted)]">☐</span> {item}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Tools */}
                {vulnSuggestions.ferramentas_recomendadas?.length > 0 && (
                  <div>
                    <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">🔧 Ferramentas Recomendadas</span>
                    <div className="flex flex-wrap gap-2 mt-1.5">
                      {vulnSuggestions.ferramentas_recomendadas.map((f, i) => (
                        <div key={i} className="px-2.5 py-1.5 rounded-lg bg-[var(--background)] border border-[var(--border)] text-[11px]">
                          <span className="font-medium text-cyan-400">{f.nome}</span>
                          <span className="text-[var(--muted)]"> — {f.uso}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Reward estimate */}
                {vulnSuggestions.estimativa_recompensa && (
                  <div className="p-3 rounded-lg bg-amber-500/5 border border-amber-500/20">
                    <span className="text-[10px] uppercase tracking-wider text-amber-400 font-semibold">💰 Estimativa de Recompensa</span>
                    <div className="flex gap-6 mt-2">
                      <div>
                        <span className="text-[10px] text-[var(--muted)]">Mínima</span>
                        <p className="text-sm font-bold text-[var(--foreground)]">R$ {vulnSuggestions.estimativa_recompensa.minima?.toLocaleString("pt-BR")}</p>
                      </div>
                      <div>
                        <span className="text-[10px] text-[var(--muted)]">Média</span>
                        <p className="text-sm font-bold text-amber-400">R$ {vulnSuggestions.estimativa_recompensa.media?.toLocaleString("pt-BR")}</p>
                      </div>
                      <div>
                        <span className="text-[10px] text-[var(--muted)]">Máxima</span>
                        <p className="text-sm font-bold text-emerald-400">R$ {vulnSuggestions.estimativa_recompensa.maxima?.toLocaleString("pt-BR")}</p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </Card>
          )}

          {/* Report Generator */}
          {aiSelectedProgram && (
            <Card>
              <h3 className="text-sm font-semibold mb-3">📝 Gerar Relatório Profissional</h3>
              <p className="text-[11px] text-[var(--muted)] mb-4">
                Gere um relatório completo para submissão direta na BugHunt. Especifique o tipo de vulnerabilidade.
              </p>

              <div className="space-y-3 mb-4">
                <div>
                  <label className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold mb-1.5 block">
                    Tipo de Vulnerabilidade *
                  </label>
                  <select
                    value={vulnType}
                    onChange={e => setVulnType(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg text-xs bg-[var(--background)] border border-[var(--border)] text-[var(--foreground)] focus:outline-none focus:border-green-500/50"
                  >
                    <option value="">Selecione...</option>
                    <optgroup label="Injeção">
                      <option value="SQL Injection">SQL Injection</option>
                      <option value="XSS (Cross-Site Scripting)">XSS (Cross-Site Scripting)</option>
                      <option value="Command Injection">Command Injection</option>
                      <option value="SSTI (Server-Side Template Injection)">SSTI</option>
                      <option value="CRLF Injection">CRLF Injection</option>
                      <option value="LDAP Injection">LDAP Injection</option>
                      <option value="CSV Injection">CSV Injection</option>
                    </optgroup>
                    <optgroup label="Autenticação/Autorização">
                      <option value="IDOR (Insecure Direct Object Reference)">IDOR</option>
                      <option value="Broken Authentication">Broken Authentication</option>
                      <option value="Privilege Escalation">Privilege Escalation</option>
                      <option value="JWT Vulnerabilities">JWT Vulnerabilities</option>
                      <option value="OAuth Misconfiguration">OAuth Misconfiguration</option>
                    </optgroup>
                    <optgroup label="Server-Side">
                      <option value="SSRF (Server-Side Request Forgery)">SSRF</option>
                      <option value="XXE (XML External Entity)">XXE</option>
                      <option value="RCE (Remote Code Execution)">RCE</option>
                      <option value="Path Traversal / LFI">Path Traversal / LFI</option>
                      <option value="Race Condition">Race Condition</option>
                    </optgroup>
                    <optgroup label="Configuração">
                      <option value="CORS Misconfiguration">CORS Misconfiguration</option>
                      <option value="Open Redirect">Open Redirect</option>
                      <option value="Subdomain Takeover">Subdomain Takeover</option>
                      <option value="Information Disclosure">Information Disclosure</option>
                      <option value="Security Misconfiguration">Security Misconfiguration</option>
                    </optgroup>
                    <optgroup label="Client-Side">
                      <option value="CSRF (Cross-Site Request Forgery)">CSRF</option>
                      <option value="Clickjacking">Clickjacking</option>
                      <option value="DOM-Based Vulnerabilities">DOM-Based Vulnerabilities</option>
                    </optgroup>
                    <optgroup label="API">
                      <option value="GraphQL Vulnerabilities">GraphQL Vulnerabilities</option>
                      <option value="API Rate Limiting">API Rate Limiting</option>
                      <option value="Mass Assignment">Mass Assignment</option>
                      <option value="Broken Object Level Authorization">BOLA (Broken Object Level Auth)</option>
                    </optgroup>
                    <optgroup label="Dados">
                      <option value="Sensitive Data Exposure">Sensitive Data Exposure</option>
                      <option value="Hardcoded Credentials">Hardcoded Credentials</option>
                      <option value="PII Leakage">PII Leakage</option>
                    </optgroup>
                  </select>
                </div>

                <div>
                  <label className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold mb-1.5 block">
                    Detalhes Adicionais (opcional)
                  </label>
                  <textarea
                    value={vulnDetails}
                    onChange={e => setVulnDetails(e.target.value)}
                    placeholder="Ex: Encontrei um endpoint /api/users/{id} que retorna dados de outros usuários sem autenticação..."
                    rows={3}
                    className="w-full px-3 py-2 rounded-lg text-xs bg-[var(--background)] border border-[var(--border)] text-[var(--foreground)] placeholder:text-[var(--muted)] focus:outline-none focus:border-green-500/50 resize-none"
                  />
                </div>

                <button onClick={handleGenerateReport} disabled={!!aiLoading || !vulnType}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-medium bg-green-500/15 text-green-400 border border-green-500/25 hover:bg-green-500/25 transition-colors disabled:opacity-50">
                  {aiLoading === "report" ? (
                    <><span className="w-3 h-3 border border-green-400/30 border-t-green-400 rounded-full animate-spin" /> Gerando relatório...</>
                  ) : (
                    <>📝 Gerar Relatório</>
                  )}
                </button>
              </div>
            </Card>
          )}

          {/* Generated Report */}
          {reportData && (
            <Card>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-semibold">📄 Relatório Gerado</h3>
                <div className="flex items-center gap-2">
                  {reportData.fallback && (
                    <span className="px-2 py-0.5 rounded text-[9px] font-semibold bg-amber-500/15 text-amber-400">PARCIAL</span>
                  )}
                  <button
                    onClick={saveCurrentReport}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-[11px] font-medium bg-green-500/15 text-green-400 border border-green-500/25 hover:bg-green-500/25 transition-colors"
                  >
                    💾 Salvar
                  </button>
                  <button
                    onClick={() => copyToClipboard(buildFullReportMarkdown(), "full")}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-[11px] font-medium bg-cyan-500/15 text-cyan-400 border border-cyan-500/25 hover:bg-cyan-500/25 transition-colors"
                  >
                    {copiedField === "full" ? "✅ Copiado!" : "📋 Copiar Tudo"}
                  </button>
                </div>
              </div>

              <div className="space-y-4">
                {/* Title */}
                <div className="p-3 rounded-lg bg-[var(--background)] border border-green-500/20">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Título</span>
                    <button onClick={() => copyToClipboard(reportData.titulo, "titulo")}
                      className="text-[10px] text-cyan-400 hover:text-cyan-300 transition-colors">
                      {copiedField === "titulo" ? "✅" : "📋"}
                    </button>
                  </div>
                  <p className="text-sm font-medium text-[var(--foreground)] mt-1">{reportData.titulo}</p>
                </div>

                {/* Severity + CVSS */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="p-3 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                    <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Severidade</span>
                    <p className={`text-sm font-bold mt-1 ${
                      reportData.severidade?.toLowerCase().includes("crít") ? "text-red-400" :
                      reportData.severidade?.toLowerCase().includes("alt") ? "text-orange-400" :
                      reportData.severidade?.toLowerCase().includes("méd") ? "text-amber-400" :
                      "text-green-400"
                    }`}>{reportData.severidade}</p>
                  </div>
                  {reportData.cvss_score && (
                    <div className="p-3 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                      <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">CVSS</span>
                      <p className="text-sm font-bold text-[var(--foreground)] mt-1">{reportData.cvss_score}</p>
                    </div>
                  )}
                  {reportData.cwe && (
                    <div className="p-3 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                      <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">CWE</span>
                      <p className="text-xs font-medium text-[var(--foreground)] mt-1">{reportData.cwe}</p>
                    </div>
                  )}
                  {reportData.owasp_category && (
                    <div className="p-3 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                      <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">OWASP</span>
                      <p className="text-xs font-medium text-[var(--foreground)] mt-1">{reportData.owasp_category}</p>
                    </div>
                  )}
                </div>

                {/* Executive Summary */}
                {reportData.resumo_executivo && (
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Resumo Executivo</span>
                      <button onClick={() => copyToClipboard(reportData.resumo_executivo, "resumo")}
                        className="text-[10px] text-cyan-400 hover:text-cyan-300">{copiedField === "resumo" ? "✅" : "📋"}</button>
                    </div>
                    <div className="mt-1.5 p-3 rounded-lg bg-[var(--background)] border border-[var(--border)] text-xs text-[var(--foreground)] leading-relaxed whitespace-pre-wrap">
                      {reportData.resumo_executivo}
                    </div>
                  </div>
                )}

                {/* Steps to reproduce */}
                {reportData.passos_reproducao?.length > 0 && (
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Passos para Reprodução</span>
                      <button onClick={() => copyToClipboard(reportData.passos_reproducao.map((s, i) => `${i + 1}. ${s}`).join("\n"), "passos")}
                        className="text-[10px] text-cyan-400 hover:text-cyan-300">{copiedField === "passos" ? "✅" : "📋"}</button>
                    </div>
                    <div className="mt-1.5 space-y-1.5">
                      {reportData.passos_reproducao.map((step, i) => (
                        <div key={i} className="flex items-start gap-2 p-2 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                          <span className="flex items-center justify-center w-5 h-5 rounded-full bg-green-500/15 text-green-400 text-[9px] font-bold shrink-0">{i + 1}</span>
                          <span className="text-xs text-[var(--foreground)] whitespace-pre-wrap">{step}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* PoC */}
                {reportData.poc && (
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Proof of Concept</span>
                      <button onClick={() => copyToClipboard(reportData.poc, "poc")}
                        className="text-[10px] text-cyan-400 hover:text-cyan-300">{copiedField === "poc" ? "✅" : "📋"}</button>
                    </div>
                    <pre className="mt-1.5 p-3 rounded-lg bg-[var(--background)] border border-[var(--border)] text-[11px] text-green-400 font-mono overflow-x-auto whitespace-pre-wrap">
                      {reportData.poc}
                    </pre>
                  </div>
                )}

                {/* Impact */}
                {reportData.impacto && (
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Impacto</span>
                      <button onClick={() => copyToClipboard(reportData.impacto, "impacto")}
                        className="text-[10px] text-cyan-400 hover:text-cyan-300">{copiedField === "impacto" ? "✅" : "📋"}</button>
                    </div>
                    <div className="mt-1.5 p-3 rounded-lg bg-red-500/5 border border-red-500/15 text-xs text-[var(--foreground)] leading-relaxed whitespace-pre-wrap">
                      {reportData.impacto}
                    </div>
                  </div>
                )}

                {/* Remediation */}
                {reportData.remediacao?.length > 0 && (
                  <div>
                    <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Remediação</span>
                    <ul className="mt-1.5 space-y-1">
                      {reportData.remediacao.map((r, i) => (
                        <li key={i} className="flex items-start gap-2 text-xs text-[var(--foreground)]">
                          <span className="text-emerald-400 mt-0.5">✓</span> {r}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* References */}
                {reportData.referencias?.length > 0 && (
                  <div>
                    <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Referências</span>
                    <ul className="mt-1.5 space-y-0.5">
                      {reportData.referencias.map((ref, i) => (
                        <li key={i} className="text-[11px] text-blue-400">
                          {ref.startsWith("http") ? (
                            <a href={ref} target="_blank" rel="noopener noreferrer" className="hover:underline">{ref}</a>
                          ) : ref}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Meta */}
                <div className="flex items-center gap-4 pt-2 border-t border-[var(--border)] text-[10px] text-[var(--muted)]">
                  <span>Programa: {reportData.programa}</span>
                  <span>Tipo: {reportData.tipo_vulnerabilidade}</span>
                  <span>Gerado: {reportData.gerado_em ? new Date(reportData.gerado_em).toLocaleString("pt-BR") : "—"}</span>
                </div>
              </div>
            </Card>
          )}

          {/* Empty state */}
          {!aiSelectedProgram && (
            <Card className="text-center py-12">
              <span className="text-3xl">🤖</span>
              <p className="text-sm text-[var(--muted)] mt-2">Selecione um programa acima para começar</p>
              <p className="text-[10px] text-[var(--muted)] mt-1">
                A IA analisará o escopo, sugerirá vulnerabilidades e gerará relatórios profissionais
              </p>
            </Card>
          )}
        </div>
      )}

      {/* ═══ REPORTS TAB — Relatórios para Envio ═══════════ */}
      {activeTab === "reports" && (
        <div className="space-y-4">
          {/* Header + Filters */}
          <Card>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-semibold">📋 Relatórios para Envio — BugHunt</h3>
                <p className="text-[11px] text-[var(--muted)] mt-1">
                  Relatórios salvos prontos para submissão na plataforma. Copie no formato desejado.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <span className="px-2.5 py-1 rounded-full text-[11px] font-bold bg-green-500/15 text-green-400 border border-green-500/25 tabular-nums">
                  {savedReports.length} relatório{savedReports.length !== 1 ? "s" : ""}
                </span>
                {savedReports.length > 0 && (
                  <button
                    onClick={() => {
                      const all = savedReports.map(r => buildPlainTextReport(r)).join("\n\n" + "=".repeat(60) + "\n\n");
                      copyToClipboard(all, "all-reports");
                    }}
                    className="px-3 py-1.5 rounded-lg text-[11px] font-medium bg-cyan-500/15 text-cyan-400 border border-cyan-500/25 hover:bg-cyan-500/25 transition-colors"
                  >
                    {copiedField === "all-reports" ? "✅ Copiado!" : "📋 Exportar Todos"}
                  </button>
                )}
              </div>
            </div>

            {/* Filters */}
            {savedReports.length > 0 && (
              <div className="flex items-center gap-3">
                <div className="flex-1 relative">
                  <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--muted)]" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
                  </svg>
                  <input
                    type="text"
                    value={reportSearch}
                    onChange={e => setReportSearch(e.target.value)}
                    placeholder="Buscar por título, programa, tipo..."
                    className="w-full pl-9 pr-3 py-2 rounded-lg text-xs bg-[var(--background)] border border-[var(--border)] text-[var(--foreground)] placeholder:text-[var(--muted)] focus:outline-none focus:border-green-500/50"
                  />
                </div>
                <select
                  value={reportSevFilter}
                  onChange={e => setReportSevFilter(e.target.value)}
                  className="px-3 py-2 rounded-lg text-xs bg-[var(--background)] border border-[var(--border)] text-[var(--foreground)] focus:outline-none focus:border-green-500/50"
                >
                  <option value="">Todas severidades</option>
                  <option value="crítica">Crítica</option>
                  <option value="alta">Alta</option>
                  <option value="média">Média</option>
                  <option value="baixa">Baixa</option>
                </select>
                <span className="text-xs text-[var(--muted)] tabular-nums shrink-0">
                  {filteredReports.length} de {savedReports.length}
                </span>
              </div>
            )}
          </Card>

          {/* Empty state */}
          {savedReports.length === 0 ? (
            <Card className="text-center py-16">
              <span className="text-4xl">📝</span>
              <p className="text-sm text-[var(--muted)] mt-3">Nenhum relatório salvo</p>
              <p className="text-[11px] text-[var(--muted)] mt-1.5 max-w-md mx-auto">
                Vá na aba <strong className="text-green-400">AI Reports</strong>, gere um relatório e clique em <strong className="text-green-400">💾 Salvar</strong> para
                ele aparecer aqui pronto para envio.
              </p>
              <button
                onClick={() => setActiveTab("ai")}
                className="mt-4 px-4 py-2 rounded-lg text-xs font-medium bg-green-500/15 text-green-400 border border-green-500/25 hover:bg-green-500/25 transition-colors"
              >
                🤖 Ir para AI Reports
              </button>
            </Card>
          ) : filteredReports.length === 0 ? (
            <Card className="text-center py-12">
              <span className="text-3xl">🔍</span>
              <p className="text-sm text-[var(--muted)] mt-2">Nenhum relatório encontrado com esse filtro</p>
            </Card>
          ) : (
            <div className="space-y-3">
              {filteredReports.map((rpt) => {
                const isExpanded = expandedReport === rpt.id;
                const sevColor =
                  rpt.severidade?.toLowerCase().includes("crít") ? { bg: "bg-red-500/10", text: "text-red-400", border: "border-red-500/20" } :
                  rpt.severidade?.toLowerCase().includes("alt") ? { bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/20" } :
                  rpt.severidade?.toLowerCase().includes("méd") ? { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/20" } :
                  { bg: "bg-sky-500/10", text: "text-sky-400", border: "border-sky-500/20" };

                return (
                  <Card key={rpt.id} className="!p-0 overflow-hidden">
                    {/* Report header row */}
                    <button
                      onClick={() => setExpandedReport(isExpanded ? null : rpt.id)}
                      className="w-full flex items-center justify-between p-4 hover:bg-white/[0.02] transition-colors text-left"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <span className={`px-2 py-1 rounded text-[10px] font-bold uppercase shrink-0 ${sevColor.bg} ${sevColor.text} border ${sevColor.border}`}>
                          {rpt.severidade}
                        </span>
                        <div className="min-w-0">
                          <div className="text-sm font-medium text-[var(--foreground)] truncate">
                            {rpt.titulo}
                          </div>
                          <div className="flex items-center gap-3 mt-0.5">
                            <span className="text-[10px] text-green-400 font-medium">{rpt.programa}</span>
                            <span className="text-[10px] text-[var(--muted)]">{rpt.tipo_vulnerabilidade}</span>
                            <span className="text-[10px] text-[var(--muted)]">
                              {formatDate(rpt.savedAt)}
                            </span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {rpt.cvss_score && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/15 text-purple-400 border border-purple-500/20">
                            CVSS {rpt.cvss_score}
                          </span>
                        )}
                        <svg className={`w-4 h-4 text-[var(--muted)] transition-transform ${isExpanded ? "rotate-180" : ""}`}
                          fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
                        </svg>
                      </div>
                    </button>

                    {/* Expanded report content */}
                    {isExpanded && (
                      <div className="border-t border-[var(--border)] bg-[var(--background)]/30">
                        {/* Action buttons */}
                        <div className="flex items-center gap-2 p-4 pb-0">
                          <button
                            onClick={(e) => { e.stopPropagation(); copyToClipboard(buildReportMarkdown(rpt), `md-${rpt.id}`); }}
                            className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-[11px] font-medium bg-cyan-500/15 text-cyan-400 border border-cyan-500/25 hover:bg-cyan-500/25 transition-colors"
                          >
                            {copiedField === `md-${rpt.id}` ? "✅ Copiado!" : "📋 Copiar Markdown"}
                          </button>
                          <button
                            onClick={(e) => { e.stopPropagation(); copyToClipboard(buildPlainTextReport(rpt), `txt-${rpt.id}`); }}
                            className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-[11px] font-medium bg-blue-500/15 text-blue-400 border border-blue-500/25 hover:bg-blue-500/25 transition-colors"
                          >
                            {copiedField === `txt-${rpt.id}` ? "✅ Copiado!" : "📄 Copiar Texto"}
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              const blob = new Blob([buildReportMarkdown(rpt)], { type: "text/markdown" });
                              const url = URL.createObjectURL(blob);
                              const a = document.createElement("a");
                              a.href = url;
                              a.download = `bughunt-report-${rpt.programa?.replace(/\s+/g, "-").toLowerCase()}-${rpt.tipo_vulnerabilidade?.replace(/\s+/g, "-").toLowerCase()}.md`;
                              a.click();
                              URL.revokeObjectURL(url);
                            }}
                            className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-[11px] font-medium bg-purple-500/15 text-purple-400 border border-purple-500/25 hover:bg-purple-500/25 transition-colors"
                          >
                            ⬇️ Download .md
                          </button>
                          <div className="flex-1" />
                          <button
                            onClick={(e) => { e.stopPropagation(); deleteReport(rpt.id); }}
                            className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-[11px] font-medium bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 transition-colors"
                          >
                            🗑️ Remover
                          </button>
                        </div>

                        {/* Full report content - readable format */}
                        <div className="p-4 space-y-4">
                          {/* Meta badges */}
                          <div className="flex flex-wrap gap-2">
                            <span className={`px-2.5 py-1 rounded-md text-[11px] font-bold ${sevColor.bg} ${sevColor.text} border ${sevColor.border}`}>
                              {rpt.severidade}
                            </span>
                            {rpt.cvss_score && (
                              <span className="px-2.5 py-1 rounded-md text-[11px] font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20">
                                CVSS: {rpt.cvss_score} {rpt.cvss_vector ? `(${rpt.cvss_vector})` : ""}
                              </span>
                            )}
                            {rpt.cwe && (
                              <span className="px-2.5 py-1 rounded-md text-[11px] font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20">
                                {rpt.cwe}
                              </span>
                            )}
                            {rpt.owasp_category && (
                              <span className="px-2.5 py-1 rounded-md text-[11px] font-medium bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                                {rpt.owasp_category}
                              </span>
                            )}
                          </div>

                          {/* Resumo Executivo */}
                          {rpt.resumo_executivo && (
                            <div className="rounded-lg border border-[var(--border)] overflow-hidden">
                              <div className="flex items-center justify-between px-3 py-2 bg-[var(--card)]">
                                <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Resumo Executivo</span>
                                <button onClick={() => copyToClipboard(rpt.resumo_executivo, `resumo-${rpt.id}`)}
                                  className="text-[10px] text-cyan-400 hover:text-cyan-300">{copiedField === `resumo-${rpt.id}` ? "✅" : "📋"}</button>
                              </div>
                              <div className="px-4 py-3 text-xs text-[var(--foreground)] leading-relaxed whitespace-pre-wrap">
                                {rpt.resumo_executivo}
                              </div>
                            </div>
                          )}

                          {/* Passos para Reprodução */}
                          {rpt.passos_reproducao?.length > 0 && (
                            <div className="rounded-lg border border-[var(--border)] overflow-hidden">
                              <div className="flex items-center justify-between px-3 py-2 bg-[var(--card)]">
                                <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Passos para Reprodução</span>
                                <button onClick={() => copyToClipboard(rpt.passos_reproducao.map((s, i) => `${i + 1}. ${s}`).join("\n"), `passos-${rpt.id}`)}
                                  className="text-[10px] text-cyan-400 hover:text-cyan-300">{copiedField === `passos-${rpt.id}` ? "✅" : "📋"}</button>
                              </div>
                              <div className="px-4 py-3 space-y-2">
                                {rpt.passos_reproducao.map((step, i) => (
                                  <div key={i} className="flex items-start gap-2.5">
                                    <span className="flex items-center justify-center w-5 h-5 rounded-full bg-green-500/15 text-green-400 text-[9px] font-bold shrink-0 mt-0.5">{i + 1}</span>
                                    <span className="text-xs text-[var(--foreground)] leading-relaxed whitespace-pre-wrap">{step}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Proof of Concept */}
                          {rpt.poc && (
                            <div className="rounded-lg border border-[var(--border)] overflow-hidden">
                              <div className="flex items-center justify-between px-3 py-2 bg-[var(--card)]">
                                <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Proof of Concept</span>
                                <button onClick={() => copyToClipboard(rpt.poc, `poc-${rpt.id}`)}
                                  className="text-[10px] text-cyan-400 hover:text-cyan-300">{copiedField === `poc-${rpt.id}` ? "✅" : "📋"}</button>
                              </div>
                              <pre className="px-4 py-3 text-[11px] text-green-400 font-mono overflow-x-auto whitespace-pre-wrap bg-black/20">
                                {rpt.poc}
                              </pre>
                            </div>
                          )}

                          {/* Impacto */}
                          {rpt.impacto && (
                            <div className="rounded-lg border border-red-500/15 overflow-hidden">
                              <div className="flex items-center justify-between px-3 py-2 bg-red-500/5">
                                <span className="text-[10px] uppercase tracking-wider text-red-400 font-semibold">Impacto</span>
                                <button onClick={() => copyToClipboard(rpt.impacto, `impacto-${rpt.id}`)}
                                  className="text-[10px] text-cyan-400 hover:text-cyan-300">{copiedField === `impacto-${rpt.id}` ? "✅" : "📋"}</button>
                              </div>
                              <div className="px-4 py-3 text-xs text-[var(--foreground)] leading-relaxed whitespace-pre-wrap">
                                {rpt.impacto}
                              </div>
                            </div>
                          )}

                          {/* Remediação */}
                          {rpt.remediacao?.length > 0 && (
                            <div className="rounded-lg border border-[var(--border)] overflow-hidden">
                              <div className="px-3 py-2 bg-[var(--card)]">
                                <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Remediação</span>
                              </div>
                              <div className="px-4 py-3 space-y-1">
                                {rpt.remediacao.map((rem, i) => (
                                  <div key={i} className="flex items-start gap-2 text-xs text-[var(--foreground)]">
                                    <span className="text-emerald-400 mt-0.5 shrink-0">✓</span>
                                    <span className="leading-relaxed">{rem}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Referências */}
                          {rpt.referencias?.length > 0 && (
                            <div className="rounded-lg border border-[var(--border)] overflow-hidden">
                              <div className="px-3 py-2 bg-[var(--card)]">
                                <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Referências</span>
                              </div>
                              <div className="px-4 py-3 space-y-0.5">
                                {rpt.referencias.map((ref, i) => (
                                  <div key={i} className="text-[11px]">
                                    {ref.startsWith("http") ? (
                                      <a href={ref} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline break-all">{ref}</a>
                                    ) : (
                                      <span className="text-[var(--foreground)]">{ref}</span>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Footer meta */}
                          <div className="flex items-center gap-4 pt-2 border-t border-[var(--border)] text-[10px] text-[var(--muted)]">
                            <span>🇧🇷 Programa: <strong className="text-green-400">{rpt.programa}</strong></span>
                            <span>Tipo: {rpt.tipo_vulnerabilidade}</span>
                            <span>Gerado: {rpt.gerado_em ? new Date(rpt.gerado_em).toLocaleString("pt-BR") : "—"}</span>
                            <span>Salvo: {formatDate(rpt.savedAt)}</span>
                          </div>
                        </div>
                      </div>
                    )}
                  </Card>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ═══ CONFIG TAB ═════════════════════════════════════ */}
      {activeTab === "config" && (
        <div className="space-y-4">
          <Card>
            <h3 className="text-sm font-semibold mb-4">🔧 Configuração do Scraper</h3>

            <div className="space-y-3">
              {/* Email */}
              <div className="flex items-center justify-between py-2 px-3 rounded-lg bg-[var(--background)]/50">
                <div className="flex items-center gap-2">
                  <span className="text-sm">📧</span>
                  <span className="text-xs font-medium">BUGHUNT_EMAIL</span>
                </div>
                <StatusBadge ok={status?.email_set ?? false} label={status?.email_set ? "Definido" : "Não definido"} />
              </div>

              {/* Password */}
              <div className="flex items-center justify-between py-2 px-3 rounded-lg bg-[var(--background)]/50">
                <div className="flex items-center gap-2">
                  <span className="text-sm">🔑</span>
                  <span className="text-xs font-medium">BUGHUNT_PASSWORD</span>
                </div>
                <StatusBadge ok={status?.password_set ?? false} label={status?.password_set ? "Definido" : "Não definido"} />
              </div>

              {/* CapSolver */}
              <div className="flex items-center justify-between py-2 px-3 rounded-lg bg-[var(--background)]/50">
                <div className="flex items-center gap-2">
                  <span className="text-sm">🤖</span>
                  <div>
                    <span className="text-xs font-medium">CAPSOLVER_API_KEY</span>
                    <span className="ml-2 text-[10px] text-[var(--muted)]">(opcional)</span>
                  </div>
                </div>
                <StatusBadge ok={status?.capsolver_set ?? false} label={status?.capsolver_set ? "Definido" : "Não definido"} />
              </div>
            </div>
          </Card>

          {/* How to configure */}
          <Card>
            <h3 className="text-sm font-semibold mb-3">📋 Como Configurar</h3>
            <div className="space-y-3 text-xs text-[var(--muted)]">
              <div className="p-3 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                <p className="font-medium text-[var(--foreground)] mb-2">1. Criar conta na BugHunt</p>
                <p>Acesse <a href="https://www.bughunt.com.br" target="_blank" rel="noopener noreferrer"
                  className="text-green-400 hover:underline">bughunt.com.br</a> e registre-se como pesquisador.</p>
              </div>

              <div className="p-3 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                <p className="font-medium text-[var(--foreground)] mb-2">2. Adicionar credenciais no .env</p>
                <pre className="mt-2 p-2 rounded bg-[var(--card)] text-[11px] font-mono text-green-400 overflow-x-auto">
{`BUGHUNT_EMAIL=seu@email.com
BUGHUNT_PASSWORD=sua_senha`}
                </pre>
              </div>

              <div className="p-3 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                <p className="font-medium text-[var(--foreground)] mb-2">3. (Opcional) CapSolver para reCAPTCHA</p>
                <p className="mb-2">O login da BugHunt usa reCAPTCHA. Configure o CapSolver para resolver automaticamente:</p>
                <pre className="mt-2 p-2 rounded bg-[var(--card)] text-[11px] font-mono text-green-400 overflow-x-auto">
{`CAPSOLVER_API_KEY=CAP-xxxxxxxx`}
                </pre>
                <p className="mt-2 text-[10px]">
                  Obtenha uma key em <a href="https://www.capsolver.com" target="_blank" rel="noopener noreferrer"
                  className="text-blue-400 hover:underline">capsolver.com</a>
                </p>
              </div>

              <div className="p-3 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                <p className="font-medium text-[var(--foreground)] mb-2">4. Reiniciar containers</p>
                <pre className="mt-2 p-2 rounded bg-[var(--card)] text-[11px] font-mono text-green-400 overflow-x-auto">
{`docker compose up -d --build app`}
                </pre>
              </div>
            </div>
          </Card>

          {/* Platform Info */}
          <Card>
            <h3 className="text-sm font-semibold mb-3">ℹ️ Sobre a BugHunt</h3>
            <div className="space-y-2 text-xs text-[var(--muted)]">
              <p>
                A <span className="text-green-400 font-medium">BugHunt</span> é a maior plataforma de bug bounty do Brasil.
                Empresas brasileiras como bancos, fintechs e startups utilizam a plataforma para programas de segurança.
              </p>
              <div className="grid grid-cols-2 gap-3 mt-3">
                <div className="p-3 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                  <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">API Base</span>
                  <p className="text-[11px] font-mono text-[var(--foreground)] mt-1">api.bughunt.com.br</p>
                </div>
                <div className="p-3 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                  <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Auth</span>
                  <p className="text-[11px] font-mono text-[var(--foreground)] mt-1">JWT + reCAPTCHA v2</p>
                </div>
                <div className="p-3 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                  <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Watcher</span>
                  <p className="text-[11px] text-[var(--foreground)] mt-1">Check automático a cada 30min</p>
                </div>
                <div className="p-3 rounded-lg bg-[var(--background)] border border-[var(--border)]">
                  <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold">Status</span>
                  <p className="text-[11px] text-[var(--foreground)] mt-1">{status?.status || "Desconhecido"}</p>
                </div>
              </div>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
