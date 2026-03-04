"use client";

import { useState, useCallback, useEffect } from "react";
import {
  fetchH1Stats,
  fetchH1Queue,
  fetchH1Me,
  fetchLocalReports,
  fetchReportStats,
  fetchSubmittedReports,
  fetchSubmittedReportsStats,
  generateReports,
  triggerH1AutoSubmit,
  triggerH1BatchSubmit,
  searchBountyPrograms,
  type H1Stats,
  type H1QueueItem,
  type LocalReport,
  type ReportStats,
  type SubmittedReport,
  type SubmittedReportsStats,
  type BountySearchParams,
  type BountySearchResponse,
} from "@/lib/api";

/* ═══════════════════════════════════════════════════
   Toast alert system
   ═══════════════════════════════════════════════════ */
type Toast = { id: number; type: "ok" | "err" | "info" | "load"; text: string };
let _tid = 0;

function useToasts() {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((type: Toast["type"], text: string) => {
    const t: Toast = { id: ++_tid, type, text };
    setToasts(prev => [t, ...prev].slice(0, 8));
    if (type !== "load") setTimeout(() => setToasts(prev => prev.filter(x => x.id !== t.id)), 6000);
    return t.id;
  }, []);
  const remove = useCallback((id: number) => setToasts(prev => prev.filter(x => x.id !== id)), []);
  return { toasts, push, remove };
}

/* ═══════════════════════════════════════════════════
   Severity badge
   ═══════════════════════════════════════════════════ */
function Sev({ s }: { s: string }) {
  const c: Record<string, string> = {
    critical: "bg-rose-500/25 text-rose-300 border-rose-500/40 shadow-rose-500/10",
    high: "bg-orange-500/25 text-orange-300 border-orange-500/40 shadow-orange-500/10",
    medium: "bg-amber-500/20 text-amber-300 border-amber-500/30",
    low: "bg-sky-500/20 text-sky-300 border-sky-500/30",
    info: "bg-slate-500/20 text-slate-400 border-slate-500/30",
  };
  return <span className={`px-1.5 py-px rounded text-[9px] font-black uppercase tracking-wide border shadow-sm ${c[s] ?? c.info}`}>{s}</span>;
}

/* ═══════════════════════════════════════════════════
   PAGE
   ═══════════════════════════════════════════════════ */
export default function HackerOnePage() {
  /* ─── state ─── */
  const [h1Stats, setH1Stats] = useState<H1Stats | null>(null);
  const [h1Queue, setH1Queue] = useState<H1QueueItem[]>([]);
  const [h1Me, setH1Me] = useState<{ ok: boolean; username: string; programs: number } | null>(null);
  const [h1MeError, setH1MeError] = useState<string | null>(null);
  const [reportStats, setReportStats] = useState<ReportStats | null>(null);
  const [localReports, setLocalReports] = useState<LocalReport[]>([]);
  const [submittedReports, setSubmittedReports] = useState<SubmittedReport[]>([]);
  const [submittedStats, setSubmittedStats] = useState<SubmittedReportsStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);

  // Discover
  const [searchQuery, setSearchQuery] = useState("");
  const [searchPlatform, setSearchPlatform] = useState("");
  const [searchBountyOnly, setSearchBountyOnly] = useState(false);
  const [searchHasWildcards, setSearchHasWildcards] = useState(false);
  const [searchSortBy, setSearchSortBy] = useState<"newest" | "name" | "scope_size">("scope_size");
  const [searchResults, setSearchResults] = useState<BountySearchResponse | null>(null);
  const [searchLoading, setSearchLoading] = useState(false);
  const [expandedProgram, setExpandedProgram] = useState<string | null>(null);
  const [showDiscover, setShowDiscover] = useState(false);

  const { toasts, push, remove } = useToasts();

  /* ─── initial fetch with toast alerts ─── */
  useEffect(() => {
    (async () => {
      setLoading(true);
      const lid = push("load", "Conectando aos serviços...");

      const results = await Promise.allSettled([
        fetchH1Stats(),
        fetchH1Queue(),
        fetchReportStats(),
        fetchLocalReports(100, "draft"),
        fetchSubmittedReports(50),
        fetchSubmittedReportsStats(),
        fetchH1Me(),
      ]);
      remove(lid);

      const labels = ["H1 Stats", "Fila H1", "Report Stats", "Drafts Locais", "Enviados", "Stats Envio", "API H1 /me"];
      let okCount = 0;
      let errCount = 0;
      results.forEach((r, i) => {
        if (r.status === "fulfilled") { okCount++; }
        else { errCount++; push("err", `${labels[i]}: ${r.reason instanceof Error ? r.reason.message : "falhou"}`); }
      });

      if (results[0].status === "fulfilled") setH1Stats(results[0].value);
      if (results[1].status === "fulfilled") setH1Queue(results[1].value.reports || []);
      if (results[2].status === "fulfilled") setReportStats(results[2].value);
      if (results[3].status === "fulfilled") setLocalReports(results[3].value.reports || []);
      if (results[4].status === "fulfilled") setSubmittedReports(results[4].value);
      if (results[5].status === "fulfilled") setSubmittedStats(results[5].value);
      if (results[6].status === "fulfilled") {
        setH1Me(results[6].value);
      } else {
        const err = results[6].reason;
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.includes("abort") || msg.includes("AbortError")) setH1MeError("Timeout API H1");
        else if (msg.includes("503") || msg.includes("not configured")) setH1MeError("Credenciais não configuradas");
        else if (msg.includes("502")) setH1MeError("Token inválido/expirado");
        else setH1MeError(msg);
      }

      if (okCount > 0) push("ok", `${okCount} serviço${okCount > 1 ? "s" : ""} carregado${okCount > 1 ? "s" : ""}${errCount ? ` · ${errCount} falha${errCount > 1 ? "s" : ""}` : ""}`);
      setLoading(false);
    })();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  /* ─── refresh ─── */
  const refreshAll = async () => {
    setLoading(true);
    const lid = push("load", "Atualizando dados...");
    try {
      const [stats, queue, rStats, reports, submitted, sStats] = await Promise.all([
        fetchH1Stats(), fetchH1Queue(), fetchReportStats(),
        fetchLocalReports(100, "draft"), fetchSubmittedReports(50), fetchSubmittedReportsStats(),
      ]);
      setH1Stats(stats); setH1Queue(queue.reports || []);
      setReportStats(rStats); setLocalReports(reports.reports || []);
      setSubmittedReports(submitted); setSubmittedStats(sStats);
      remove(lid);
      push("ok", "Dados atualizados");
    } catch {
      remove(lid);
      push("err", "Falha ao atualizar");
    }
    setLoading(false);
  };

  /* ─── search ─── */
  const doSearch = useCallback(async (overrides?: Partial<BountySearchParams>) => {
    setSearchLoading(true);
    const lid = push("load", "Buscando programas...");
    try {
      const res = await searchBountyPrograms({
        q: overrides?.q ?? searchQuery,
        platform: overrides?.platform ?? searchPlatform,
        bounty_only: overrides?.bounty_only ?? searchBountyOnly,
        has_wildcards: overrides?.has_wildcards ?? searchHasWildcards,
        sort_by: overrides?.sort_by ?? searchSortBy,
        limit: 60,
      });
      setSearchResults(res);
      remove(lid);
      push("ok", `${res.total} programa${res.total !== 1 ? "s" : ""} encontrado${res.total !== 1 ? "s" : ""}`);
    } catch (e) {
      remove(lid);
      push("err", e instanceof Error ? e.message : "Erro na busca");
    } finally { setSearchLoading(false); }
  }, [searchQuery, searchPlatform, searchBountyOnly, searchHasWildcards, searchSortBy, push, remove]);

  /* ─── actions ─── */
  const handleAction = async (
    label: string,
    fn: () => Promise<string>,
  ) => {
    setActionLoading(true);
    const lid = push("load", `${label}...`);
    try {
      const msg = await fn();
      remove(lid);
      push("ok", msg);
      await refreshAll();
    } catch (e: unknown) {
      remove(lid);
      push("err", `${label}: ${e instanceof Error ? e.message : "falhou"}`);
    } finally { setActionLoading(false); }
  };

  const doGenerate = () => handleAction("Gerando reports", async () => {
    const r = await generateReports({ limit: 50 });
    return `${r.reports_generated} reports de ${r.processed_vulns} vulns`;
  });
  const doDryRun = () => handleAction("Dry run", async () => {
    const r = await triggerH1BatchSubmit({ limit: 10, dry_run: true });
    return `${r.submitted} seriam enviados · ${r.duplicates} duplicados`;
  });
  const doBatchSubmit = () => handleAction("Batch submit", async () => {
    const r = await triggerH1BatchSubmit({ limit: 10, dry_run: false });
    return `${r.submitted} enviados · ${r.duplicates} dup · ${r.errors} erro(s)`;
  });
  const doFullCycle = () => handleAction("Ciclo completo", async () => {
    const r = await triggerH1AutoSubmit({ limit: 10 });
    return `${r.reports_generated} reports → ${r.submitted} enviados · ${r.duplicates} dup`;
  });

  /* ─── derived ─── */
  const credOk = h1Me != null;
  const credInvalid = !credOk && h1MeError != null && (h1MeError.includes("inválido") || h1MeError.includes("expirado"));
  const autoOn = h1Stats?.auto_submit_config?.enabled ?? false;
  const dryMode = h1Stats?.auto_submit_config?.dry_run ?? false;

  /* ═══════════════════════════════════════════════════
     RENDER
     ═══════════════════════════════════════════════════ */
  return (
    <div className="min-h-screen" style={{ background: "linear-gradient(180deg, #05050c 0%, #08081a 50%, #060614 100%)" }}>
      <div className="max-w-6xl mx-auto px-4 py-6 space-y-5">

        {/* ─── TOAST ALERTS ─── */}
        {toasts.length > 0 && (
          <div className="fixed top-4 right-4 z-50 space-y-2 w-80 pointer-events-none">
            {toasts.map(t => (
              <div
                key={t.id}
                onClick={() => remove(t.id)}
                className={`pointer-events-auto cursor-pointer px-4 py-2.5 rounded-lg border text-xs font-medium backdrop-blur-xl shadow-2xl transition-all animate-[slideIn_0.3s_ease-out] ${
                  t.type === "ok"   ? "bg-emerald-950/80 border-emerald-500/30 text-emerald-300 shadow-emerald-500/10" :
                  t.type === "err"  ? "bg-rose-950/80 border-rose-500/30 text-rose-300 shadow-rose-500/10" :
                  t.type === "load" ? "bg-cyan-950/80 border-cyan-500/30 text-cyan-300 shadow-cyan-500/10" :
                                      "bg-slate-950/80 border-slate-500/30 text-slate-300"
                }`}
              >
                <span className="mr-2">
                  {t.type === "ok" ? "✓" : t.type === "err" ? "✕" : t.type === "load" ? "◌" : "i"}
                </span>
                {t.text}
              </div>
            ))}
          </div>
        )}

        {/* ─── HEADER ─── */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-600/30 to-cyan-600/30 border border-violet-500/20 flex items-center justify-center text-lg shadow-lg shadow-violet-500/10">
              🏴‍☠️
            </div>
            <div>
              <h1 className="text-lg font-bold text-white tracking-tight">HackerOne</h1>
              <div className="flex items-center gap-2 mt-0.5">
                <span className={`w-2 h-2 rounded-full ${credOk ? "bg-emerald-400 animate-pulse shadow-lg shadow-emerald-400/50" : credInvalid ? "bg-rose-400" : "bg-amber-400"}`} />
                <span className="text-[10px] text-slate-500">
                  {credOk ? `${h1Me!.username} · ${h1Me!.programs} prog` : credInvalid ? "token expirado" : h1MeError ?? "desconectado"}
                </span>
                <span className={`text-[9px] px-1.5 py-px rounded font-black tracking-wider ${
                  autoOn ? dryMode ? "bg-amber-500/15 text-amber-400 border border-amber-500/20" : "bg-emerald-500/15 text-emerald-400 border border-emerald-500/20"
                         : "bg-slate-500/10 text-slate-600 border border-slate-500/10"
                }`}>{autoOn ? dryMode ? "DRY" : "AUTO" : "OFF"}</span>
              </div>
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => { setShowDiscover(!showDiscover); if (!showDiscover && !searchResults) doSearch(); }}
              className={`px-3 py-1.5 text-[10px] font-bold rounded-lg border transition-all ${
                showDiscover ? "bg-cyan-500/15 border-cyan-500/30 text-cyan-300 shadow-lg shadow-cyan-500/10" : "bg-white/[0.02] border-white/8 text-slate-500 hover:text-white hover:border-white/15"
              }`}
            >🔍 Descobrir</button>
            <button onClick={refreshAll} disabled={loading}
              className="px-3 py-1.5 text-[10px] font-bold rounded-lg bg-white/[0.02] border border-white/8 text-slate-500 hover:text-white hover:border-white/15 transition-all disabled:opacity-30">
              {loading ? "◌" : "↻"} Sync
            </button>
          </div>
        </div>

        {/* ─── CREDENTIAL ALERT ─── */}
        {!credOk && (
          <div className={`flex items-center gap-3 px-4 py-2.5 rounded-lg border ${
            credInvalid ? "bg-rose-950/40 border-rose-500/20" : "bg-amber-950/30 border-amber-500/15"
          }`}>
            <span className="text-sm">{credInvalid ? "🔑" : "⚠"}</span>
            <div className="flex-1 text-xs">
              <span className={credInvalid ? "text-rose-300" : "text-amber-300"}>
                {credInvalid ? "Token expirado" : "Credenciais H1 ausentes"}
              </span>
              <span className="text-slate-600 ml-2">
                → <a href="https://hackerone.com/settings/api_token" target="_blank" rel="noopener noreferrer" className={`underline ${credInvalid ? "text-rose-400/70" : "text-amber-400/70"}`}>hackerone.com/settings/api_token</a> → atualizar .env
              </span>
            </div>
          </div>
        )}

        {/* ─── STATS ROW ─── */}
        <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
          {([
            { v: reportStats?.total ?? 0, l: "Vulns", c: "from-cyan-500/20 to-cyan-500/5", tc: "text-cyan-400", bc: "border-cyan-500/15" },
            { v: reportStats?.draft ?? 0, l: "Drafts", c: "from-violet-500/20 to-violet-500/5", tc: "text-violet-400", bc: "border-violet-500/15" },
            { v: h1Queue.length, l: "Na Fila", c: "from-amber-500/20 to-amber-500/5", tc: "text-amber-400", bc: "border-amber-500/15" },
            { v: h1Stats?.successful ?? 0, l: "Enviados", c: "from-emerald-500/20 to-emerald-500/5", tc: "text-emerald-400", bc: "border-emerald-500/15" },
            { v: h1Stats?.failed ?? 0, l: "Falhas", c: "from-rose-500/20 to-rose-500/5", tc: "text-rose-400", bc: "border-rose-500/15" },
            { v: h1Stats?.total_submissions ?? 0, l: "Total", c: "from-slate-500/15 to-slate-500/5", tc: "text-slate-300", bc: "border-slate-500/10" },
          ] as const).map((s, i) => (
            <div key={i} className={`rounded-lg border ${s.bc} bg-gradient-to-b ${s.c} p-3 text-center`}>
              <div className={`text-2xl font-black tabular-nums ${s.tc}`}>{s.v}</div>
              <div className="text-[9px] text-slate-500 font-bold uppercase tracking-widest mt-0.5">{s.l}</div>
            </div>
          ))}
        </div>

        {/* ─── ACTION BAR ─── */}
        <div className="flex gap-2 flex-wrap">
          <button onClick={doGenerate} disabled={actionLoading}
            className="flex-1 min-w-[140px] px-4 py-2.5 text-[11px] font-bold rounded-lg bg-gradient-to-b from-cyan-500/10 to-cyan-500/[0.03] border border-cyan-500/20 text-cyan-300 hover:from-cyan-500/20 hover:to-cyan-500/10 transition-all disabled:opacity-30 shadow-lg shadow-cyan-500/5">
            {actionLoading ? "◌" : "⚡"} Gerar Reports
          </button>
          <button onClick={doDryRun} disabled={actionLoading}
            className="flex-1 min-w-[120px] px-4 py-2.5 text-[11px] font-bold rounded-lg bg-gradient-to-b from-amber-500/10 to-amber-500/[0.03] border border-amber-500/20 text-amber-300 hover:from-amber-500/20 hover:to-amber-500/10 transition-all disabled:opacity-30 shadow-lg shadow-amber-500/5">
            {actionLoading ? "◌" : "👁"} Dry Run
          </button>
          <button onClick={doBatchSubmit} disabled={actionLoading || !credOk}
            className="flex-1 min-w-[120px] px-4 py-2.5 text-[11px] font-bold rounded-lg bg-gradient-to-b from-emerald-500/10 to-emerald-500/[0.03] border border-emerald-500/20 text-emerald-300 hover:from-emerald-500/20 hover:to-emerald-500/10 transition-all disabled:opacity-30 shadow-lg shadow-emerald-500/5">
            {actionLoading ? "◌" : "📤"} Enviar Batch
          </button>
          <button onClick={doFullCycle} disabled={actionLoading}
            className="flex-1 min-w-[140px] px-4 py-2.5 text-[11px] font-bold rounded-lg bg-gradient-to-b from-violet-500/15 to-violet-500/[0.03] border border-violet-500/25 text-violet-300 hover:from-violet-500/25 hover:to-violet-500/10 transition-all disabled:opacity-30 shadow-lg shadow-violet-500/5">
            {actionLoading ? "◌" : "▶"} Ciclo Completo
          </button>
        </div>

        {/* ─── LOADING ─── */}
        {loading && (
          <div className="flex items-center justify-center gap-3 py-8">
            <div className="w-5 h-5 border-2 border-violet-500/30 border-t-violet-400 rounded-full animate-spin" />
            <span className="text-xs text-slate-500">Carregando...</span>
          </div>
        )}

        {/* ─── QUEUE + SUBMITTED ─── */}
        {!loading && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

            {/* QUEUE */}
            <div className="rounded-xl border border-amber-500/10 bg-gradient-to-b from-amber-500/[0.03] to-transparent overflow-hidden">
              <div className="px-4 py-3 border-b border-amber-500/10 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400 shadow-sm shadow-amber-400/50" />
                  <span className="text-[11px] font-bold text-amber-300 uppercase tracking-wider">Fila de Envio</span>
                  <span className="text-[10px] bg-amber-500/15 text-amber-400 px-1.5 rounded font-bold">{h1Queue.length}</span>
                </div>
              </div>
              {h1Queue.length === 0 && localReports.length === 0 ? (
                <div className="px-4 py-8 text-center">
                  <div className="text-slate-600 text-xs">Nenhum report na fila</div>
                </div>
              ) : (
                <div className="divide-y divide-white/[0.03] max-h-[380px] overflow-y-auto">
                  {h1Queue.map(r => (
                    <div key={r.id} className="px-4 py-2.5 hover:bg-white/[0.02] transition-colors">
                      <div className="flex items-center gap-2.5">
                        <Sev s={r.severity} />
                        <div className="min-w-0 flex-1">
                          <div className="text-xs text-white/90 font-medium truncate">{r.title}</div>
                          <div className="text-[10px] text-slate-600 font-mono mt-px">{r.ip} · {r.vulnerability_count} vuln{r.vulnerability_count !== 1 ? "s" : ""}</div>
                        </div>
                        <span className="text-[9px] text-amber-500/50 font-mono">#{r.id.slice(-6)}</span>
                      </div>
                    </div>
                  ))}
                  {localReports.filter(r => !h1Queue.find(q => q.id === r.id)).slice(0, 20).map(r => (
                    <div key={r.id} className="px-4 py-2.5 hover:bg-white/[0.02] transition-colors opacity-60">
                      <div className="flex items-center gap-2.5">
                        <Sev s={r.severity} />
                        <div className="min-w-0 flex-1">
                          <div className="text-xs text-white/70 font-medium truncate">{r.title}</div>
                          <div className="text-[10px] text-slate-600 font-mono mt-px">
                            {r.ip} · {r.vulnerability_count}v
                            {r.auto_submit_eligible && <span className="text-emerald-500 ml-1">✓ elegível</span>}
                          </div>
                        </div>
                        <span className={`text-[9px] px-1.5 py-px rounded font-bold ${
                          r.status === "draft" ? "bg-violet-500/15 text-violet-400" : r.status === "submitted" ? "bg-emerald-500/15 text-emerald-400" : "bg-rose-500/15 text-rose-400"
                        }`}>{r.status}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* SUBMITTED */}
            <div className="rounded-xl border border-emerald-500/10 bg-gradient-to-b from-emerald-500/[0.03] to-transparent overflow-hidden">
              <div className="px-4 py-3 border-b border-emerald-500/10 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-sm shadow-emerald-400/50" />
                  <span className="text-[11px] font-bold text-emerald-300 uppercase tracking-wider">Enviados</span>
                  <span className="text-[10px] bg-emerald-500/15 text-emerald-400 px-1.5 rounded font-bold">{submittedReports.length}</span>
                </div>
                {submittedStats && (
                  <div className="flex gap-1.5 text-[9px]">
                    {submittedStats.submitted > 0 && <span className="bg-emerald-500/10 text-emerald-400 px-1.5 py-px rounded font-bold">✓ {submittedStats.submitted}</span>}
                    {submittedStats.pending > 0 && <span className="bg-amber-500/10 text-amber-400 px-1.5 py-px rounded font-bold">◌ {submittedStats.pending}</span>}
                    {submittedStats.errors > 0 && <span className="bg-rose-500/10 text-rose-400 px-1.5 py-px rounded font-bold">✕ {submittedStats.errors}</span>}
                  </div>
                )}
              </div>
              {submittedReports.length === 0 ? (
                <div className="px-4 py-8 text-center">
                  <div className="text-slate-600 text-xs">Nenhum report enviado ainda</div>
                </div>
              ) : (
                <div className="divide-y divide-white/[0.03] max-h-[380px] overflow-y-auto">
                  {submittedReports.map(r => (
                    <div key={r.id} className="px-4 py-2.5 hover:bg-white/[0.02] transition-colors">
                      <div className="flex items-center gap-2.5">
                        <Sev s={r.severity} />
                        <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${
                          r.status === "submitted" ? "bg-emerald-400" : r.status === "pending" ? "bg-amber-400 animate-pulse" : "bg-rose-400"
                        }`} />
                        <div className="min-w-0 flex-1">
                          <div className="text-xs text-white/90 font-medium truncate">{r.title}</div>
                          <div className="text-[10px] text-slate-600 mt-px flex items-center gap-1.5 flex-wrap">
                            <span className="font-mono">{r.domain}</span>
                            {r.program_name && <><span className="text-slate-700">·</span><span>{r.program_name}</span></>}
                            {r.findings_count > 0 && <><span className="text-slate-700">·</span><span>{r.findings_count}f</span></>}
                            {r.timestamp && <><span className="text-slate-700">·</span><span>{new Date(r.timestamp).toLocaleDateString("pt-BR")}</span></>}
                          </div>
                        </div>
                        <div className="flex items-center gap-1.5 flex-shrink-0">
                          <span className={`text-[9px] px-1.5 py-px rounded font-bold ${
                            r.status === "submitted" ? "bg-emerald-500/15 text-emerald-400" : r.status === "pending" ? "bg-amber-500/15 text-amber-400" : "bg-rose-500/15 text-rose-400"
                          }`}>{r.status}</span>
                          {r.h1_report_url && (
                            <a href={r.h1_report_url} target="_blank" rel="noopener noreferrer"
                              className="text-[10px] text-violet-400 hover:text-violet-300">↗</a>
                          )}
                        </div>
                      </div>
                      {r.error && (
                        <div className="mt-1.5 text-[9px] text-rose-400/70 bg-rose-500/5 border border-rose-500/10 rounded px-2 py-1">
                          {r.error}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ─── SEVERITY BREAKDOWN ─── */}
        {!loading && submittedStats && Object.keys(submittedStats.by_severity).length > 0 && (
          <div className="flex items-center gap-3 px-4 py-2.5 rounded-lg border border-white/[0.04] bg-white/[0.01]">
            <span className="text-[9px] text-slate-600 font-bold uppercase tracking-widest">Severidades</span>
            <div className="flex gap-2 flex-wrap">
              {Object.entries(submittedStats.by_severity)
                .sort((a, b) => { const o: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }; return (o[a[0]] ?? 9) - (o[b[0]] ?? 9); })
                .map(([sev, count]) => (
                  <div key={sev} className="flex items-center gap-1">
                    <Sev s={sev} />
                    <span className="text-xs font-black text-white/80 tabular-nums">{count}</span>
                  </div>
                ))}
            </div>
          </div>
        )}

        {/* ═════════════════════════════════════════
           DISCOVER PANEL
           ═════════════════════════════════════════ */}
        {showDiscover && (
          <div className="rounded-xl border border-cyan-500/15 bg-gradient-to-b from-cyan-500/[0.04] to-transparent overflow-hidden">
            <div className="px-4 py-3 border-b border-cyan-500/10 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 shadow-sm shadow-cyan-400/50" />
                <span className="text-[11px] font-bold text-cyan-300 uppercase tracking-wider">Descobrir Programas</span>
                {searchResults && <span className="text-[10px] bg-cyan-500/15 text-cyan-400 px-1.5 rounded font-bold">{searchResults.total}</span>}
              </div>
              {searchResults && (
                <div className="flex gap-1.5 text-[9px]">
                  {searchResults.summary.with_bounty > 0 && <span className="bg-emerald-500/10 text-emerald-400 px-1.5 py-px rounded font-bold">💰 {searchResults.summary.with_bounty}</span>}
                  {searchResults.summary.with_wildcards > 0 && <span className="bg-cyan-500/10 text-cyan-400 px-1.5 py-px rounded font-bold">🌐 {searchResults.summary.with_wildcards}</span>}
                </div>
              )}
            </div>

            {/* Search controls */}
            <div className="px-4 py-3 border-b border-cyan-500/[0.06] space-y-2">
              <div className="flex gap-2">
                <input
                  type="text"
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && doSearch()}
                  placeholder="Nome, domínio, handle..."
                  className="flex-1 px-3 py-2 text-xs rounded-lg bg-black/60 border border-white/8 text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/30 focus:shadow-lg focus:shadow-cyan-500/5 transition-all"
                />
                <button onClick={() => doSearch()} disabled={searchLoading}
                  className="px-4 py-2 text-[10px] font-bold rounded-lg bg-cyan-500/15 border border-cyan-500/25 text-cyan-300 hover:bg-cyan-500/25 transition-all disabled:opacity-30 shadow-lg shadow-cyan-500/5">
                  {searchLoading ? "◌" : "→"}
                </button>
              </div>
              <div className="flex flex-wrap gap-1.5">
                <select value={searchPlatform} onChange={e => setSearchPlatform(e.target.value)}
                  className="px-2 py-1 text-[10px] rounded bg-black/50 border border-white/8 text-slate-300 focus:outline-none">
                  <option value="">Plataforma</option>
                  <option value="hackerone">HackerOne</option>
                  <option value="bugcrowd">Bugcrowd</option>
                  <option value="intigriti">Intigriti</option>
                  <option value="yeswehack">YWH</option>
                </select>
                <select value={searchSortBy} onChange={e => setSearchSortBy(e.target.value as "newest" | "name" | "scope_size")}
                  className="px-2 py-1 text-[10px] rounded bg-black/50 border border-white/8 text-slate-300 focus:outline-none">
                  <option value="scope_size">Maior scope</option>
                  <option value="newest">Recentes</option>
                  <option value="name">A-Z</option>
                </select>
                <button onClick={() => setSearchBountyOnly(!searchBountyOnly)}
                  className={`px-2 py-1 text-[10px] rounded border font-bold transition-all ${
                    searchBountyOnly ? "bg-emerald-500/15 border-emerald-500/25 text-emerald-300" : "bg-black/30 border-white/8 text-slate-500 hover:text-white"
                  }`}>💰 Bounty</button>
                <button onClick={() => setSearchHasWildcards(!searchHasWildcards)}
                  className={`px-2 py-1 text-[10px] rounded border font-bold transition-all ${
                    searchHasWildcards ? "bg-cyan-500/15 border-cyan-500/25 text-cyan-300" : "bg-black/30 border-white/8 text-slate-500 hover:text-white"
                  }`}>🌐 Wildcard</button>
                {(searchQuery || searchPlatform || searchBountyOnly || searchHasWildcards) && (
                  <button onClick={() => { setSearchQuery(""); setSearchPlatform(""); setSearchBountyOnly(false); setSearchHasWildcards(false); doSearch({ q: "", platform: "", bounty_only: false, has_wildcards: false }); }}
                    className="px-2 py-1 text-[10px] rounded bg-rose-500/10 border border-rose-500/15 text-rose-400 hover:bg-rose-500/20 transition-all font-bold">
                    ✕
                  </button>
                )}
              </div>
            </div>

            {/* Results */}
            {searchLoading ? (
              <div className="py-8 text-center">
                <div className="w-5 h-5 border-2 border-cyan-500/30 border-t-cyan-400 rounded-full animate-spin mx-auto mb-2" />
                <div className="text-[10px] text-slate-600">Buscando...</div>
              </div>
            ) : searchResults && searchResults.results.length === 0 ? (
              <div className="py-8 text-center text-xs text-slate-600">Nenhum programa encontrado</div>
            ) : searchResults ? (
              <div className="divide-y divide-white/[0.03] max-h-[500px] overflow-y-auto">
                {searchResults.results.map(prog => {
                  const open = expandedProgram === prog.id;
                  const pc: Record<string, string> = {
                    hackerone: "text-violet-400", bugcrowd: "text-orange-400",
                    intigriti: "text-blue-400", yeswehack: "text-emerald-400",
                  };
                  return (
                    <div key={prog.id} className={`transition-all ${open ? "bg-cyan-500/[0.03]" : "hover:bg-white/[0.015]"}`}>
                      <div className="px-4 py-2.5 cursor-pointer" onClick={() => setExpandedProgram(open ? null : prog.id)}>
                        <div className="flex items-center gap-2.5">
                          <span className={`text-[9px] font-black uppercase tracking-wider w-[52px] text-center ${pc[prog.platform] ?? "text-slate-500"}`}>
                            {prog.platform === "yeswehack" ? "YWH" : prog.platform === "hackerone" ? "H1" : prog.platform === "bugcrowd" ? "BC" : "INT"}
                          </span>
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-1.5">
                              <span className="text-xs text-white/90 font-medium truncate">{prog.name}</span>
                              {prog.has_bounty && <span className="text-[8px] text-emerald-400 font-black">$</span>}
                              {prog.scope_changed && <span className="text-[8px] text-amber-400 font-black">NEW</span>}
                            </div>
                            <div className="flex items-center gap-1.5 mt-px text-[10px] text-slate-600">
                              <span>{prog.scope_count} alvo{prog.scope_count !== 1 ? "s" : ""}</span>
                              {prog.wildcard_count > 0 && <span className="text-cyan-500">{prog.wildcard_count}wc</span>}
                              {prog.scope_preview.slice(0, 2).map((s, i) => (
                                <span key={i} className="font-mono text-slate-700 truncate max-w-[120px]">{s}</span>
                              ))}
                            </div>
                          </div>
                          <span className="text-[10px] text-slate-700">{open ? "▲" : "▼"}</span>
                        </div>
                      </div>
                      {open && (
                        <div className="px-4 pb-3 pt-0.5 space-y-2">
                          <div className="flex flex-wrap gap-1">
                            {prog.in_scope.map((s, i) => {
                              const wc = s.startsWith("*.") || s.startsWith("*");
                              return (
                                <span key={i} className={`text-[9px] font-mono px-1.5 py-px rounded border ${
                                  wc ? "bg-cyan-500/10 text-cyan-300/80 border-cyan-500/15" : "bg-white/[0.03] text-slate-400 border-white/[0.04]"
                                }`}>{s}</span>
                              );
                            })}
                          </div>
                          {prog.out_of_scope.length > 0 && (
                            <div className="flex flex-wrap gap-1">
                              <span className="text-[8px] text-rose-500/50 font-bold uppercase">Out:</span>
                              {prog.out_of_scope.slice(0, 10).map((s, i) => (
                                <span key={i} className="text-[9px] font-mono px-1.5 py-px rounded bg-rose-500/5 text-rose-400/50 border border-rose-500/8">{s}</span>
                              ))}
                            </div>
                          )}
                          <div className="flex items-center justify-between pt-1">
                            <div className="flex gap-2 text-[9px] text-slate-600">
                              {prog.asset_types.length > 0 && <span>{prog.asset_types.join(" · ")}</span>}
                              {prog.bounty_max != null && prog.bounty_max > 0 && <span className="text-emerald-500">max ${prog.bounty_max.toLocaleString()}</span>}
                            </div>
                            {prog.url && (
                              <a href={prog.url} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()}
                                className="text-[10px] text-cyan-400 hover:text-cyan-300 font-bold">
                                Abrir ↗
                              </a>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : null}
          </div>
        )}

      </div>

      {/* Slide-in animation */}
      <style jsx global>{`
        @keyframes slideIn {
          from { opacity: 0; transform: translateX(20px); }
          to { opacity: 1; transform: translateX(0); }
        }
      `}</style>
    </div>
  );
}
