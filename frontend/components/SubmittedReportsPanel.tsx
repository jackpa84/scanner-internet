"use client";

import { useEffect, useState, useCallback } from "react";
import Modal from "@/components/Modal";
import {
  fetchSubmittedReports,
  fetchSubmittedReportsStats,
  type SubmittedReport,
  type SubmittedReportsStats,
} from "@/lib/api";

const REFRESH_MS = 15_000;

const STATUS_STYLE: Record<string, { bg: string; text: string; label: string }> = {
  submitted: { bg: "bg-emerald-500/15", text: "text-emerald-400", label: "Enviado" },
  error: { bg: "bg-red-500/15", text: "text-red-400", label: "Erro" },
  pending: { bg: "bg-amber-500/15", text: "text-amber-400", label: "Pendente" },
};

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-amber-400",
  low: "text-sky-400",
  info: "text-slate-400",
};

export default function SubmittedReportsPanel() {
  const [reports, setReports] = useState<SubmittedReport[]>([]);
  const [stats, setStats] = useState<SubmittedReportsStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [detailReport, setDetailReport] = useState<SubmittedReport | null>(null);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const [r, s] = await Promise.all([
        fetchSubmittedReports(30),
        fetchSubmittedReportsStats(),
      ]);
      setReports(Array.isArray(r) ? r : []);
      setStats(s);
    } catch (e) {
      console.error("SubmittedReportsPanel:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  const total = stats?.total ?? 0;
  const submitted = stats?.submitted ?? 0;
  const errors = stats?.errors ?? 0;
  const pending = stats?.pending ?? 0;
  const bySev = stats?.by_severity ?? {};

  return (
    <div className="rounded-2xl border border-[var(--border)] bg-[var(--card)] p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/15 text-emerald-400">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
            </svg>
          </div>
          <h2 className="text-base font-bold text-[var(--foreground)]">Reports H1</h2>
        </div>
        <span className="rounded-full bg-emerald-500/15 text-emerald-400 px-2.5 py-1 text-base font-extrabold tabular-nums">
          {total}
        </span>
      </div>

      {/* Counters */}
      <div className="grid grid-cols-3 gap-2 mb-3">
        <div className="rounded-lg bg-emerald-500/10 border border-emerald-500/20 p-2.5 text-center">
          <div className="text-2xl font-extrabold text-emerald-400 tabular-nums leading-none">{submitted}</div>
          <div className="text-xs text-[var(--muted)] mt-1">Enviados</div>
        </div>
        <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 p-2.5 text-center">
          <div className="text-2xl font-extrabold text-amber-400 tabular-nums leading-none">{pending}</div>
          <div className="text-xs text-[var(--muted)] mt-1">Pendentes</div>
        </div>
        <div className="rounded-lg bg-red-500/10 border border-red-500/20 p-2.5 text-center">
          <div className="text-2xl font-extrabold text-red-400 tabular-nums leading-none">{errors}</div>
          <div className="text-xs text-[var(--muted)] mt-1">Erros</div>
        </div>
      </div>

      {/* Severity breakdown */}
      {Object.keys(bySev).length > 0 && (
        <div className="flex flex-wrap gap-1.5 mb-3">
          {Object.entries(bySev).sort(([a], [b]) => ({"critical":0,"high":1,"medium":2,"low":3,"info":4}[a] ?? 5) - ({"critical":0,"high":1,"medium":2,"low":3,"info":4}[b] ?? 5)).map(([sev, count]) => (
            <span key={sev} className={`rounded bg-black/20 border border-white/5 px-2 py-1 text-xs font-bold uppercase ${SEV_COLORS[sev] ?? "text-[var(--muted)]"}`}>
              {count} {sev}
            </span>
          ))}
        </div>
      )}

      {/* Progress bar */}
      {total > 0 && (
        <div className="flex rounded-full overflow-hidden h-2 mb-3">
          {submitted > 0 && <div style={{ width: `${(submitted / total) * 100}%`, background: "#10b981" }} />}
          {pending > 0 && <div style={{ width: `${(pending / total) * 100}%`, background: "#f59e0b" }} />}
          {errors > 0 && <div style={{ width: `${(errors / total) * 100}%`, background: "#ef4444" }} />}
        </div>
      )}

      {/* List */}
      {reports.length === 0 ? (
        <div className="flex items-center gap-3 py-4">
          <svg className="w-8 h-8 text-[var(--muted)]" fill="none" viewBox="0 0 24 24" strokeWidth={1} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div>
            <p className="text-base text-[var(--muted)]">Nenhum report submetido</p>
            <p className="text-sm text-[var(--muted)]/60">Reports serao enviados automaticamente ao HackerOne</p>
          </div>
        </div>
      ) : (
        <div className="space-y-1.5 max-h-[40vh] overflow-y-auto hide-scrollbar">
          {reports.map((r) => {
            const st = STATUS_STYLE[r.status] ?? STATUS_STYLE.pending;
            return (
              <button
                key={r.id}
                type="button"
                onClick={() => setDetailReport(r)}
                className="w-full rounded-xl border border-[var(--border)] bg-[var(--background)] p-3 text-left hover:bg-[var(--card-hover)] transition-all group"
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="truncate text-base font-semibold text-[var(--foreground)]">{r.program_name}</span>
                  <span className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-bold ${st.bg} ${st.text}`}>
                    {st.label}
                  </span>
                </div>
                <div className="text-sm text-emerald-300 font-mono truncate">{r.domain}</div>
                <div className="flex items-center gap-3 text-sm mt-1">
                  <span className={`font-semibold uppercase ${SEV_COLORS[r.severity] ?? "text-[var(--muted)]"}`}>{r.severity}</span>
                  <span className="text-[var(--muted)] tabular-nums">{r.findings_count} achados</span>
                  <span className="text-[var(--muted)] tabular-nums">{r.timestamp ? new Date(r.timestamp).toLocaleDateString("pt-BR") : ""}</span>
                  {r.h1_report_url && (
                    <a
                      href={r.h1_report_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={(e) => e.stopPropagation()}
                      className="ml-auto text-xs text-[var(--accent-light)] hover:underline"
                    >
                      H1 →
                    </a>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      )}

      {/* Detail Modal */}
      <Modal
        open={!!detailReport}
        onClose={() => setDetailReport(null)}
        title={detailReport ? `Report: ${detailReport.domain}` : ""}
        maxWidth="max-w-3xl"
      >
        {detailReport && (() => {
          const st = STATUS_STYLE[detailReport.status] ?? STATUS_STYLE.pending;
          return (
            <div className="space-y-5">
              {/* Status banner */}
              <div className={`rounded-xl ${st.bg} p-4 flex items-center justify-between`}>
                <div>
                  <span className={`text-lg font-bold ${st.text}`}>{st.label}</span>
                  {detailReport.h1_report_id && (
                    <span className="text-base text-[var(--muted)] ml-3">Report #{detailReport.h1_report_id}</span>
                  )}
                </div>
                {detailReport.h1_report_url && (
                  <a
                    href={detailReport.h1_report_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="rounded-lg bg-orange-500 hover:bg-orange-400 px-4 py-2 text-base font-bold text-white transition-all"
                  >
                    Abrir no HackerOne
                  </a>
                )}
              </div>

              {/* Metrics */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-4 text-center">
                  <div className={`text-2xl font-extrabold uppercase ${SEV_COLORS[detailReport.severity] ?? "text-[var(--muted)]"}`}>{detailReport.severity}</div>
                  <div className="text-sm text-[var(--muted)] mt-1">Severidade</div>
                </div>
                <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-4 text-center">
                  <div className="text-2xl font-extrabold text-amber-400 tabular-nums">{detailReport.findings_count}</div>
                  <div className="text-sm text-[var(--muted)] mt-1">Achados</div>
                </div>
                <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-4 text-center">
                  <div className="text-base font-bold text-[var(--foreground)]">{detailReport.program_name}</div>
                  <div className="text-sm text-[var(--muted)] mt-1">Programa</div>
                </div>
                <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-4 text-center">
                  <div className="text-base font-mono font-bold text-emerald-300">{detailReport.domain}</div>
                  <div className="text-sm text-[var(--muted)] mt-1">Target</div>
                </div>
              </div>

              {/* Info */}
              <div className="space-y-2">
                <div className="flex justify-between text-base">
                  <span className="text-[var(--muted)]">Título</span>
                  <span className="text-[var(--foreground)] font-medium text-right truncate ml-4">{detailReport.title}</span>
                </div>
                <div className="flex justify-between text-base">
                  <span className="text-[var(--muted)]">Data</span>
                  <span className="text-[var(--foreground)]">{detailReport.timestamp ? new Date(detailReport.timestamp).toLocaleString("pt-BR") : "–"}</span>
                </div>
                {detailReport.error && (
                  <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-3">
                    <span className="text-sm text-red-400">{detailReport.error}</span>
                  </div>
                )}
              </div>

              {/* Report body */}
              {detailReport.report_body && (
                <div>
                  <h3 className="text-base font-bold text-[var(--foreground)] mb-2">Report enviado</h3>
                  <pre className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-4 text-sm text-[var(--foreground)]/80 whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
                    {detailReport.report_body}
                  </pre>
                </div>
              )}
            </div>
          );
        })()}
      </Modal>
    </div>
  );
}
