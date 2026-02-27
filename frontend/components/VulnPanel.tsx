"use client";

import { Fragment, useEffect, useState, useCallback } from "react";
import Modal from "@/components/Modal";
import {
  fetchVulnResults,
  fetchVulnStats,
  triggerBatchVulnScan,
  type VulnResult,
  type VulnStats,
} from "@/lib/api";

const REFRESH_MS = 8_000;

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/20",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  medium: "bg-amber-500/10 text-amber-400 border-amber-500/20",
  low: "bg-sky-500/10 text-sky-400 border-sky-500/20",
  info: "bg-slate-500/10 text-slate-400 border-slate-500/20",
};

function SevBadge({ severity }: { severity: string }) {
  return (
    <span className={`inline-flex items-center rounded-md border px-3 py-1 text-sm font-bold uppercase ${SEV_COLORS[severity] ?? SEV_COLORS.info}`}>
      {severity}
    </span>
  );
}

function ToolBadge({ tool }: { tool: string }) {
  return (
    <span className={`inline-flex items-center rounded-md border px-3 py-1 text-sm font-medium ${
      tool === "nuclei" ? "bg-violet-500/10 text-violet-400 border-violet-500/20" : "bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
    }`}>
      {tool}
    </span>
  );
}

function VulnDetails({ v }: { v: VulnResult }) {
  return (
    <div className="bg-[var(--background)]/50 px-4 py-3 border-t border-[var(--border)]">
      <div className="grid gap-3 sm:grid-cols-2 text-base">
        <div>
          <div className="text-sm font-medium text-[var(--muted)] uppercase mb-1">Descricao</div>
          <p className="text-[var(--foreground)]/80">{v.description || "Sem descricao."}</p>
        </div>
        <div>
          <div className="text-sm font-medium text-[var(--muted)] uppercase mb-1">Matched At</div>
          <p className="font-mono text-[var(--foreground)]/80 break-all">{v.matched_at || "-"}</p>
        </div>
        {v.proof && (
          <div className="sm:col-span-2">
            <div className="text-sm font-medium text-[var(--muted)] uppercase mb-1">Prova</div>
            <pre className="rounded-lg bg-[var(--card)] border border-[var(--border)] p-3 text-base text-[var(--foreground)]/70 whitespace-pre-wrap break-all max-h-40 overflow-auto">
              {typeof v.proof === "string" ? v.proof : JSON.stringify(v.proof, null, 2)}
            </pre>
          </div>
        )}
        {v.references && v.references.length > 0 && (
          <div className="sm:col-span-2">
            <div className="text-sm font-medium text-[var(--muted)] uppercase mb-1">Referencias</div>
            <div className="flex flex-wrap gap-2">
              {v.references.map((ref, i) => (
                <a key={i} href={ref} target="_blank" rel="noopener noreferrer" className="text-[var(--accent-light)] hover:underline text-base break-all">{ref}</a>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function VulnPanel() {
  const [vulns, setVulns] = useState<VulnResult[]>([]);
  const [stats, setStats] = useState<VulnStats | null>(null);
  const [filter, setFilter] = useState<string>("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [detailVuln, setDetailVuln] = useState<VulnResult | null>(null);

  const load = useCallback(async () => {
    try {
      const [v, s] = await Promise.all([fetchVulnResults(50, filter || undefined), fetchVulnStats()]);
      setVulns(Array.isArray(v) ? v : []);
      setStats(s);
    } catch (e) { console.error("VulnPanel load:", e); }
  }, [filter]);

  useEffect(() => {
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  const handleBatchScan = async () => {
    setScanning(true);
    try { await triggerBatchVulnScan(70); } catch { /* ignore */ }
    setTimeout(() => setScanning(false), 2000);
  };

  const toggle = (id: string) => setExpandedId(prev => prev === id ? null : id);
  const sev = stats?.by_severity;
  const scanner = stats?.scanner;

  return (
    <div>
      {/* Severity cards */}
      <div className="grid grid-cols-3 gap-4 mb-4">
        {[
          { label: "Critical", value: sev?.critical ?? 0, color: "text-red-400" },
          { label: "High", value: sev?.high ?? 0, color: "text-orange-400" },
          { label: "Medium", value: sev?.medium ?? 0, color: "text-amber-400" },
        ].map(({ label, value, color }) => (
          <div key={label} className="rounded-xl border border-[var(--border)] bg-[var(--card)] p-5">
            <div className={`text-4xl font-bold tabular-nums ${value > 0 ? color : "text-[var(--muted)]"}`}>{value}</div>
            <div className="text-base text-[var(--muted)] mt-1">{label}</div>
          </div>
        ))}
      </div>

      {/* Controls */}
      <div className="flex items-center gap-2 mb-4 flex-wrap">
        {scanner && (
          <div className="rounded-xl border border-[var(--border)] bg-[var(--card)] px-5 py-2.5 text-base flex items-center gap-3">
            <span className="text-[var(--muted)]">Fila</span>
            <span className="font-bold text-[var(--foreground)]">{scanner.queue_size}</span>
            <span className="text-[var(--muted)]">OK</span>
            <span className="font-bold text-emerald-400">{scanner.completed}</span>
          </div>
        )}
        <button onClick={handleBatchScan} disabled={scanning}
          className="rounded-xl bg-[var(--accent)]/10 hover:bg-[var(--accent)]/15 border border-[var(--accent)]/20 px-5 py-2.5 text-base font-medium text-[var(--accent-light)] disabled:opacity-40 transition-all">
          {scanning ? "Enfileirando..." : "Scan alto risco"}
        </button>
      </div>

      {/* Filter */}
      <div className="flex gap-2 mb-4 overflow-x-auto hide-scrollbar pb-1">
        {["", "critical", "high", "medium", "low", "info"].map(s => (
          <button key={s} onClick={() => setFilter(s)}
            className={`shrink-0 rounded-lg px-5 py-2.5 text-base font-medium transition-all border ${
              filter === s
                ? "border-[var(--accent)]/30 bg-[var(--accent)]/10 text-[var(--accent-light)]"
                : "border-[var(--border)] bg-[var(--card)] text-[var(--muted)] hover:text-[var(--foreground)]"
            }`}>
            {s || "Todas"}
          </button>
        ))}
      </div>

      {/* Results */}
      {vulns.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-[var(--border)] bg-[var(--card)]/50 py-8 text-center text-lg text-[var(--muted)]">
          {scanner?.completed === 0 ? "Nenhum scan realizado ainda." : "Nenhuma vulnerabilidade com esse filtro."}
        </div>
      ) : (
        <div className="space-y-2">
          {vulns.map(v => (
            <div key={v.id} className="rounded-xl border border-[var(--border)] bg-[var(--card)]/60 overflow-hidden hover:bg-[var(--card)] transition-all">
              <div className="px-5 py-4 cursor-pointer" onClick={() => toggle(v.id)}>
                <div className="flex items-center justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[var(--accent-light)] text-base">{v.ip}</span>
                      {v.port && <span className="text-sm text-[var(--muted)]">:{v.port}</span>}
                      <ToolBadge tool={v.tool} />
                    </div>
                    <div className="text-base text-[var(--muted)] truncate mt-0.5">{v.name}</div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={(e) => { e.stopPropagation(); setDetailVuln(v); }}
                      className="text-sm text-[var(--accent-light)] hover:underline"
                    >
                      Detalhes
                    </button>
                    <SevBadge severity={v.severity} />
                    <span className="text-sm text-[var(--muted)] tabular-nums">
                      {v.timestamp ? new Date(v.timestamp).toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit" }) : ""}
                    </span>
                  </div>
                </div>
              </div>
              {expandedId === v.id && <VulnDetails v={v} />}
            </div>
          ))}
        </div>
      )}

      {/* Vuln Detail Modal */}
      <Modal
        open={!!detailVuln}
        onClose={() => setDetailVuln(null)}
        title={detailVuln ? `Vulnerabilidade: ${detailVuln.name}` : ""}
        maxWidth="max-w-3xl"
      >
        {detailVuln && (
          <div className="space-y-5">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-5 text-center">
                <SevBadge severity={detailVuln.severity} />
                <div className="text-base text-[var(--muted)] mt-2">Severidade</div>
              </div>
              <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-5 text-center">
                <div className="text-2xl font-mono font-bold text-[var(--accent-light)]">{detailVuln.ip}</div>
                <div className="text-base text-[var(--muted)] mt-1">IP</div>
              </div>
              <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-5 text-center">
                <div className="text-2xl font-bold text-[var(--foreground)]">{detailVuln.port || "-"}</div>
                <div className="text-base text-[var(--muted)] mt-1">Porta</div>
              </div>
              <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-5 text-center">
                <ToolBadge tool={detailVuln.tool} />
                <div className="text-base text-[var(--muted)] mt-2">Ferramenta</div>
              </div>
            </div>

            <div className="space-y-3">
              <div>
                <h3 className="text-base font-semibold text-[var(--muted)] uppercase mb-1">Nome</h3>
                <p className="text-lg text-[var(--foreground)]">{detailVuln.name}</p>
              </div>

              <div>
                <h3 className="text-base font-semibold text-[var(--muted)] uppercase mb-1">Descricao</h3>
                <p className="text-base text-[var(--foreground)]/80">{detailVuln.description || "Sem descricao."}</p>
              </div>

              {detailVuln.matched_at && (
                <div>
                  <h3 className="text-base font-semibold text-[var(--muted)] uppercase mb-1">Matched At</h3>
                  <p className="text-base font-mono text-[var(--foreground)]/80 break-all">{detailVuln.matched_at}</p>
                </div>
              )}

              {detailVuln.proof && (
                <div>
                  <h3 className="text-base font-semibold text-[var(--muted)] uppercase mb-1">Prova</h3>
                  <pre className="rounded-lg bg-[var(--background)] border border-[var(--border)] p-4 text-base text-[var(--foreground)]/70 whitespace-pre-wrap break-all max-h-48 overflow-auto">
                    {typeof detailVuln.proof === "string" ? detailVuln.proof : JSON.stringify(detailVuln.proof, null, 2)}
                  </pre>
                </div>
              )}

              {detailVuln.references && detailVuln.references.length > 0 && (
                <div>
                  <h3 className="text-base font-semibold text-[var(--muted)] uppercase mb-1">Referências</h3>
                  <div className="space-y-1">
                    {detailVuln.references.map((ref, i) => (
                      <a key={i} href={ref} target="_blank" rel="noopener noreferrer" className="block text-base text-[var(--accent-light)] hover:underline break-all">
                        {ref}
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {detailVuln.timestamp && (
                <div className="flex items-center gap-3 pt-2 border-t border-[var(--border)]">
                  <span className="text-base text-[var(--muted)]">Detectado em:</span>
                  <span className="text-base text-[var(--foreground)]">{new Date(detailVuln.timestamp).toLocaleString("pt-BR")}</span>
                </div>
              )}
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
