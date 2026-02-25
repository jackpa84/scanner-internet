"use client";

import { Fragment, useEffect, useState, useCallback } from "react";
import {
  fetchVulnResults,
  fetchVulnStats,
  triggerBatchVulnScan,
  type VulnResult,
  type VulnStats,
} from "@/lib/api";

const REFRESH_MS = 8_000;

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-600/20 text-red-300 border-red-500/50",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/50",
  medium: "bg-amber-500/20 text-amber-300 border-amber-500/50",
  low: "bg-sky-500/20 text-sky-300 border-sky-500/50",
  info: "bg-slate-500/20 text-slate-300 border-slate-500/40",
};

function SevBadge({ severity }: { severity: string }) {
  const cls = SEV_COLORS[severity] ?? SEV_COLORS.info;
  return (
    <span className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[11px] font-bold uppercase ${cls}`}>
      {severity}
    </span>
  );
}

function ToolBadge({ tool }: { tool: string }) {
  const cls =
    tool === "nuclei"
      ? "bg-purple-500/15 text-purple-300 border-purple-500/30"
      : "bg-cyan-500/15 text-cyan-300 border-cyan-500/30";
  return (
    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold ${cls}`}>
      {tool}
    </span>
  );
}

export default function VulnPanel() {
  const [vulns, setVulns] = useState<VulnResult[]>([]);
  const [stats, setStats] = useState<VulnStats | null>(null);
  const [filter, setFilter] = useState<string>("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);

  const load = useCallback(async () => {
    try {
      const [v, s] = await Promise.all([
        fetchVulnResults(50, filter || undefined),
        fetchVulnStats(),
      ]);
      setVulns(Array.isArray(v) ? v : []);
      setStats(s);
    } catch (e) {
      console.error("VulnPanel load error:", e);
    }
  }, [filter]);

  useEffect(() => {
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  const handleBatchScan = async () => {
    setScanning(true);
    try {
      await triggerBatchVulnScan(70);
    } catch (e) {
      console.error("Batch scan error:", e);
    }
    setTimeout(() => setScanning(false), 2000);
  };

  const toggle = (id: string) => setExpandedId((prev) => (prev === id ? null : id));
  const sev = stats?.by_severity;
  const scanner = stats?.scanner;

  return (
    <div>
      {/* Stats cards */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6 mb-4">
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2">
          <div className="text-lg font-bold tabular-nums text-red-400">{sev?.critical ?? 0}</div>
          <div className="text-[10px] text-muted">Critical</div>
        </div>
        <div className="rounded-lg border border-orange-500/30 bg-orange-500/5 px-3 py-2">
          <div className="text-lg font-bold tabular-nums text-orange-400">{sev?.high ?? 0}</div>
          <div className="text-[10px] text-muted">High</div>
        </div>
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2">
          <div className="text-lg font-bold tabular-nums text-amber-400">{sev?.medium ?? 0}</div>
          <div className="text-[10px] text-muted">Medium</div>
        </div>
        <div className="rounded-lg border border-sky-500/30 bg-sky-500/5 px-3 py-2">
          <div className="text-lg font-bold tabular-nums text-sky-400">{sev?.low ?? 0}</div>
          <div className="text-[10px] text-muted">Low</div>
        </div>
        <div className="rounded-lg border border-border bg-card px-3 py-2">
          <div className="text-lg font-bold tabular-nums">{stats?.unique_ips_scanned ?? 0}</div>
          <div className="text-[10px] text-muted">IPs scaneados</div>
        </div>
        <div className="rounded-lg border border-border bg-card px-3 py-2">
          <div className="text-lg font-bold tabular-nums">{stats?.total_vulns ?? 0}</div>
          <div className="text-[10px] text-muted">Total achados</div>
        </div>
      </div>

      {/* Scanner status + controls */}
      {scanner && (
        <div className="flex flex-wrap items-center gap-3 mb-4 text-xs">
          <div className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-1.5">
            <span className="text-muted">Fila:</span>
            <span className="font-bold">{scanner.queue_size}</span>
            <span className="text-muted ml-2">Escaneando:</span>
            <span className="font-bold text-amber-400">{scanner.scanning}</span>
            <span className="text-muted ml-2">Completos:</span>
            <span className="font-bold text-emerald-400">{scanner.completed}</span>
            <span className="text-muted ml-2">Erros:</span>
            <span className="font-bold text-red-400">{scanner.errors}</span>
          </div>
          <div className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-1.5">
            <span className="text-muted">Nuclei:</span>
            <span className="font-bold text-purple-400">{scanner.nuclei_runs}</span>
            <span className="text-muted ml-2">Nmap:</span>
            <span className="font-bold text-cyan-400">{scanner.nmap_runs}</span>
          </div>
          <button
            type="button"
            onClick={handleBatchScan}
            disabled={scanning}
            className="rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-semibold text-accent hover:bg-accent/20 transition-colors disabled:opacity-50"
          >
            {scanning ? "Enfileirando..." : "Scan IPs alto risco"}
          </button>
        </div>
      )}

      {/* Top vulns */}
      {stats && stats.top_vulns.length > 0 && (
        <div className="mb-4">
          <div className="text-[10px] font-bold text-foreground/60 uppercase mb-1.5">Top Vulnerabilidades</div>
          <div className="flex flex-wrap gap-2">
            {stats.top_vulns.map((v) => (
              <div key={v.template_id} className="rounded border border-border bg-card px-2.5 py-1.5 text-xs flex items-center gap-2">
                <SevBadge severity={v.severity} />
                <span className="font-mono text-foreground/90">{v.template_id}</span>
                <span className="text-muted truncate max-w-[200px]">{v.name}</span>
                <span className="text-accent font-bold">x{v.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filter */}
      <div className="flex gap-2 mb-3">
        {["", "critical", "high", "medium", "low", "info"].map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`rounded px-2.5 py-1 text-[11px] font-semibold transition-colors border ${
              filter === s
                ? "border-accent/50 bg-accent/15 text-accent"
                : "border-border bg-card text-muted hover:text-foreground"
            }`}
          >
            {s || "Todas"}
          </button>
        ))}
      </div>

      {/* Results table */}
      {vulns.length === 0 ? (
        <p className="text-muted py-6 text-center text-sm">
          {stats?.scanner?.completed === 0
            ? "Nenhum scan de vulnerabilidade realizado ainda. IPs de alto risco serao escaneados automaticamente."
            : "Nenhuma vulnerabilidade encontrada com esse filtro."}
        </p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-left text-xs">
            <thead className="bg-card text-muted border-b border-border">
              <tr>
                <th className="px-3 py-2.5 font-medium">IP</th>
                <th className="px-3 py-2.5 font-medium">Vulnerabilidade</th>
                <th className="px-3 py-2.5 font-medium">Severidade</th>
                <th className="px-3 py-2.5 font-medium">Porta</th>
                <th className="px-3 py-2.5 font-medium">Ferramenta</th>
                <th className="px-3 py-2.5 font-medium">Hora</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {vulns.map((v) => {
                const isExpanded = expandedId === v.id;
                return (
                  <Fragment key={v.id}>
                    <tr
                      className={`hover:bg-card/50 transition-colors cursor-pointer ${isExpanded ? "bg-card/40" : ""}`}
                      onClick={() => toggle(v.id)}
                    >
                      <td className="px-3 py-2 font-mono text-accent">{v.ip}</td>
                      <td className="px-3 py-2 max-w-[300px]">
                        <div className="flex items-center gap-1.5">
                          <span className={`text-[10px] transition-transform ${isExpanded ? "rotate-90" : ""}`}>▶</span>
                          <div>
                            <div className="font-semibold text-foreground/90">{v.template_id}</div>
                            <div className="text-[10px] text-muted truncate max-w-[280px]">{v.name}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-3 py-2"><SevBadge severity={v.severity} /></td>
                      <td className="px-3 py-2 text-muted">{v.port ?? "—"}</td>
                      <td className="px-3 py-2"><ToolBadge tool={v.tool} /></td>
                      <td className="px-3 py-2 text-muted whitespace-nowrap">
                        {v.timestamp ? new Date(v.timestamp).toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }) : "—"}
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr>
                        <td colSpan={6} className="bg-card/80 px-4 py-3 border-b border-border">
                          <div className="grid gap-3 sm:grid-cols-2 text-xs">
                            <div>
                              <div className="text-[10px] font-bold text-foreground/60 uppercase mb-1">Descricao</div>
                              <p className="text-foreground/80">{v.description || "Sem descricao disponivel."}</p>
                            </div>
                            <div>
                              <div className="text-[10px] font-bold text-foreground/60 uppercase mb-1">Matched At</div>
                              <p className="font-mono text-foreground/80 break-all">{v.matched_at || "—"}</p>
                            </div>
                            {v.proof && (
                              <div className="sm:col-span-2">
                                <div className="text-[10px] font-bold text-foreground/60 uppercase mb-1">Prova / Output</div>
                                <pre className="rounded bg-background border border-border p-2 text-[11px] text-foreground/70 whitespace-pre-wrap break-all max-h-40 overflow-auto">
                                  {typeof v.proof === "string" ? v.proof : JSON.stringify(v.proof, null, 2)}
                                </pre>
                              </div>
                            )}
                            {v.references && v.references.length > 0 && (
                              <div className="sm:col-span-2">
                                <div className="text-[10px] font-bold text-foreground/60 uppercase mb-1">Referencias</div>
                                <div className="flex flex-wrap gap-1.5">
                                  {v.references.map((ref, i) => (
                                    <a
                                      key={i}
                                      href={ref}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-accent hover:underline text-[11px] break-all"
                                    >
                                      {ref}
                                    </a>
                                  ))}
                                </div>
                              </div>
                            )}
                            {v.tags && v.tags.length > 0 && (
                              <div>
                                <div className="text-[10px] font-bold text-foreground/60 uppercase mb-1">Tags</div>
                                <div className="flex flex-wrap gap-1">
                                  {v.tags.map((tag, i) => (
                                    <span key={i} className="rounded bg-background border border-border px-1.5 py-0.5 text-[10px] text-muted">
                                      {tag}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

