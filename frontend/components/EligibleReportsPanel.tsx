"use client";

import { useEffect, useState, useCallback } from "react";
import Modal from "@/components/Modal";
import {
  fetchBountyPrograms,
  fetchBountyTargets,
  type BountyProgram,
  type BountyTarget,
} from "@/lib/api";

const REFRESH_MS = 12_000;

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, none: 5 };

function maxSeverity(findings: Array<{ severity?: string }>): string {
  if (!findings.length) return "medium";
  let max = "none";
  for (const f of findings) {
    const s = (f.severity || "").toLowerCase();
    if (s && (SEV_ORDER[s] ?? 99) < (SEV_ORDER[max] ?? 99)) max = s;
  }
  return max === "none" ? "medium" : max;
}

function isEligible(t: BountyTarget): boolean {
  return (
    t.alive &&
    !!t.recon_checks?.checked &&
    (t.recon_checks?.total_findings ?? 0) > 0
  );
}

type EligibleItem = {
  program: BountyProgram;
  target: BountyTarget;
  severity: string;
  findings: number;
};

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300",
  high: "bg-orange-500/20 text-orange-300",
  medium: "bg-amber-500/20 text-amber-300",
  low: "bg-sky-500/20 text-sky-300",
  info: "bg-slate-500/20 text-slate-300",
};

const IMPACT_BY_SEV: Record<string, string> = {
  critical: "Critical risk: possible severe compromise of the system or sensitive data.",
  high: "High impact: data exposure or misconfiguration that facilitates attacks.",
  medium: "Medium impact: misconfiguration or information leak that should be remediated.",
  low: "Low impact: security improvement recommended.",
  info: "Informational: useful technical detail for security assessment.",
};

const REMEDIATION_BY_CODE: Record<string, string> = {
  no_https: "Implement HTTPS and redirect all HTTP traffic to HTTPS.",
  cors_credentials_wildcard: "Restrict Access-Control-Allow-Origin to trusted origins; do not use * with credentials.",
  cors_any_origin: "Set Access-Control-Allow-Origin with an explicit list of allowed origins.",
  security_headers_missing: "Add security headers (X-Content-Type-Options, X-Frame-Options, CSP, etc.).",
  trace_enabled: "Disable HTTP TRACE method on the server.",
  request_error: "Ensure the endpoint responds securely without leaking information.",
  git_head_exposed: "Remove or restrict access to /.git and disable directory listing in production.",
  server_status_exposed: "Protect or remove status/debug endpoints in production.",
  actuator_health_exposed: "Restrict access to actuator/health endpoints to internal networks only.",
};

function buildH1Report(program: BountyProgram, target: BountyTarget): string {
  const findings = target.recon_checks?.findings ?? [];
  const url = target.httpx?.url || `https://${target.domain}`;
  const ipList = (target.ips ?? []).join(", ") || "-";
  const severity = maxSeverity(findings);
  const titleFinding = findings[0];
  const title = titleFinding
    ? `${titleFinding.title} on ${target.domain}`
    : `Security findings on ${target.domain}`;
  const description = findings.length
    ? `During reconnaissance of program ${program.name}, the asset ${target.domain} (${url}) was analyzed. The following issues were identified: ${findings.map((f) => f.title).join("; ")}. Details and evidence are provided below.`
    : `Asset ${target.domain} (${url}) in scope of ${program.name}. Describe the identified issue.`;
  const steps = [
    `1. Navigate to the in-scope asset: ${url}`,
    ...findings.map((f, i) => `${i + 2}. Observe: ${f.title}${f.evidence ? ` (evidence: ${f.evidence})` : ""}`),
  ];
  const impact = IMPACT_BY_SEV[severity] || IMPACT_BY_SEV.medium;
  const pocLines = findings.length
    ? findings.map((f) => `- [${(f.severity || "").toUpperCase()}] ${f.title}${f.evidence ? ` | ${f.evidence}` : ""}`)
    : ["- Attach screenshots, video, or cURL as appropriate."];
  const remediationLines: string[] = [];
  const seen: Record<string, boolean> = {};
  for (const f of findings) {
    const line = REMEDIATION_BY_CODE[f.code as string] || `Fix: ${f.title}`;
    if (!seen[line]) { seen[line] = true; remediationLines.push(line); }
  }
  if (!remediationLines.length) remediationLines.push("Apply remediation per best practices for this finding type.");

  return [
    `## Summary`, ``, title, ``,
    `## Severity`, severity.charAt(0).toUpperCase() + severity.slice(1), ``,
    `## Asset`, `- Domain: ${target.domain}`, `- IPs: ${ipList}`, `- URL: ${url}`, `- HTTP Status: ${target.httpx?.status_code ?? "-"}`, ``,
    `## Description`, description, ``,
    `## Steps to Reproduce`, ...steps, ``,
    `## Impact`, impact, ``,
    `## Proof of Concept`, ...pocLines, ``,
    `## Remediation`, ...remediationLines, ``,
    `## References`, `- Review program policy and OWASP/CWE best practices for this weakness type.`, ``,
  ].join("\n");
}

export default function EligibleReportsPanel() {
  const [items, setItems] = useState<EligibleItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [detailItem, setDetailItem] = useState<EligibleItem | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const programs = await fetchBountyPrograms();
      const list = Array.isArray(programs) ? programs : [];
      const h1 = list.filter(
        (p) => p.platform === "hackerone" && (p.url || "").includes("hackerone.com")
      );
      if (h1.length === 0) {
        setItems([]);
        return;
      }

      setLoading(true);
      const byProgram = await Promise.all(
        h1.map(async (prog) => {
          try {
            const targets = await fetchBountyTargets(prog.id);
            return (Array.isArray(targets) ? targets : [])
              .filter(isEligible)
              .map((target) => ({
                program: prog,
                target,
                severity: maxSeverity(target.recon_checks?.findings ?? []),
                findings: target.recon_checks?.total_findings ?? 0,
              }));
          } catch {
            return [] as EligibleItem[];
          }
        })
      );

      const flattened = byProgram
        .flat()
        .sort(
          (a, b) =>
            (SEV_ORDER[a.severity] ?? 99) - (SEV_ORDER[b.severity] ?? 99) ||
            b.findings - a.findings
        );
      setItems(flattened);
    } catch (e) {
      console.error("EligibleReportsPanel:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  const isAlert = items.length > 1;

  const borderColor = isAlert ? "border-red-500/50" : items.length === 1 ? "border-orange-500/30" : "border-[var(--border)]";
  const bgColor = isAlert ? "bg-red-500/5" : items.length === 1 ? "bg-orange-500/5" : "bg-[var(--card)]";
  const headerTextColor = isAlert ? "text-red-400" : "text-orange-300";
  const iconBg = isAlert ? "bg-red-500/20 text-red-400" : "bg-orange-500/15 text-orange-400";
  const countBadgeBg = isAlert ? "bg-red-500/25 text-red-200" : "bg-orange-500/20 text-orange-200";

  const totalFindings = items.reduce((s, i) => s + i.findings, 0);
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of items) {
    for (const f of item.target.recon_checks?.findings ?? []) {
      const s = (f.severity || "info").toLowerCase() as keyof typeof sevCounts;
      if (s in sevCounts) sevCounts[s]++;
    }
  }
  const uniquePrograms = new Set(items.map(i => i.program.id)).size;
  const uniqueDomains = new Set(items.map(i => i.target.domain)).size;

  return (
    <div className={`rounded-2xl border ${borderColor} ${bgColor} p-4 ${isAlert ? "shadow-md shadow-red-500/10" : ""}`}>
      {/* Header */}
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className={`flex h-8 w-8 items-center justify-center rounded-lg ${iconBg}`}>
            {isAlert ? (
              <svg className="w-4 h-4 animate-pulse" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
              </svg>
            ) : (
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
              </svg>
            )}
          </div>
          <h2 className={`text-base font-bold uppercase tracking-wider ${headerTextColor}`}>
            {isAlert ? "Alerta H1" : "Elegíveis H1"}
          </h2>
        </div>
        <div className="flex items-center gap-2">
          {items.length > 0 && (
            <div className="flex gap-1.5 text-xs">
              {sevCounts.critical > 0 && <span className="rounded bg-red-500/20 text-red-300 px-1.5 py-0.5 font-bold">{sevCounts.critical}C</span>}
              {sevCounts.high > 0 && <span className="rounded bg-orange-500/20 text-orange-300 px-1.5 py-0.5 font-bold">{sevCounts.high}H</span>}
              {sevCounts.medium > 0 && <span className="rounded bg-amber-500/20 text-amber-300 px-1.5 py-0.5 font-bold">{sevCounts.medium}M</span>}
            </div>
          )}
          <span className={`rounded-full px-2.5 py-1 text-base font-extrabold tabular-nums ${countBadgeBg} ${isAlert ? "animate-pulse" : ""}`}>
            {items.length}
          </span>
        </div>
      </div>

      {/* Content */}
      {loading && items.length === 0 ? (
        <p className="text-sm text-slate-400 py-2">Carregando...</p>
      ) : items.length === 0 ? (
        <p className="text-sm text-[var(--muted)] py-2">Nenhum report elegível</p>
      ) : (
        <div className="space-y-2 max-h-[50vh] overflow-y-auto hide-scrollbar">
          {items.slice(0, 15).map((item) => {
            const score = item.target.recon_checks?.risk_score ?? 0;
            const findings = item.target.recon_checks?.findings ?? [];
            const highFindings = findings.filter(f => f.severity === "critical" || f.severity === "high");
            const httpCode = item.target.httpx?.status_code;

            return (
              <button
                key={`${item.program.id}-${item.target.id}`}
                type="button"
                onClick={() => setDetailItem(item)}
                className={`rounded-xl border p-3 text-left transition-all group w-full ${
                  isAlert
                    ? "border-red-500/30 bg-red-950/30 hover:border-red-400/50 hover:bg-red-950/50"
                    : "border-slate-700/50 bg-slate-900/70 hover:border-orange-500/40 hover:bg-slate-900"
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="truncate text-base font-bold text-[var(--foreground)]">{item.program.name}</span>
                  <span className={`shrink-0 rounded px-2 py-0.5 text-xs font-bold uppercase ${SEV_COLORS[item.severity] ?? SEV_COLORS.info}`}>
                    {item.severity}
                  </span>
                </div>

                <div className="text-sm text-emerald-300 font-mono truncate mb-2">{item.target.domain}</div>

                <div className="flex items-center gap-3 text-sm">
                  <span className="text-amber-400 font-bold tabular-nums">{item.findings} achados</span>
                  {highFindings.length > 0 && <span className="text-red-400 font-semibold tabular-nums">{highFindings.length} high+</span>}
                  <span className="text-[var(--muted)] tabular-nums">score {score}</span>
                  {httpCode && <span className="text-[var(--muted)] tabular-nums">{httpCode}</span>}
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      const md = buildH1Report(item.program, item.target);
                      navigator.clipboard.writeText(md).catch(() => {});
                      setCopiedId(item.target.id);
                      setTimeout(() => setCopiedId(null), 2000);
                      if (item.program.url) {
                        const reportUrl = item.program.url.replace(/\/?$/, "/reports/new");
                        window.open(reportUrl, "_blank", "noopener,noreferrer");
                      }
                    }}
                    className={`ml-auto rounded-lg px-3 py-1 text-xs font-bold transition-all ${
                      copiedId === item.target.id
                        ? "bg-emerald-600 text-white"
                        : "bg-orange-500 hover:bg-orange-400 text-white"
                    }`}
                  >
                    {copiedId === item.target.id ? "Copiado!" : "Reportar H1"}
                  </button>
                </div>
              </button>
            );
          })}
        </div>
      )}

      {/* Detail Modal */}
      <Modal
        open={!!detailItem}
        onClose={() => setDetailItem(null)}
        title={detailItem ? `Report: ${detailItem.target.domain}` : ""}
        maxWidth="max-w-4xl"
      >
        {detailItem && (() => {
          const t = detailItem.target;
          const p = detailItem.program;
          const findings = t.recon_checks?.findings ?? [];
          const ips = t.ips ?? [];
          const techs = t.httpx?.tech ?? [];
          const httpPorts = t.http_scanner ?? [];
          const waybackCount = t.wayback_urls?.length ?? 0;
          const paramsCount = t.paramspider?.params?.length ?? 0;

          return (
            <div className="space-y-6">
              {/* Reportar H1 — main action */}
              <button
                type="button"
                onClick={() => {
                  const md = buildH1Report(p, t);
                  navigator.clipboard.writeText(md).catch(() => {});
                  setCopiedId(t.id);
                  setTimeout(() => setCopiedId(null), 2500);
                  if (p.url) {
                    const reportUrl = p.url.replace(/\/?$/, "/reports/new");
                    window.open(reportUrl, "_blank", "noopener,noreferrer");
                  }
                }}
                className={`w-full rounded-xl py-3.5 text-lg font-bold transition-all flex items-center justify-center gap-3 ${
                  copiedId === t.id
                    ? "bg-emerald-600 text-white"
                    : "bg-orange-500 hover:bg-orange-400 text-white shadow-lg shadow-orange-500/20"
                }`}
              >
                {copiedId === t.id ? (
                  <>
                    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    Report copiado! Abrindo HackerOne...
                  </>
                ) : (
                  <>
                    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                    </svg>
                    Reportar no HackerOne
                  </>
                )}
              </button>

              {/* Top metric cards */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
                {[
                  { label: "Severidade", node: <span className={`rounded-full px-3 py-1 text-base font-bold uppercase ${SEV_COLORS[detailItem.severity] ?? SEV_COLORS.info}`}>{detailItem.severity}</span> },
                  { label: "Achados", node: <span className="text-3xl font-extrabold text-amber-400 tabular-nums">{detailItem.findings}</span> },
                  { label: "Risk Score", node: <span className="text-3xl font-extrabold text-[var(--foreground)] tabular-nums">{t.recon_checks?.risk_score ?? 0}</span> },
                  { label: "Etapa", node: <span className="text-3xl font-extrabold text-[var(--accent-light)] tabular-nums">{p.flow_step ?? 1}/7</span> },
                  { label: "HTTP", node: <span className="text-3xl font-extrabold text-[var(--foreground)] tabular-nums">{t.httpx?.status_code ?? "–"}</span> },
                ].map(({ label, node }, i) => (
                  <div key={i} className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-4 text-center flex flex-col items-center justify-center">
                    {node}
                    <div className="text-sm text-[var(--muted)] mt-2">{label}</div>
                  </div>
                ))}
              </div>

              {/* Program & target info */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                <div className="space-y-2.5">
                  <h3 className="text-base font-bold text-[var(--foreground)] uppercase tracking-wide mb-1">Programa</h3>
                  <div className="flex justify-between text-base"><span className="text-[var(--muted)]">Nome</span><span className="text-[var(--foreground)] font-semibold">{p.name}</span></div>
                  <div className="flex justify-between text-base"><span className="text-[var(--muted)]">Plataforma</span><span className="text-orange-300 font-semibold uppercase">{p.platform}</span></div>
                  {p.url && <div className="flex justify-between text-base gap-2"><span className="text-[var(--muted)] shrink-0">URL</span><a href={p.url} target="_blank" rel="noopener noreferrer" className="text-[var(--accent-light)] hover:underline truncate">{p.url}</a></div>}
                  {p.has_bounty && <div className="flex justify-between text-base"><span className="text-[var(--muted)]">Bounty</span><span className="text-green-400 font-semibold">{p.bounty_currency || "USD"} {p.bounty_min ?? "?"} – {p.bounty_max ?? "?"}</span></div>}
                  <div className="flex justify-between text-base"><span className="text-[var(--muted)]">Escopo in</span><span className="text-[var(--foreground)]">{p.in_scope?.length ?? 0}</span></div>
                  <div className="flex justify-between text-base"><span className="text-[var(--muted)]">Escopo out</span><span className="text-[var(--foreground)]">{p.out_of_scope?.length ?? 0}</span></div>
                </div>

                <div className="space-y-2.5">
                  <h3 className="text-base font-bold text-[var(--foreground)] uppercase tracking-wide mb-1">Target</h3>
                  <div className="flex justify-between text-base"><span className="text-[var(--muted)]">Domínio</span><span className="text-emerald-300 font-mono font-semibold">{t.domain}</span></div>
                  {t.httpx?.url && <div className="flex justify-between text-base gap-2"><span className="text-[var(--muted)] shrink-0">HTTP URL</span><a href={t.httpx.url} target="_blank" rel="noopener noreferrer" className="text-[var(--accent-light)] hover:underline truncate">{t.httpx.url}</a></div>}
                  <div className="flex justify-between text-base"><span className="text-[var(--muted)]">Status</span><span className="text-[var(--foreground)]">{t.status}</span></div>
                  {ips.length > 0 && <div className="flex justify-between text-base gap-2"><span className="text-[var(--muted)] shrink-0">IPs</span><span className="text-[var(--foreground)] font-mono truncate">{ips.join(", ")}</span></div>}
                  {t.httpx?.webserver && <div className="flex justify-between text-base"><span className="text-[var(--muted)]">Server</span><span className="text-[var(--foreground)]">{t.httpx.webserver}</span></div>}
                  {t.httpx?.title && <div className="flex justify-between text-base gap-2"><span className="text-[var(--muted)] shrink-0">Title</span><span className="text-[var(--foreground)] truncate">{t.httpx.title}</span></div>}
                  {t.httpx?.cdn != null && <div className="flex justify-between text-base"><span className="text-[var(--muted)]">CDN</span><span className={t.httpx.cdn ? "text-amber-300" : "text-[var(--foreground)]"}>{t.httpx.cdn ? "Sim" : "Não"}</span></div>}
                  {waybackCount > 0 && <div className="flex justify-between text-base"><span className="text-[var(--muted)]">Wayback URLs</span><span className="text-[var(--foreground)] tabular-nums">{waybackCount}</span></div>}
                  {paramsCount > 0 && <div className="flex justify-between text-base"><span className="text-[var(--muted)]">Params</span><span className="text-[var(--foreground)] tabular-nums">{paramsCount}</span></div>}
                </div>
              </div>

              {/* Technologies */}
              {techs.length > 0 && (
                <div>
                  <h3 className="text-base font-bold text-[var(--foreground)] uppercase tracking-wide mb-2">Tecnologias</h3>
                  <div className="flex flex-wrap gap-2">
                    {techs.map((tech, i) => (
                      <span key={i} className="rounded-lg bg-cyan-500/10 border border-cyan-500/20 px-3 py-1 text-base text-cyan-300">{tech}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* HTTP Scanner ports */}
              {httpPorts.length > 0 && (
                <div>
                  <h3 className="text-base font-bold text-[var(--foreground)] uppercase tracking-wide mb-2">Portas HTTP</h3>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                    {httpPorts.slice(0, 9).map((hp, i) => (
                      <div key={i} className="rounded-lg bg-[var(--background)] border border-[var(--border)] px-3 py-2 text-sm">
                        <span className="font-mono text-[var(--foreground)] font-semibold">{hp.port ?? "?"}</span>
                        {hp.service && <span className="text-[var(--muted)] ml-2">{hp.service}</span>}
                        {hp.status_code && <span className="text-emerald-400 ml-2">{hp.status_code}</span>}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Findings */}
              {findings.length > 0 && (
                <div>
                  <h3 className="text-base font-bold text-[var(--foreground)] uppercase tracking-wide mb-3">Findings ({findings.length})</h3>
                  <div className="space-y-2.5">
                    {findings.map((f, i) => (
                      <div key={i} className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-4">
                        <div className="flex items-center justify-between gap-2 mb-1">
                          <span className="text-base font-semibold text-[var(--foreground)]">{f.title}</span>
                          <span className={`shrink-0 rounded px-2.5 py-0.5 text-sm font-bold uppercase ${
                            f.severity === "critical" ? "bg-red-500/20 text-red-300" :
                            f.severity === "high" ? "bg-orange-500/20 text-orange-300" :
                            f.severity === "medium" ? "bg-amber-500/20 text-amber-300" :
                            f.severity === "low" ? "bg-sky-500/20 text-sky-300" :
                            "bg-slate-500/20 text-slate-300"
                          }`}>{f.severity}</span>
                        </div>
                        {f.code && <div className="text-sm text-[var(--muted)] font-mono">{f.code}</div>}
                        {f.evidence && <p className="text-base text-[var(--muted)] break-all mt-1">{f.evidence}</p>}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })()}
      </Modal>
    </div>
  );
}
