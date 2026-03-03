"use client";

import { Fragment, useEffect, useState, useCallback } from "react";
import Modal from "@/components/Modal";
import {
  fetchBountyPrograms,
  fetchBountyTargets,
  fetchBountyStats,
  fetchProgramFlow,
  fetchBountyChanges,
  createBountyProgram,
  suggestBountyScope,
  triggerBountyRecon,
  clearBountyProgramError,
  triggerBountyTargetScan,
  deleteBountyProgram,
  fetchBountyReport,
  syncBugScraperPrograms,
  deleteAllBountyPrograms,
  generateTargetReport,
  type BountyProgram,
  type BountyTarget,
  type BountyStats,
  type BountyProgramFlow,
  type BountyChange,
} from "@/lib/api";

const REFRESH_MS = 10_000;
const HIGH_ONLY_STORAGE_KEY = "bounty-high-only-by-program";

const PLATFORM_OPTS = [
  { value: "hackerone", label: "HackerOne" },
  { value: "bugcrowd", label: "Bugcrowd" },
  { value: "intigriti", label: "Intigriti" },
  { value: "yeswehack", label: "YesWeHack" },
  { value: "bughunt", label: "BugHunt" },
  { value: "other", label: "Outra" },
];

const STATUS_COLORS: Record<string, string> = {
  discovered: "text-slate-400",
  resolved: "text-blue-400",
  probed: "text-green-400",
  scanning: "text-amber-400 animate-pulse",
  scanned: "text-emerald-400",
};

function StatBox({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-xl bg-slate-800/60 border border-slate-700/50 px-5 py-4 sm:px-6 sm:py-5 text-center">
      <div className="text-3xl sm:text-4xl font-bold text-white tabular-nums">{value}</div>
      <div className="text-sm sm:text-base text-slate-400 uppercase tracking-wider mt-1.5">{label}</div>
    </div>
  );
}

function isHackerOneProgram(program: BountyProgram): boolean {
  return program.platform === "hackerone" && (program.url || "").includes("hackerone.com");
}

function targetFulfillsHackerOneRules(t: BountyTarget): boolean {
  return (
    t.alive &&
    !!t.recon_checks?.checked &&
    (t.recon_checks?.total_findings ?? 0) > 0
  );
}

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, none: 5 };
function maxSeverity(findings: Array<{ severity?: string }>): string {
  if (!findings.length) return "Medium";
  let max = "none";
  for (const f of findings) {
    const s = (f.severity || "").toLowerCase();
    if (s && (SEV_ORDER[s] ?? 99) < (SEV_ORDER[max] ?? 99)) max = s;
  }
  return max === "none" ? "Medium" : max;
}

const IMPACT_BY_SEV: Record<string, string> = {
  critical: "Risco crítico: possível comprometimento grave do sistema ou dados sensíveis.",
  high: "Alto impacto: exposição de dados ou configuração que facilita ataques.",
  medium: "Impacto médio: má configuração ou vazamento de informação que deve ser corrigido.",
  low: "Baixo impacto: melhoria de segurança recomendada.",
  info: "Informativo: detalhe técnico útil para avaliação de segurança.",
};

const REMEDIATION_BY_CODE: Record<string, string> = {
  no_https: "Implementar HTTPS e redirecionar todo o tráfego HTTP para HTTPS.",
  cors_credentials_wildcard: "Restringir Access-Control-Allow-Origin a origens confiáveis; não usar * com credenciais.",
  cors_any_origin: "Definir Access-Control-Allow-Origin com lista explícita de origens permitidas.",
  security_headers_missing: "Incluir headers de segurança (X-Content-Type-Options, X-Frame-Options, CSP, etc.).",
  trace_enabled: "Desabilitar o método HTTP TRACE no servidor.",
  request_error: "Garantir que o endpoint responda de forma segura e sem vazamento de informação.",
  git_head_exposed: "Remover ou restringir acesso a /.git e desabilitar listagem em produção.",
  server_status_exposed: "Proteger ou remover endpoints de status/debug em produção.",
  actuator_health_exposed: "Restringir acesso a endpoints de actuator/health apenas a redes internas ou remover.",
};

type H1EligibleReport = {
  program: BountyProgram;
  target: BountyTarget;
  severity: string;
  findings: number;
};

/** Gera report automaticamente a partir de programa, target e recon checks (.cursor/rules/bounty-reports.mdc). */
function buildReportTemplate(program: BountyProgram, target: BountyTarget): string {
  const findings = target.recon_checks?.findings ?? [];
  const url = target.httpx?.url || `https://${target.domain}`;
  const ipList = (target.ips ?? []).join(", ") || "-";
  const severity = maxSeverity(findings);
  const titleFinding = findings[0];
  const title = titleFinding
    ? `${titleFinding.title} em ${target.domain}`
    : `Achados de segurança em ${target.domain}`;
  const description = findings.length
    ? `Durante o recon do programa ${program.name}, o ativo ${target.domain} (${url}) foi analisado. Foram identificados: ${findings.map((f) => f.title).join("; ")}. Detalhes e evidências nas seções abaixo.`
    : `Ativo ${target.domain} (${url}) no escopo de ${program.name}. Incluir descrição do problema identificado.`;
  const steps = [
    `Acessar o ativo em escopo: ${url}`,
    ...findings.map((f) => `Observar: ${f.title}${f.evidence ? ` (evidência: ${f.evidence})` : ""}`),
  ].filter(Boolean);
  const impact = IMPACT_BY_SEV[severity] || IMPACT_BY_SEV.medium;
  const pocLines = findings.length
    ? findings.map((f) => `- [${(f.severity || "").toUpperCase()}] ${f.title}${f.evidence ? ` | ${f.evidence}` : ""}`)
    : ["- Anexar screenshots, vídeo ou cURL conforme o finding."];
  let remediationLines: string[] = [];
  if (findings.length) {
    const seen: Record<string, boolean> = {};
    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      const line = REMEDIATION_BY_CODE[f.code as string] || `Corrigir: ${f.title}`;
      if (!seen[line]) {
        seen[line] = true;
        remediationLines.push(line);
      }
    }
  } else {
    remediationLines = ["- Aplicar correção conforme melhores práticas para o tipo de finding."];
  }

  return [
    `# ${title}`,
    "",
    "## Program",
    `- Name: ${program.name}`,
    `- Platform: ${program.platform || "N/A"}`,
    `- URL: ${program.url || "N/A"}`,
    "",
    "## Asset",
    `- Domain: ${target.domain}`,
    `- IPs: ${ipList}`,
    `- HTTP: ${url}`,
    `- Status code: ${target.httpx?.status_code ?? "-"}`,
    "",
    "## Title",
    title,
    "",
    "## Severity",
    severity.charAt(0).toUpperCase() + severity.slice(1),
    "",
    "## Description / Vulnerability information",
    description,
    "",
    "## Steps to Reproduce",
    ...steps.map((s, i) => `${i + 1}. ${s}`),
    "",
    "## Impact",
    impact,
    "",
    "## Proof of Concept (PoC)",
    ...pocLines,
    "",
    "## Remediation",
    ...remediationLines,
    "",
    "## References",
    "- Revisar política do programa e boas práticas OWASP/CWE para o tipo de weakness.",
    "",
  ].join("\n");
}

/* ═══════════════════════════════════════════════════════════════
   Report Actions — Generate, Preview & Copy for any platform
   ═══════════════════════════════════════════════════════════════ */

function ReportActions({ targetId, program, target }: {
  targetId: string;
  program: BountyProgram | null;
  target: BountyTarget;
}) {
  const [report, setReport] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState("");
  const [showPreview, setShowPreview] = useState(false);
  const [error, setError] = useState("");

  const handleGenerate = async () => {
    setLoading(true);
    setError("");
    try {
      const r = await generateTargetReport(targetId);
      setReport(r);
      setShowPreview(true);
    } catch (e: any) {
      setError(e.message || "Failed to generate report");
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(label);
      setTimeout(() => setCopied(""), 2000);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      setCopied(label);
      setTimeout(() => setCopied(""), 2000);
    }
  };

  const formatForPlatform = (platform: string): string => {
    if (!report) return "";

    const body = report.body || report.vulnerability_information || "";
    const title = report.title || "";
    const severity = report.severity || report.severity_rating || "medium";
    const impact = report.impact || "";

    if (platform === "hackerone") {
      return body;
    }

    if (platform === "bugcrowd") {
      return [
        `# ${title}`,
        "",
        `**Severity:** ${severity.toUpperCase()}`,
        `**Target:** ${target.domain}`,
        "",
        body,
        "",
        impact ? `## Business Impact\n\n${impact}` : "",
      ].filter(Boolean).join("\n");
    }

    if (platform === "intigriti") {
      return [
        `## Submission Title`,
        title,
        "",
        `## Domain`,
        target.domain,
        "",
        `## Endpoint`,
        target.httpx?.url || `https://${target.domain}`,
        "",
        `## Description`,
        body,
        "",
        impact ? `## Impact Statement\n\n${impact}` : "",
      ].filter(Boolean).join("\n");
    }

    if (platform === "yeswehack") {
      return [
        `# ${title}`,
        "",
        `**Severity:** ${severity.toUpperCase()}`,
        `**Scope:** ${target.domain}`,
        "",
        body,
        "",
        impact ? `## Impact\n\n${impact}` : "",
      ].filter(Boolean).join("\n");
    }

    if (platform === "bughunt") {
      const findings = target.recon_checks?.findings ?? [];
      const cweList = findings.map(f => f.code).filter(Boolean).join(", ");
      return [
        `# ${title}`,
        "",
        `## Informações do Ativo`,
        `- **Domínio:** ${target.domain}`,
        `- **URL:** ${target.httpx?.url || `https://${target.domain}`}`,
        `- **IPs:** ${(target.ips ?? []).join(", ") || "N/A"}`,
        `- **Status HTTP:** ${target.httpx?.status_code ?? "N/A"}`,
        "",
        `## Severidade`,
        `**${severity.toUpperCase()}**`,
        cweList ? `\n**CWE:** ${cweList}` : "",
        "",
        `## Descrição da Vulnerabilidade`,
        body,
        "",
        `## Impacto`,
        impact || "A exploração desta vulnerabilidade pode comprometer a segurança do ativo e dos dados dos usuários.",
        "",
        `## Evidências e Prova de Conceito`,
        findings.length > 0
          ? findings.map(f => `- **[${(f.severity || "").toUpperCase()}]** ${f.title}${f.evidence ? `\n  Evidência: \`${f.evidence}\`` : ""}`).join("\n")
          : "- Anexar screenshots ou vídeo demonstrando a exploração.",
        "",
        `## Sugestão de Correção`,
        "Consulte a seção de remediação no report completo acima.",
        "",
        `---`,
        `*Report gerado por Scanner Bounty*`,
      ].filter(Boolean).join("\n");
    }

    return `# ${title}\n\n${body}`;
  };

  const platforms = [
    { id: "hackerone", label: "HackerOne", icon: "🟢", color: "border-green-500/30 bg-green-500/5 hover:bg-green-500/10 text-green-400" },
    { id: "bugcrowd", label: "Bugcrowd", icon: "🟠", color: "border-orange-500/30 bg-orange-500/5 hover:bg-orange-500/10 text-orange-400" },
    { id: "intigriti", label: "Intigriti", icon: "🔵", color: "border-blue-500/30 bg-blue-500/5 hover:bg-blue-500/10 text-blue-400" },
    { id: "yeswehack", label: "YesWeHack", icon: "🟡", color: "border-yellow-500/30 bg-yellow-500/5 hover:bg-yellow-500/10 text-yellow-400" },
    { id: "bughunt", label: "BugHunt", icon: "🇧🇷", color: "border-emerald-500/30 bg-emerald-500/5 hover:bg-emerald-500/10 text-emerald-400" },
    { id: "markdown", label: "Markdown", icon: "📋", color: "border-[var(--border)] bg-white/[0.02] hover:bg-white/[0.05] text-[var(--foreground)]" },
  ];

  return (
    <div className="border-t border-[var(--border)] pt-4">
      <h3 className="text-base font-semibold text-[var(--foreground)] mb-3">Report</h3>

      {!report && !showPreview && (
        <button
          onClick={handleGenerate}
          disabled={loading}
          className={`w-full py-3 rounded-xl text-base font-semibold transition-all ${
            loading
              ? "bg-[var(--accent)]/10 text-[var(--accent-light)] cursor-wait"
              : "bg-[var(--accent)]/15 text-[var(--accent-light)] hover:bg-[var(--accent)]/25 border border-[var(--accent)]/30"
          }`}
        >
          {loading ? "Generating report (AI may take ~30s)..." : "Generate Report"}
        </button>
      )}

      {error && <div className="text-sm text-red-400 mt-2 p-2 rounded-lg bg-red-500/5 border border-red-500/20">{error}</div>}

      {report && showPreview && (
        <div className="space-y-3">
          {/* Source badge */}
          <div className="flex items-center gap-2">
            <span className={`text-xs font-bold px-2 py-1 rounded border ${
              report.source === "ai"
                ? "border-fuchsia-500/30 bg-fuchsia-500/10 text-fuchsia-400"
                : "border-[var(--accent)]/30 bg-[var(--accent)]/10 text-[var(--accent-light)]"
            }`}>
              {report.source === "ai" ? `AI (${report.ai_provider || "ollama"})` : "Template"}
            </span>
            <span className={`text-xs font-bold px-2 py-1 rounded sev-${report.severity || report.severity_rating || "medium"}`}>
              {(report.severity || report.severity_rating || "medium").toUpperCase()}
            </span>
            {report.confidence && (
              <span className="text-xs text-[var(--muted)]">Confidence: {report.confidence}%</span>
            )}
            {report.cvss_score && (
              <span className="text-xs text-amber-400 font-semibold">CVSS {report.cvss_score}</span>
            )}
          </div>

          {/* Title */}
          <div className="rounded-lg bg-[var(--background)] border border-[var(--border)] p-3">
            <div className="text-[10px] text-[var(--muted)] uppercase font-semibold mb-1">Title</div>
            <div className="text-sm font-semibold text-[var(--foreground)]">{report.title}</div>
          </div>

          {/* Copy buttons for each platform */}
          <div className="space-y-2">
            <div className="text-[10px] text-[var(--muted)] uppercase font-semibold">Copy report for:</div>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
              {platforms.map(p => (
                <button
                  key={p.id}
                  onClick={() => copyToClipboard(formatForPlatform(p.id), p.id)}
                  className={`flex items-center justify-center gap-1.5 py-2.5 px-3 rounded-xl border text-sm font-medium transition-all ${p.color}`}
                >
                  <span>{p.icon}</span>
                  <span>{copied === p.id ? "Copied!" : p.label}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Copy title separately */}
          <button
            onClick={() => copyToClipboard(report.title || "", "title")}
            className="text-xs text-[var(--muted)] hover:text-[var(--foreground)] transition-colors"
          >
            {copied === "title" ? "Title copied!" : "Copy title only"}
          </button>

          {/* Preview body */}
          <details className="group">
            <summary className="text-xs text-[var(--muted)] cursor-pointer hover:text-[var(--foreground)] transition-colors">
              Preview report body
            </summary>
            <div className="mt-2 rounded-xl bg-[var(--background)] border border-[var(--border)] p-4 max-h-80 overflow-y-auto hide-scrollbar">
              <pre className="text-xs text-[var(--foreground)] whitespace-pre-wrap font-mono leading-relaxed">
                {report.body || report.vulnerability_information || "No body"}
              </pre>
            </div>
          </details>

          {/* Regenerate */}
          <button
            onClick={handleGenerate}
            disabled={loading}
            className="text-xs text-[var(--accent-light)] hover:text-[var(--foreground)] transition-colors"
          >
            {loading ? "Regenerating..." : "Regenerate report"}
          </button>
        </div>
      )}
    </div>
  );
}

export default function BountyPanel() {
  const [programs, setPrograms] = useState<BountyProgram[]>([]);
  const [stats, setStats] = useState<BountyStats | null>(null);
  const [expandedProgram, setExpandedProgram] = useState<string | null>(null);
  const [targets, setTargets] = useState<BountyTarget[]>([]);
  const [loadingTargets, setLoadingTargets] = useState(false);

  const [showForm, setShowForm] = useState(false);
  const [formName, setFormName] = useState("");
  const [formPlatform, setFormPlatform] = useState("hackerone");
  const [formUrl, setFormUrl] = useState("");
  const [formInScope, setFormInScope] = useState("");
  const [formOutScope, setFormOutScope] = useState("");
  const [formPolicyUrl, setFormPolicyUrl] = useState("");
  const [formHasBounty, setFormHasBounty] = useState(false);
  const [formBountyMin, setFormBountyMin] = useState<string>("");
  const [formBountyMax, setFormBountyMax] = useState<string>("");
  const [formBountyCurrency, setFormBountyCurrency] = useState("USD");
  const [formAssetTypes, setFormAssetTypes] = useState<string[]>([]);
  const [formPriority, setFormPriority] = useState("normal");
  const [formSafeHarbor, setFormSafeHarbor] = useState(false);
  const [formNotes, setFormNotes] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [scopeLoading, setScopeLoading] = useState(false);
  const [scopeHint, setScopeHint] = useState<string | null>(null);

  const [reconning, setReconning] = useState<Set<string>>(new Set());
  const [scanningTargets, setScanningTargets] = useState<Set<string>>(new Set());
  const [reportLoading, setReportLoading] = useState<string | null>(null);
  const [copiedTemplateId, setCopiedTemplateId] = useState<string | null>(null);
  const [templatePreview, setTemplatePreview] = useState<string | null>(null);
  const [flowByProgram, setFlowByProgram] = useState<Record<string, BountyProgramFlow>>({});
  const [filterFlowStep, setFilterFlowStep] = useState<number | "">("");
  const [highOnlyByProgram, setHighOnlyByProgram] = useState<Record<string, boolean>>({});
  const [showCsvImport, setShowCsvImport] = useState(false);
  const [csvFile, setCsvFile] = useState<File | null>(null);
  const [csvPaste, setCsvPaste] = useState("");
  const [csvLoading, setCsvLoading] = useState(false);
  const [csvResult, setCsvResult] = useState<{ created: number; updated: number; errors: string[] } | null>(null);
  const [bugScraperLoading, setBugScraperLoading] = useState(false);
  const [bugScraperInserted, setBugScraperInserted] = useState<number | null>(null);
  const [clearingAll, setClearingAll] = useState(false);
  const [reconAllRunning, setReconAllRunning] = useState(false);
  const [reconAllProgress, setReconAllProgress] = useState<{ done: number; total: number } | null>(null);
  const [changes, setChanges] = useState<BountyChange[]>([]);
  const [changesLoading, setChangesLoading] = useState(false);
  const [h1EligibleReports, setH1EligibleReports] = useState<H1EligibleReport[]>([]);
  const [h1EligibleLoading, setH1EligibleLoading] = useState(false);
  const [detailProgram, setDetailProgram] = useState<BountyProgram | null>(null);
  const [detailTarget, setDetailTarget] = useState<BountyTarget | null>(null);
  const [showProgramList, setShowProgramList] = useState(false);
  const [programSearch, setProgramSearch] = useState("");

  const handleBugScraperSync = async () => {
    try {
      setBugScraperLoading(true);
      setBugScraperInserted(null);
      const res = await syncBugScraperPrograms();
      setBugScraperInserted(res.inserted ?? 0);
      await loadPrograms();
    } catch (e) {
      console.error("BugScraper sync error:", e);
      setBugScraperInserted(0);
    } finally {
      setBugScraperLoading(false);
    }
  };

  const handleDeleteAllPrograms = async () => {
    if (!window.confirm("Tem certeza que deseja remover todos os programas e targets cadastrados?")) {
      return;
    }
    try {
      setClearingAll(true);
      await deleteAllBountyPrograms();
      await loadPrograms();
    } catch (e) {
      console.error("Delete all programs error:", e);
    } finally {
      setClearingAll(false);
    }
  };

  const handleReconAll = async () => {
    if (programs.length === 0) return;
    const eligible = programs.filter((p) => p.status !== "reconning");
    if (eligible.length === 0) return;
    setReconAllRunning(true);
    setReconAllProgress({ done: 0, total: eligible.length });
    for (let i = 0; i < eligible.length; i++) {
      try {
        await triggerBountyRecon(eligible[i].id);
      } catch (e) {
        console.error(`Recon error for ${eligible[i].name}:`, e);
      }
      setReconAllProgress({ done: i + 1, total: eligible.length });
    }
    setReconAllRunning(false);
    setReconAllProgress(null);
    await loadPrograms();
  };

  const loadPrograms = useCallback(async () => {
    try {
      const [p, s] = await Promise.all([fetchBountyPrograms(), fetchBountyStats()]);
      const firstList = Array.isArray(p) ? p : [];
      const inError = firstList.filter((prog) => prog.status === "error");
      let finalList = firstList;
      let finalStats = s;
      if (inError.length > 0) {
        for (const prog of inError) {
          try {
            await clearBountyProgramError(prog.id);
          } catch (e) {
            console.error("Auto-clear error for program:", prog.id, e);
          }
        }
        const [p2, s2] = await Promise.all([fetchBountyPrograms(), fetchBountyStats()]);
        finalList = Array.isArray(p2) ? p2 : [];
        finalStats = s2;
      }

      setPrograms(finalList);
      setStats(finalStats);

      const h1Programs = finalList.filter(
        (prog) => prog.platform === "hackerone" && (prog.url || "").includes("hackerone.com")
      );
      if (h1Programs.length === 0) {
        setH1EligibleReports([]);
        return;
      }

      setH1EligibleLoading(true);
      const byProgram = await Promise.all(
        h1Programs.map(async (prog) => {
          try {
            const programTargets = await fetchBountyTargets(prog.id);
            return (Array.isArray(programTargets) ? programTargets : [])
              .filter(targetFulfillsHackerOneRules)
              .map((target) => ({
                program: prog,
                target,
                severity: maxSeverity(target.recon_checks?.findings ?? []),
                findings: target.recon_checks?.total_findings ?? 0,
              }));
          } catch {
            return [] as H1EligibleReport[];
          }
        })
      );
      const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      const flattened = byProgram
        .flat()
        .sort((a, b) => (sevRank[a.severity] ?? 99) - (sevRank[b.severity] ?? 99) || b.findings - a.findings);
      setH1EligibleReports(flattened);
    } catch (e) {
      console.error("BountyPanel load error:", e);
    } finally {
      setH1EligibleLoading(false);
    }
  }, []);

  useEffect(() => {
    loadPrograms();
    const id = setInterval(loadPrograms, REFRESH_MS);
    return () => clearInterval(id);
  }, [loadPrograms]);

  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(HIGH_ONLY_STORAGE_KEY);
      if (!raw) return;
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object") {
        setHighOnlyByProgram(parsed as Record<string, boolean>);
      }
    } catch (e) {
      console.error("Failed to load high-only preferences:", e);
    }
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem(HIGH_ONLY_STORAGE_KEY, JSON.stringify(highOnlyByProgram));
    } catch (e) {
      console.error("Failed to save high-only preferences:", e);
    }
  }, [highOnlyByProgram]);

  const loadTargets = useCallback(async (programId: string) => {
    setLoadingTargets(true);
    setChangesLoading(true);
    try {
      const [t, flow, ch] = await Promise.all([
        fetchBountyTargets(programId),
        fetchProgramFlow(programId).catch(() => null),
        fetchBountyChanges(programId, 10).catch(() => []),
      ]);
      setTargets(Array.isArray(t) ? t : []);
      setChanges(Array.isArray(ch) ? ch : []);
      if (flow) setFlowByProgram((prev) => ({ ...prev, [programId]: flow }));
    } catch (e) {
      console.error("Failed to load targets:", e);
      setTargets([]);
      setChanges([]);
    } finally {
      setLoadingTargets(false);
      setChangesLoading(false);
    }
  }, []);

  useEffect(() => {
    if (expandedProgram) loadTargets(expandedProgram);
  }, [expandedProgram, loadTargets]);

  const handleSubmit = async () => {
    if (!formName.trim() || !formInScope.trim()) return;
    setSubmitting(true);
    try {
      const inScope = formInScope.split("\n").map(s => s.trim()).filter(Boolean);
      const outScope = formOutScope.split("\n").map(s => s.trim()).filter(Boolean);
      const bountyMin = formHasBounty && formBountyMin ? Number(formBountyMin) : null;
      const bountyMax = formHasBounty && formBountyMax ? Number(formBountyMax) : null;
      await createBountyProgram({
        name: formName.trim(),
        platform: formPlatform,
        url: formUrl.trim(),
        in_scope: inScope,
        out_of_scope: outScope,
        policy_url: formPolicyUrl.trim(),
        has_bounty: formHasBounty,
        bounty_min: Number.isFinite(bountyMin as number) ? bountyMin : null,
        bounty_max: Number.isFinite(bountyMax as number) ? bountyMax : null,
        bounty_currency: formHasBounty ? formBountyCurrency.trim().toUpperCase() : "",
        asset_types: formAssetTypes,
        notes: formNotes.trim(),
        priority: formPriority,
        safe_harbor: formSafeHarbor,
      });
      setShowForm(false);
      setFormName(""); setFormPlatform("hackerone"); setFormUrl(""); setFormInScope(""); setFormOutScope("");
      setFormPolicyUrl(""); setFormHasBounty(false); setFormBountyMin(""); setFormBountyMax(""); setFormBountyCurrency("USD");
      setFormAssetTypes([]); setFormPriority("normal"); setFormSafeHarbor(false); setFormNotes("");
      await loadPrograms();
    } catch (e) {
      console.error("Create program error:", e);
    } finally {
      setSubmitting(false);
    }
  };

  /** Parse a single CSV line into fields (handles quoted commas). */
  const parseCsvLine = (line: string): string[] => {
    const fields: string[] = [];
    let i = 0;
    while (i < line.length) {
      if (line[i] === '"') {
        i++;
        const end = line.indexOf('"', i);
        if (end === -1) {
          fields.push(line.slice(i).replace(/""/g, '"'));
          break;
        }
        fields.push(line.slice(i, end).replace(/""/g, '"'));
        i = end + 1;
        if (line[i] === ",") i++;
      } else {
        const end = line.indexOf(",", i);
        if (end === -1) {
          fields.push(line.slice(i).trim());
          break;
        }
        fields.push(line.slice(i, end).trim());
        i = end + 1;
      }
    }
    return fields;
  };

  const handleCsvImport = async () => {
    let text = csvPaste.trim();
    if (csvFile && !text) {
      text = await new Promise<string>((resolve, reject) => {
        const r = new FileReader();
        r.onload = () => resolve(String(r.result ?? ""));
        r.onerror = () => reject(new Error("Falha ao ler arquivo"));
        r.readAsText(csvFile, "UTF-8");
      });
    }
    if (!text) return;
    setCsvLoading(true);
    setCsvResult(null);
    const errors: string[] = [];
    let created = 0;
    let updated = 0;
    const importedIds: string[] = [];
    const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const fields = parseCsvLine(line);
      if (fields.length < 5) {
        if (i === 0 && /^name\s*,\s*platform/i.test(line)) continue;
        errors.push(`Linha ${i + 1}: esperadas 5 colunas (name,platform,url,in_scope,out_of_scope)`);
        continue;
      }
      const [name, platform, url, inScopeStr, outScopeStr] = fields;
      if (!name?.trim() || !inScopeStr?.trim()) {
        errors.push(`Linha ${i + 1}: nome e in_scope obrigatórios`);
        continue;
      }
      const in_scope = inScopeStr.split(";").map((s) => s.trim()).filter(Boolean);
      const out_of_scope = outScopeStr.split(";").map((s) => s.trim()).filter(Boolean);
      try {
        const res = await createBountyProgram({
          name: name.trim(),
          platform: (platform?.trim() || "hackerone").toLowerCase(),
          url: (url?.trim() || "").trim(),
          in_scope,
          out_of_scope,
        });
        if (res.created) created++;
        if (res.updated) updated++;
        if (res.id) importedIds.push(res.id);
      } catch (e) {
        errors.push(`Linha ${i + 1} (${name}): ${e instanceof Error ? e.message : String(e)}`);
      }
    }
    setCsvResult({ created, updated, errors });
    setCsvFile(null);
    setCsvPaste("");
    setCsvLoading(false);
    await loadPrograms();
    for (const programId of importedIds) {
      try {
        await triggerBountyRecon(programId);
      } catch (e) {
        console.error("Recon auto-start error:", e);
      }
    }
    if (importedIds.length > 0) await loadPrograms();
  };

  const handleSuggestScope = async () => {
    if (!formUrl.trim()) return;
    setScopeLoading(true);
    setScopeHint(null);
    try {
      const suggestion = await suggestBountyScope({
        url: formUrl.trim(),
        platform: formPlatform,
      });
      if ((suggestion.in_scope ?? []).length > 0) {
        setFormInScope(suggestion.in_scope.join("\n"));
      }
      if ((suggestion.out_of_scope ?? []).length > 0) {
        setFormOutScope(suggestion.out_of_scope.join("\n"));
      }
      setScopeHint(`Escopo sugerido via ${suggestion.source}. Revise antes de salvar.`);
    } catch (e) {
      console.error("Scope suggest error:", e);
      setScopeHint("Nao foi possivel importar o escopo automaticamente.");
    } finally {
      setScopeLoading(false);
    }
  };

  const handleRecon = async (programId: string) => {
    setReconning(prev => new Set(prev).add(programId));
    try {
      await triggerBountyRecon(programId);
      await loadPrograms();
      if (expandedProgram === programId) {
        await loadTargets(programId);
      }
    } catch (e) {
      console.error("Recon trigger error:", e);
    } finally {
      setReconning(prev => {
        const s = new Set(prev);
        s.delete(programId);
        return s;
      });
    }
  };

  const handleClearError = async (programId: string) => {
    try {
      await clearBountyProgramError(programId);
      await loadPrograms();
    } catch (e) {
      console.error("Clear error:", e);
    }
  };

  const handleDelete = async (programId: string) => {
    try {
      await deleteBountyProgram(programId);
      await loadPrograms();
      if (expandedProgram === programId) {
        setExpandedProgram(null);
        setTargets([]);
      }
    } catch (e) {
      console.error("Delete program error:", e);
    }
  };

  const handleScanTarget = async (targetId: string) => {
    setScanningTargets(prev => new Set(prev).add(targetId));
    try {
      await triggerBountyTargetScan(targetId);
    } catch (e) {
      console.error("Scan target error:", e);
    }
    setTimeout(() => {
      setScanningTargets(prev => {
        const s = new Set(prev);
        s.delete(targetId);
        return s;
      });
      if (expandedProgram) loadTargets(expandedProgram);
    }, 3000);
  };

  const handleReport = async (programId: string) => {
    setReportLoading(programId);
    try {
      const md = await fetchBountyReport(programId);
      const blob = new Blob([md], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `bounty-report-${programId}.md`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error("Report error:", e);
    } finally {
      setReportLoading(null);
    }
  };

  const handleCopyTemplate = async (program: BountyProgram, target: BountyTarget) => {
    const md = buildReportTemplate(program, target);
    setTemplatePreview(md);
    try {
      await navigator.clipboard.writeText(md);
      setCopiedTemplateId(target.id);
      setTimeout(() => setCopiedTemplateId(null), 1600);
    } catch (e) {
      console.error("Copy template error:", e);
    }
  };

  const getTargetUrl = (target: BountyTarget): string => {
    const url = target.httpx?.url?.trim();
    if (url) return url;
    return `https://${target.domain}`;
  };

  const handleOpenTarget = (target: BountyTarget) => {
    const url = getTargetUrl(target);
    window.open(url, "_blank", "noopener,noreferrer");
  };

  const handleExportTopTargets = (program: BountyProgram, prioritizedTargets: BountyTarget[]) => {
    const lines: string[] = [
      `# Top Targets - ${program.name}`,
      "",
      `- Plataforma: ${program.platform || "N/A"}`,
      `- URL do programa: ${program.url || "N/A"}`,
      `- Gerado em: ${new Date().toLocaleString("pt-BR")}`,
      "",
      "## Backlog do dia",
      "",
    ];
    if (prioritizedTargets.length === 0) {
      lines.push("- Nenhum target vivo priorizado no momento.");
    } else {
      prioritizedTargets.forEach((t, idx) => {
        const findings = (t.recon_checks?.findings ?? [])
          .slice(0, 5)
          .map(f => `  - [${f.severity.toUpperCase()}] ${f.title}${f.evidence ? ` (${f.evidence})` : ""}`);
        lines.push(`${idx + 1}. ${t.domain}`);
        lines.push(`   - URL: ${getTargetUrl(t)}`);
        lines.push(`   - Score: ${t.recon_checks?.risk_score ?? 0}`);
        lines.push(`   - Achados: ${t.recon_checks?.total_findings ?? 0}`);
        if (findings.length > 0) lines.push(...findings);
        lines.push("   - TODO: validar impacto real e preparar PoC");
      });
    }
    lines.push("");
    lines.push("## Checklist de submissao");
    lines.push("- Confirmar que o alvo esta em escopo");
    lines.push("- Reproduzir sem causar indisponibilidade");
    lines.push("- Coletar evidencias claras");
    lines.push("- Descrever impacto de negocio");

    const md = lines.join("\n");
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `top-targets-${program.id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const h1Programs = programs.filter(isHackerOneProgram);
  const listedPrograms = (filterFlowStep === "" ? programs : programs.filter((p) => (p.flow_step ?? 1) === filterFlowStep))
    .filter((p) => !isHackerOneProgram(p));
  const allPrograms = (filterFlowStep === "" ? programs : programs.filter((p) => (p.flow_step ?? 1) === filterFlowStep))
    .slice()
    .sort((a, b) => (b.vuln_count ?? 0) - (a.vuln_count ?? 0));

  const filteredPrograms = programSearch.trim()
    ? allPrograms.filter(p => p.name.toLowerCase().includes(programSearch.toLowerCase()) || (p.platform || "").toLowerCase().includes(programSearch.toLowerCase()))
    : allPrograms;

  return (
    <div className="space-y-5">
      {/* Programs — elegant button */}
      <button
        type="button"
        onClick={() => { setShowProgramList(true); setProgramSearch(""); }}
        className="w-full rounded-2xl border border-[var(--border)] bg-[var(--card)] p-6 text-left hover:border-[var(--accent)]/40 hover:bg-[var(--card-hover)] transition-all group"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-[var(--accent)]/10 text-[var(--accent-light)]">
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 21h16.5M4.5 3h15M5.25 3v18m13.5-18v18M9 6.75h1.5m-1.5 3h1.5m-1.5 3h1.5m3-6H15m-1.5 3H15m-1.5 3H15M9 21v-3.375c0-.621.504-1.125 1.125-1.125h3.75c.621 0 1.125.504 1.125 1.125V21" />
              </svg>
            </div>
            <div>
              <div className="text-xl font-bold text-[var(--foreground)]">
                {allPrograms.length} <span className="text-[var(--muted)] font-normal">Programas</span>
              </div>
              <div className="flex items-center gap-3 text-sm text-[var(--muted)] mt-0.5">
                <span>{programs.filter(p => p.has_bounty).length} com bounty</span>
                <span>{programs.filter(p => p.platform === "hackerone").length} HackerOne</span>
                <span>{programs.filter(p => p.status === "reconning").length} reconning</span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-base font-medium text-[var(--accent-light)] opacity-0 group-hover:opacity-100 transition-opacity">
              Ver lista completa
            </span>
            <svg className="w-5 h-5 text-[var(--accent-light)] opacity-60 group-hover:opacity-100 transition-opacity" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
            </svg>
          </div>
        </div>
      </button>

      {/* Programs List Modal */}
      <Modal
        open={showProgramList}
        onClose={() => setShowProgramList(false)}
        title={`Programas (${filteredPrograms.length})`}
        maxWidth="max-w-4xl"
      >
        <div className="space-y-4">
          {/* Search */}
          <input
            type="text"
            value={programSearch}
            onChange={(e) => setProgramSearch(e.target.value)}
            placeholder="Buscar programa..."
            className="w-full rounded-xl bg-[var(--background)] border border-[var(--border)] px-4 py-3 text-base text-[var(--foreground)] placeholder-[var(--muted)] focus:border-[var(--accent)] focus:outline-none"
          />

          {/* List */}
          <div className="space-y-1.5 max-h-[65vh] overflow-y-auto hide-scrollbar">
            {filteredPrograms.map((p) => {
              const isReconRunning = p.status === "reconning" || reconning.has(p.id);
              const isH1 = isHackerOneProgram(p);
              const hasBounty = p.has_bounty === true;
              const vulnCount = p.vuln_count ?? 0;

              const statusDot =
                p.status === "reconning" ? "bg-blue-400 animate-pulse" :
                p.status === "error" ? "bg-red-400" :
                "bg-emerald-400";

              return (
                <div
                  key={p.id}
                  className={`rounded-xl border p-4 flex items-center gap-4 hover:bg-[var(--card-hover)] transition-all ${
                    isH1 ? "border-orange-500/20 bg-[var(--card)]" : "border-[var(--border)] bg-[var(--card)]"
                  }`}
                >
                  <span className={`h-2.5 w-2.5 rounded-full shrink-0 ${statusDot}`} />

                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-base font-bold text-[var(--foreground)] truncate">{p.name}</span>
                      <span className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-semibold uppercase ${
                        isH1 ? "bg-orange-500/15 text-orange-300" : "bg-purple-500/15 text-purple-300"
                      }`}>{p.platform || "?"}</span>
                      {hasBounty && <span className="shrink-0 rounded-full bg-green-500/15 text-green-300 px-2 py-0.5 text-xs font-semibold">$</span>}
                    </div>
                    <div className="flex items-center gap-3 text-sm text-[var(--muted)] mt-0.5">
                      <span>{p.target_count ?? 0} targets</span>
                      <span className="text-emerald-400">{p.alive_count ?? 0} vivos</span>
                      {vulnCount > 0 && <span className="text-red-400">{vulnCount} vulns</span>}
                      <span>etapa {p.flow_step ?? 1}/7</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0" onClick={(e) => e.stopPropagation()}>
                    <button
                      onClick={() => handleRecon(p.id)}
                      disabled={isReconRunning}
                      className="rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-40 px-3 py-1.5 text-sm font-semibold text-white transition"
                    >
                      {isReconRunning ? "..." : "Recon"}
                    </button>
                    <button
                      onClick={() => { setShowProgramList(false); setDetailProgram(p); }}
                      className="rounded-lg bg-[var(--accent)]/15 hover:bg-[var(--accent)]/25 px-3 py-1.5 text-sm font-semibold text-[var(--accent-light)] transition"
                    >
                      Detalhes
                    </button>
                    <button
                      onClick={() => handleDelete(p.id)}
                      className="rounded-lg bg-red-700/40 hover:bg-red-600 px-3 py-1.5 text-sm font-semibold text-red-300 transition"
                    >
                      Excluir
                    </button>
                  </div>
                </div>
              );
            })}
            {filteredPrograms.length === 0 && (
              <p className="text-center text-base text-[var(--muted)] py-8">Nenhum programa encontrado</p>
            )}
          </div>
        </div>
      </Modal>


      {/* CSV Import */}
      {showCsvImport && (
        <div className="rounded-lg border border-slate-700/60 bg-slate-800/50 p-4 space-y-3">
          <p className="text-xs text-slate-400">
            CSV: 5 colunas — <code className="text-slate-300">name,platform,url,in_scope,out_of_scope</code>. Múltiplos escopos na mesma célula separados por <code className="text-slate-300">;</code>. Primeira linha pode ser cabeçalho.
          </p>
          <div className="flex flex-col sm:flex-row gap-3">
            <label className="flex items-center gap-2 cursor-pointer">
              <span className="text-sm text-slate-300">Arquivo .csv</span>
              <input
                type="file"
                accept=".csv"
                className="text-sm text-slate-400 file:mr-2 file:rounded file:border-0 file:bg-slate-700 file:px-3 file:py-1.5 file:text-white"
                onChange={(e) => setCsvFile(e.target.files?.[0] ?? null)}
              />
            </label>
            <span className="text-slate-500 text-sm">ou cole abaixo:</span>
          </div>
          <textarea
            value={csvPaste}
            onChange={(e) => setCsvPaste(e.target.value)}
            placeholder={"name,platform,url,in_scope,out_of_scope\nExample Corp,hackerone,https://hackerone.com/example,*.example.com;*.api.example.com,blog.example.com"}
            rows={5}
            className="w-full rounded bg-slate-900 border border-slate-600 px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none font-mono"
          />
          <div className="flex items-center gap-3 flex-wrap">
            <button
              onClick={handleCsvImport}
              disabled={csvLoading || (!csvFile && !csvPaste.trim())}
              className="rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 px-4 py-2 text-sm font-semibold text-white transition"
            >
              {csvLoading ? "Importando..." : "Importar"}
            </button>
            {csvResult && (
              <span className="text-sm text-slate-300">
                {csvResult.created > 0 && <span className="text-emerald-400">{csvResult.created} criados</span>}
                {csvResult.updated > 0 && <span className="text-sky-400"> {csvResult.updated} atualizados</span>}
                {csvResult.errors.length > 0 && (
                  <span className="text-amber-400"> {csvResult.errors.length} erros</span>
                )}
              </span>
            )}
          </div>
          {csvResult && csvResult.errors.length > 0 && (
            <ul className="text-xs text-amber-400/90 list-disc list-inside max-h-24 overflow-y-auto">
              {csvResult.errors.slice(0, 10).map((err, i) => (
                <li key={i}>{err}</li>
              ))}
              {csvResult.errors.length > 10 && (
                <li>… e mais {csvResult.errors.length - 10} erros</li>
              )}
            </ul>
          )}
        </div>
      )}

      {/* Form */}
      {showForm && (
        <div className="rounded-lg border border-slate-700/60 bg-slate-800/50 p-4 space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Nome do Programa</label>
              <input
                type="text"
                value={formName}
                onChange={e => setFormName(e.target.value)}
                placeholder="Ex: Example Corp"
                className="w-full rounded bg-slate-900 border border-slate-600 px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Plataforma</label>
              <select
                value={formPlatform}
                onChange={e => setFormPlatform(e.target.value)}
                className="w-full rounded bg-slate-900 border border-slate-600 px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none"
              >
                {PLATFORM_OPTS.map(o => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">URL da Política / Regras</label>
              <input
                type="url"
                value={formPolicyUrl}
                onChange={e => setFormPolicyUrl(e.target.value)}
                placeholder="https://hackerone.com/program/policy"
                className="w-full rounded bg-slate-900 border border-slate-600 px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
              />
            </div>
            <div className="flex flex-col gap-2">
              <label className="block text-xs text-slate-400">Metadados</label>
              <div className="flex flex-wrap gap-3 text-xs text-slate-200">
                <label className="inline-flex items-center gap-1 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formSafeHarbor}
                    onChange={e => setFormSafeHarbor(e.target.checked)}
                    className="h-3 w-3 rounded border-slate-500 bg-slate-900"
                  />
                  <span>Safe Harbor</span>
                </label>
                <div className="flex items-center gap-1">
                  <span className="text-slate-400">Prioridade:</span>
                  <select
                    value={formPriority}
                    onChange={e => setFormPriority(e.target.value)}
                    className="rounded bg-slate-900 border border-slate-600 px-2 py-1 text-[11px] text-white focus:border-emerald-500 focus:outline-none"
                  >
                    <option value="baixa">Baixa</option>
                    <option value="normal">Normal</option>
                    <option value="alta">Alta</option>
                  </select>
                </div>
              </div>
            </div>
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">URL do Programa</label>
            <div className="flex gap-2">
              <input
                type="url"
                value={formUrl}
                onChange={e => setFormUrl(e.target.value)}
                placeholder="https://hackerone.com/example"
                className="w-full rounded bg-slate-900 border border-slate-600 px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
              />
              <button
                type="button"
                onClick={handleSuggestScope}
                disabled={scopeLoading || !formUrl.trim()}
                className="shrink-0 rounded bg-sky-700 hover:bg-sky-600 disabled:opacity-40 px-3 py-2 text-xs font-semibold text-white transition"
              >
                {scopeLoading ? "Importando..." : "Importar escopo"}
              </button>
            </div>
            {scopeHint && (
              <p className="mt-1 text-[11px] text-slate-400">{scopeHint}</p>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">In-Scope (um por linha)</label>
              <textarea
                value={formInScope}
                onChange={e => setFormInScope(e.target.value)}
                placeholder={"*.example.com\n*.api.example.com\n10.0.0.0/24"}
                rows={4}
                className="w-full rounded bg-slate-900 border border-slate-600 px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none font-mono"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Out-of-Scope (um por linha)</label>
              <textarea
                value={formOutScope}
                onChange={e => setFormOutScope(e.target.value)}
                placeholder={"blog.example.com\nstatus.example.com"}
                rows={4}
                className="w-full rounded bg-slate-900 border border-slate-600 px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none font-mono"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Bounty / Recompensa</label>
              <div className="flex items-center gap-2 mb-2 text-xs text-slate-200">
                <label className="inline-flex items-center gap-1 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formHasBounty}
                    onChange={e => setFormHasBounty(e.target.checked)}
                    className="h-3 w-3 rounded border-slate-500 bg-slate-900"
                  />
                  <span>Paga bounty</span>
                </label>
              </div>
              <div className="flex gap-2">
                <input
                  type="number"
                  min="0"
                  step="0.01"
                  value={formBountyMin}
                  onChange={e => setFormBountyMin(e.target.value)}
                  placeholder="Min"
                  disabled={!formHasBounty}
                  className="w-1/3 rounded bg-slate-900 border border-slate-600 px-2 py-1.5 text-xs text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
                />
                <input
                  type="number"
                  min="0"
                  step="0.01"
                  value={formBountyMax}
                  onChange={e => setFormBountyMax(e.target.value)}
                  placeholder="Max"
                  disabled={!formHasBounty}
                  className="w-1/3 rounded bg-slate-900 border border-slate-600 px-2 py-1.5 text-xs text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
                />
                <input
                  type="text"
                  value={formBountyCurrency}
                  onChange={e => setFormBountyCurrency(e.target.value.toUpperCase())}
                  placeholder="USD"
                  disabled={!formHasBounty}
                  className="w-1/3 rounded bg-slate-900 border border-slate-600 px-2 py-1.5 text-xs text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
                />
              </div>
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Tipos de ativo em escopo</label>
              <div className="flex flex-wrap gap-3 text-xs text-slate-200">
                {[
                  { value: "web", label: "Web" },
                  { value: "api", label: "API" },
                  { value: "mobile", label: "Mobile" },
                  { value: "outros", label: "Outros" },
                ].map(opt => (
                  <label key={opt.value} className="inline-flex items-center gap-1 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formAssetTypes.includes(opt.value)}
                      onChange={e => {
                        const checked = e.target.checked;
                        setFormAssetTypes(prev =>
                          checked ? [...prev, opt.value] : prev.filter(v => v !== opt.value)
                        );
                      }}
                      className="h-3 w-3 rounded border-slate-500 bg-slate-900"
                    />
                    <span>{opt.label}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">Notas / Estratégia</label>
            <textarea
              value={formNotes}
              onChange={e => setFormNotes(e.target.value)}
              placeholder="Ex.: focar em auth, IDOR, expor APIs internas, etc."
              rows={3}
              className="w-full rounded bg-slate-900 border border-slate-600 px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
            />
          </div>

          <div className="flex justify-end">
            <button
              onClick={handleSubmit}
              disabled={submitting || !formName.trim() || !formInScope.trim()}
              className="rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 px-5 py-2 text-sm font-semibold text-white transition"
            >
              {submitting ? "Salvando..." : "Criar Programa"}
            </button>
          </div>
        </div>
      )}

      {/* (seção "Outros Programas" foi unificada na grade acima) */}

      {/* Program cards (legado oculto) */}
      {false && listedPrograms.length === 0 && !showForm && (
        <p className="text-center text-sm text-slate-500 py-6">
          Nenhum programa fora da HackerOne para listar.
        </p>
      )}

      {false && filterFlowStep !== "" && listedPrograms.length === 0 && programs.length > 0 && (
        <p className="text-center text-sm text-slate-500 py-4">
          Nenhum programa nao-H1 na etapa {filterFlowStep}.
        </p>
      )}

      <div className="hidden">
        {listedPrograms
          .slice()
          .sort((a, b) => {
            const aHasRecon = a.last_recon ? 1 : 0;
            const bHasRecon = b.last_recon ? 1 : 0;
            if (aHasRecon !== bHasRecon) return bHasRecon - aHasRecon;
            const aAlive = a.alive_count ?? 0;
            const bAlive = b.alive_count ?? 0;
            if (aAlive !== bAlive) return bAlive - aAlive;
            return (b.vuln_count ?? 0) - (a.vuln_count ?? 0);
          })
          .map(p => {
          const isReconRunning = p.status === "reconning" || reconning.has(p.id);
          const isH1 = p.platform === "hackerone" && (p.url || "").includes("hackerone.com");
          const isH1Ready = isH1 && (p.flow_step ?? 1) >= 6;
          const hasBounty = p.has_bounty === true;
          const dotColor = p.status === "reconning" ? "bg-blue-400" : p.status === "error" ? "bg-red-400" : isH1Ready ? "bg-orange-400" : "bg-emerald-400";
          const isOpen = expandedProgram === p.id;
          const highOnly = highOnlyByProgram[p.id] === true;
          const visibleTargets = highOnly
            ? targets.filter(t => (t.recon_checks?.high ?? 0) > 0)
            : targets;
          const prioritizedTargets = [...targets]
            .filter(t => t.alive)
            .sort((a, b) => {
              const scoreA = a.recon_checks?.risk_score ?? 0;
              const scoreB = b.recon_checks?.risk_score ?? 0;
              if (scoreA !== scoreB) return scoreB - scoreA;
              return (b.recon_checks?.total_findings ?? 0) - (a.recon_checks?.total_findings ?? 0);
            })
            .slice(0, 5);

          return (
            <div key={p.id} className={isH1Ready ? "bg-orange-500/[0.03]" : ""}>
              {/* Row header — always visible */}
              <div
                onClick={() => {
                  if (isOpen) { setExpandedProgram(null); }
                  else { setExpandedProgram(p.id); loadTargets(p.id); }
                }}
                className="flex items-center gap-2 px-3 py-2.5 sm:px-4 sm:py-3 cursor-pointer hover:bg-slate-800/30 transition-colors group"
              >
                {/* Expand chevron */}
                <svg className={`w-3.5 h-3.5 text-slate-500 shrink-0 transition-transform ${isOpen ? "rotate-90" : ""}`} fill="none" viewBox="0 0 24 24" strokeWidth={2.5} stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
                </svg>

                {/* Status dot */}
                <span className={`h-2 w-2 rounded-full shrink-0 ${dotColor} ${isReconRunning ? "animate-pulse" : ""}`} />

                {/* Name */}
                <span className={`text-sm font-medium truncate min-w-0 flex-1 ${
                  isH1Ready ? "text-orange-200" : "text-white"
                }`}>
                  {p.name}
                </span>

                {/* Badges */}
                <div className="flex items-center gap-1 shrink-0">
                  <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border ${
                    isH1
                      ? "bg-orange-500/20 text-orange-300 border-orange-500/30"
                      : "bg-purple-500/20 text-purple-300 border-purple-500/30"
                  }`}>
                    {p.platform || "?"}
                  </span>
                  {hasBounty && (
                    <span className="text-[9px] font-bold px-1 py-0.5 rounded bg-green-500/20 text-green-300 border border-green-500/30">$</span>
                  )}
                  {isH1Ready && (
                    <span className="text-[9px] font-bold px-1 py-0.5 rounded bg-orange-500/25 text-orange-300 border border-orange-500/40 animate-pulse">H1</span>
                  )}
                </div>

                {/* Counters */}
                <div className="hidden sm:flex items-center gap-3 shrink-0 text-[11px] tabular-nums">
                  <span className="text-slate-400">{p.target_count ?? 0} <span className="text-slate-600">tgt</span></span>
                  <span className="text-emerald-400">{p.alive_count ?? 0} <span className="text-slate-600">up</span></span>
                  <span className="text-red-400">{p.vuln_count ?? 0} <span className="text-slate-600">vln</span></span>
                </div>

                {/* Step */}
                <span className={`text-[10px] shrink-0 tabular-nums ${isH1 ? "text-orange-400/70" : "text-slate-500"}`}>
                  {p.flow_step ?? 1}/7
                </span>
              </div>

              {/* Expanded content — inline */}
              {isOpen && (
                <div className="border-t border-slate-700/40 bg-slate-950/40 px-4 py-4 sm:px-6 space-y-4">
                  {/* Mobile counters */}
                  <div className="sm:hidden grid grid-cols-3 gap-2">
                    <div className="rounded-lg bg-slate-800/60 px-2 py-1.5 text-center">
                      <div className="text-sm font-bold text-white tabular-nums">{p.target_count ?? 0}</div>
                      <div className="text-[9px] text-slate-500 uppercase">Targets</div>
                    </div>
                    <div className="rounded-lg bg-slate-800/60 px-2 py-1.5 text-center">
                      <div className="text-sm font-bold text-emerald-400 tabular-nums">{p.alive_count ?? 0}</div>
                      <div className="text-[9px] text-slate-500 uppercase">Vivos</div>
                    </div>
                    <div className="rounded-lg bg-slate-800/60 px-2 py-1.5 text-center">
                      <div className="text-sm font-bold text-red-400 tabular-nums">{p.vuln_count ?? 0}</div>
                      <div className="text-[9px] text-slate-500 uppercase">Vulns</div>
                    </div>
                  </div>

                  {/* Info + URL */}
                  {p.url && (
                    <a href={p.url} target="_blank" rel="noopener noreferrer" className="text-xs text-accent hover:underline truncate block">
                      {p.url}
                    </a>
                  )}
                  {hasBounty && (p.bounty_min || p.bounty_max) && (
                    <span className="text-[11px] text-green-400 font-semibold">
                      {p.bounty_currency || "USD"} {p.bounty_min ?? "?"} – {p.bounty_max ?? "?"}
                    </span>
                  )}

                  {p.status === "error" && p.last_recon_error && (
                    <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-300">
                      {p.last_recon_error}
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex flex-wrap gap-2">
                    <button
                      onClick={() => handleRecon(p.id)}
                      disabled={isReconRunning}
                      className="rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-40 px-3 py-1.5 text-xs font-semibold text-white transition"
                    >
                      {isReconRunning ? "Recon..." : "Recon"}
                    </button>
                    <button
                      onClick={() => handleReport(p.id)}
                      disabled={reportLoading === p.id}
                      className="rounded-lg bg-slate-600 hover:bg-slate-500 disabled:opacity-40 px-3 py-1.5 text-xs font-semibold text-white transition"
                    >
                      {reportLoading === p.id ? "..." : "Report"}
                    </button>
                    {(p.status === "error" || p.status === "reconning") && (
                      <button
                        onClick={() => handleClearError(p.id)}
                        className="rounded-lg bg-amber-600 hover:bg-amber-500 px-3 py-1.5 text-xs font-semibold text-white transition"
                      >
                        {p.status === "reconning" ? "Cancelar" : "Limpar Erro"}
                      </button>
                    )}
                    <button
                      onClick={() => { handleDelete(p.id); setExpandedProgram(null); }}
                      className="rounded-lg bg-red-700/60 hover:bg-red-600 px-3 py-1.5 text-xs font-semibold text-red-200 transition ml-auto"
                    >
                      Excluir
                    </button>
                  </div>

                  {/* Flow HackerOne */}
                  {flowByProgram[p.id] && (
                    <div className="space-y-3">
                      <div className="rounded-lg border border-slate-700/70 bg-slate-900/60 p-3">
                        <div className="mb-2 flex items-center justify-between">
                          <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Fluxo</span>
                          <span className="text-[10px] font-medium text-emerald-300">Passo {flowByProgram[p.id].current_step}/7</span>
                        </div>
                        <div className="flex flex-wrap gap-1 text-[10px]">
                          {flowByProgram[p.id].steps.map((s) => (
                            <span
                              key={s.n}
                              className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 border ${
                                s.done
                                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                                  : "border-slate-700/70 text-slate-500"
                              }`}
                            >
                              {s.done ? "✓" : s.n}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Scope */}
                  <div className="flex flex-wrap gap-1">
                    {(p.in_scope ?? []).map((s: string, i: number) => (
                      <code key={i} className="rounded bg-emerald-500/10 border border-emerald-500/20 px-1.5 py-0.5 text-[10px] text-emerald-300">{s}</code>
                    ))}
                    {(p.out_of_scope ?? []).map((s: string, i: number) => (
                      <code key={`o${i}`} className="rounded bg-red-500/10 border border-red-500/20 px-1.5 py-0.5 text-[10px] text-red-300 line-through">{s}</code>
                    ))}
                  </div>

                  {/* Recon Intelligence */}
                  {p.stats && ((p.stats.asns_discovered ?? 0) > 0 || (p.stats.new_subdomains ?? 0) > 0) && (
                    <div className="flex flex-wrap gap-2">
                      {(p.stats.asns_discovered ?? 0) > 0 && (
                        <div className="rounded-lg bg-violet-500/10 border border-violet-500/20 px-2.5 py-1.5">
                          <div className="text-sm font-bold text-violet-300 tabular-nums">{p.stats.asns_discovered}</div>
                          <div className="text-[9px] text-slate-400">ASNs</div>
                        </div>
                      )}
                      {(p.stats.org_prefixes ?? 0) > 0 && (
                        <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 px-2.5 py-1.5">
                          <div className="text-sm font-bold text-amber-300 tabular-nums">{p.stats.org_prefixes}</div>
                          <div className="text-[9px] text-slate-400">Prefixos</div>
                        </div>
                      )}
                      {(p.stats.new_subdomains ?? 0) > 0 && (
                        <div className="rounded-lg bg-lime-500/10 border border-lime-500/20 px-2.5 py-1.5">
                          <div className="text-sm font-bold text-lime-300 tabular-nums">{p.stats.new_subdomains}</div>
                          <div className="text-[9px] text-slate-400">Novos subs</div>
                        </div>
                      )}
                      <div className="rounded-lg bg-slate-700/30 border border-slate-600/30 px-2.5 py-1.5">
                        <div className="text-sm font-bold text-slate-200 tabular-nums">{p.stats.subdomains ?? 0}</div>
                        <div className="text-[9px] text-slate-400">Total</div>
                      </div>
                    </div>
                  )}

                  {/* Recent Changes */}
                  {changes.length > 0 && (
                    <div className="rounded-lg border border-lime-500/20 bg-lime-500/5 p-3">
                      <div className="text-[10px] font-semibold uppercase tracking-wider text-lime-300 mb-2">Mudanças</div>
                      <div className="space-y-1.5 max-h-32 overflow-y-auto">
                        {changes.map((ch) => (
                          <div key={ch.id} className="text-[10px]">
                            <span className="text-slate-500">{new Date(ch.timestamp).toLocaleString("pt-BR")}</span>
                            {ch.new_subdomains.length > 0 && (
                              <span className="text-emerald-400 ml-2">+{ch.new_subdomains.length} novos</span>
                            )}
                            {ch.removed_subdomains.length > 0 && (
                              <span className="text-red-400 ml-2">-{ch.removed_subdomains.length}</span>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Targets */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                        Targets ({visibleTargets.length})
                      </span>
                      <div className="flex items-center gap-2">
                        <label className="inline-flex items-center gap-1.5 text-[10px] text-slate-400 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={highOnly}
                            onChange={(e) => setHighOnlyByProgram(prev => ({ ...prev, [p.id]: e.target.checked }))}
                            className="rounded border-slate-600 bg-slate-900 h-3 w-3"
                          />
                          HIGH
                        </label>
                        <button
                          onClick={() => handleExportTopTargets(p, prioritizedTargets)}
                          className="rounded bg-slate-700 hover:bg-slate-600 px-2 py-0.5 text-[10px] font-semibold text-white transition"
                        >
                          Export
                        </button>
                      </div>
                    </div>

                    {loadingTargets ? (
                      <p className="text-xs text-slate-500 py-2 text-center">Carregando...</p>
                    ) : visibleTargets.length === 0 ? (
                      <p className="text-xs text-slate-500 py-2 text-center">Sem targets. Execute Recon.</p>
                    ) : (
                      <div className="space-y-1 max-h-64 overflow-y-auto">
                        {visibleTargets.map(t => (
                          <div key={t.id} className="rounded-lg border border-slate-700/40 bg-slate-800/30 px-3 py-2 hover:bg-slate-800/50 transition-colors">
                            <div className="flex items-center justify-between gap-2">
                              <div className="min-w-0 flex-1">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono text-emerald-300 text-xs truncate">{t.domain}</span>
                                  {t.is_new && (
                                    <span className="rounded bg-lime-500/20 border border-lime-500/40 px-1 py-0.5 text-[8px] font-bold text-lime-300 uppercase animate-pulse">
                                      NEW
                                    </span>
                                  )}
                                  <span className={`text-[9px] font-semibold uppercase ${STATUS_COLORS[t.status] ?? "text-slate-400"}`}>
                                    {t.status}
                                  </span>
                                </div>
                                <div className="flex items-center gap-2 mt-0.5 text-[10px] text-slate-500">
                                  {t.httpx?.status_code && <span>{t.httpx.status_code}</span>}
                                  {(t.httpx?.tech ?? []).length > 0 && <span>{t.httpx!.tech!.slice(0, 2).join(", ")}</span>}
                                  {t.recon_checks?.checked && (
                                    <span className={
                                      (t.recon_checks?.high ?? 0) > 0 ? "text-red-300 font-semibold"
                                      : (t.recon_checks?.total_findings ?? 0) > 0 ? "text-amber-300"
                                      : "text-emerald-300"
                                    }>
                                      {t.recon_checks?.total_findings ?? 0} achado(s)
                                    </span>
                                  )}
                                </div>
                              </div>
                              <div className="flex items-center gap-1 shrink-0">
                                <button onClick={() => handleCopyTemplate(p, t)} className="rounded bg-slate-600 hover:bg-slate-500 px-2 py-0.5 text-[10px] font-semibold text-white transition">
                                  {copiedTemplateId === t.id ? "OK" : "Tmpl"}
                                </button>
                                <button onClick={() => handleOpenTarget(t)} className="rounded bg-sky-700 hover:bg-sky-600 px-2 py-0.5 text-[10px] font-semibold text-white transition">
                                  Abrir
                                </button>
                                <button
                                  onClick={() => handleScanTarget(t.id)}
                                  disabled={scanningTargets.has(t.id) || !t.alive}
                                  className="rounded bg-amber-600 hover:bg-amber-500 disabled:opacity-30 px-2 py-0.5 text-[10px] font-semibold text-white transition"
                                >
                                  {scanningTargets.has(t.id) ? "..." : "Scan"}
                                </button>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Top 5 */}
                  {prioritizedTargets.length > 0 && (
                    <div className="rounded-lg border border-slate-700/40 bg-slate-900/40 p-3">
                      <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">Top 5</div>
                      <div className="space-y-1">
                        {prioritizedTargets.map((t, idx) => (
                          <div key={t.id} className="flex items-center justify-between gap-2 text-xs">
                            <div className="min-w-0 flex items-center gap-2">
                              <span className="text-slate-500 font-bold w-3 text-right shrink-0">{idx + 1}</span>
                              <span className="font-mono text-emerald-300 truncate">{t.domain}</span>
                              <span className="text-slate-500 shrink-0">{t.recon_checks?.risk_score ?? 0}pts</span>
                            </div>
                            <button
                              onClick={() => handleCopyTemplate(p, t)}
                              className="rounded bg-sky-700 hover:bg-sky-600 px-2 py-0.5 text-[10px] font-semibold text-white transition shrink-0"
                            >
                              Report
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Preview do template copiado */}
      {templatePreview && (
        <div
          className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/60 sm:p-4"
          onClick={() => setTemplatePreview(null)}
        >
          <div
            className="relative w-full max-h-[90vh] sm:max-h-[85vh] sm:max-w-2xl rounded-t-xl sm:rounded-xl border border-slate-600 bg-slate-900 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-slate-700 px-5 py-4">
              <span className="text-lg font-semibold text-slate-200">Preview</span>
              <button
                type="button"
                onClick={() => setTemplatePreview(null)}
                className="rounded bg-slate-600 px-4 py-2 text-base font-medium text-white hover:bg-slate-500"
              >
                Fechar
              </button>
            </div>
            <pre className="max-h-[75vh] sm:max-h-[70vh] overflow-auto whitespace-pre-wrap p-5 sm:p-6 text-left text-base text-slate-300">
              {templatePreview}
            </pre>
          </div>
        </div>
      )}

      {/* Program Detail Modal */}
      <Modal
        open={!!detailProgram}
        onClose={() => setDetailProgram(null)}
        title={detailProgram ? `Programa: ${detailProgram.name}` : ""}
        maxWidth="max-w-3xl"
      >
        {detailProgram && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-5 text-center">
                <div className="text-3xl font-bold text-[var(--foreground)] tabular-nums">{detailProgram.target_count ?? 0}</div>
                <div className="text-base text-[var(--muted)] mt-2">Targets</div>
              </div>
              <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-5 text-center">
                <div className="text-3xl font-bold text-emerald-400 tabular-nums">{detailProgram.alive_count ?? 0}</div>
                <div className="text-base text-[var(--muted)] mt-2">Vivos</div>
              </div>
              <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-5 text-center">
                <div className="text-3xl font-bold text-red-400 tabular-nums">{detailProgram.vuln_count ?? 0}</div>
                <div className="text-base text-[var(--muted)] mt-2">Vulns</div>
              </div>
              <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-5 text-center">
                <div className="text-3xl font-bold text-[var(--accent-light)] tabular-nums">{detailProgram.flow_step ?? 1}/7</div>
                <div className="text-base text-[var(--muted)] mt-2">Etapa</div>
              </div>
            </div>

            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <span className="text-base text-[var(--muted)]">Plataforma:</span>
                <span className="text-base font-semibold text-[var(--foreground)] uppercase">{detailProgram.platform || "N/A"}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-base text-[var(--muted)]">Status:</span>
                <span className="text-base font-semibold text-[var(--foreground)]">{detailProgram.status}</span>
              </div>
              {detailProgram.url && (
                <div className="flex items-center gap-3">
                  <span className="text-base text-[var(--muted)]">URL:</span>
                  <a href={detailProgram.url} target="_blank" rel="noopener noreferrer" className="text-base text-[var(--accent-light)] hover:underline truncate">
                    {detailProgram.url}
                  </a>
                </div>
              )}
              {detailProgram.has_bounty && (
                <div className="flex items-center gap-3">
                  <span className="text-base text-[var(--muted)]">Bounty:</span>
                  <span className="text-base font-semibold text-green-400">
                    {detailProgram.bounty_currency || "USD"} {detailProgram.bounty_min ?? "?"} - {detailProgram.bounty_max ?? "?"}
                  </span>
                </div>
              )}
            </div>

            {(detailProgram.in_scope ?? []).length > 0 && (
              <div>
                <h3 className="text-base font-semibold text-[var(--foreground)] mb-3">In-Scope</h3>
                <div className="flex flex-wrap gap-2">
                  {detailProgram.in_scope!.map((s: string, i: number) => (
                    <code key={i} className="rounded bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 text-base text-emerald-300">{s}</code>
                  ))}
                </div>
              </div>
            )}

            {(detailProgram.out_of_scope ?? []).length > 0 && (
              <div>
                <h3 className="text-base font-semibold text-[var(--foreground)] mb-3">Out-of-Scope</h3>
                <div className="flex flex-wrap gap-2">
                  {detailProgram.out_of_scope!.map((s: string, i: number) => (
                    <code key={i} className="rounded bg-red-500/10 border border-red-500/20 px-3 py-1.5 text-base text-red-300 line-through">{s}</code>
                  ))}
                </div>
              </div>
            )}

            {detailProgram.last_recon && (
              <div className="flex items-center gap-3">
                <span className="text-base text-[var(--muted)]">Último recon:</span>
                <span className="text-base text-[var(--foreground)]">{new Date(detailProgram.last_recon).toLocaleString("pt-BR")}</span>
              </div>
            )}

            {detailProgram.last_recon_error && (
              <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-5">
                <span className="text-base text-red-400">{detailProgram.last_recon_error}</span>
              </div>
            )}
          </div>
        )}
      </Modal>

      {/* Target Detail Modal */}
      <Modal
        open={!!detailTarget}
        onClose={() => setDetailTarget(null)}
        title={detailTarget ? `Target: ${detailTarget.domain}` : ""}
        maxWidth="max-w-3xl"
      >
        {detailTarget && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
              <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-5 text-center">
                <div className={`text-3xl font-bold tabular-nums ${detailTarget.alive ? "text-emerald-400" : "text-red-400"}`}>
                  {detailTarget.alive ? "Online" : "Offline"}
                </div>
                <div className="text-base text-[var(--muted)] mt-2">Status</div>
              </div>
              <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-5 text-center">
                <div className="text-3xl font-bold text-[var(--foreground)] tabular-nums">{detailTarget.httpx?.status_code ?? "-"}</div>
                <div className="text-base text-[var(--muted)] mt-2">HTTP Status</div>
              </div>
              <div className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-5 text-center">
                <div className="text-3xl font-bold text-amber-400 tabular-nums">{detailTarget.recon_checks?.total_findings ?? 0}</div>
                <div className="text-base text-[var(--muted)] mt-2">Achados</div>
              </div>
            </div>

            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <span className="text-base text-[var(--muted)]">Domínio:</span>
                <span className="text-base font-mono font-semibold text-[var(--foreground)]">{detailTarget.domain}</span>
              </div>
              {detailTarget.httpx?.url && (
                <div className="flex items-center gap-3">
                  <span className="text-base text-[var(--muted)]">URL:</span>
                  <a href={detailTarget.httpx.url} target="_blank" rel="noopener noreferrer" className="text-base text-[var(--accent-light)] hover:underline">
                    {detailTarget.httpx.url}
                  </a>
                </div>
              )}
              {(detailTarget.ips ?? []).length > 0 && (
                <div className="flex items-center gap-3">
                  <span className="text-base text-[var(--muted)]">IPs:</span>
                  <span className="text-base font-mono text-[var(--foreground)]">{detailTarget.ips!.join(", ")}</span>
                </div>
              )}
              {(detailTarget.httpx?.tech ?? []).length > 0 && (
                <div className="flex items-start gap-3">
                  <span className="text-base text-[var(--muted)] shrink-0">Tecnologias:</span>
                  <div className="flex flex-wrap gap-2">
                    {detailTarget.httpx!.tech!.map((tech, i) => (
                      <span key={i} className="rounded bg-cyan-500/10 border border-cyan-500/20 px-3 py-1 text-base text-cyan-300">{tech}</span>
                    ))}
                  </div>
                </div>
              )}
              {detailTarget.recon_checks?.risk_score != null && (
                <div className="flex items-center gap-3">
                  <span className="text-base text-[var(--muted)]">Risk Score:</span>
                  <span className="text-base font-bold text-amber-400">{detailTarget.recon_checks.risk_score} pts</span>
                </div>
              )}
            </div>

            {(detailTarget.recon_checks?.findings ?? []).length > 0 && (
              <div>
                <h3 className="text-base font-semibold text-[var(--foreground)] mb-3">Findings</h3>
                <div className="space-y-2.5">
                  {detailTarget.recon_checks!.findings!.map((f, i) => (
                    <div key={i} className="rounded-xl bg-[var(--background)] border border-[var(--border)] p-4">
                      <div className="flex items-center justify-between gap-2 mb-1.5">
                        <span className="text-base font-semibold text-[var(--foreground)]">{f.title}</span>
                        <span className={`rounded px-2.5 py-1 text-sm font-bold uppercase ${
                          f.severity === "critical" ? "bg-red-500/20 text-red-300" :
                          f.severity === "high" ? "bg-orange-500/20 text-orange-300" :
                          f.severity === "medium" ? "bg-amber-500/20 text-amber-300" :
                          f.severity === "low" ? "bg-sky-500/20 text-sky-300" :
                          "bg-slate-500/20 text-slate-300"
                        }`}>
                          {f.severity}
                        </span>
                      </div>
                      {f.evidence && (
                        <p className="text-base text-[var(--muted)] break-all">{f.evidence}</p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* ── Generate & Copy Report ── */}
            {(detailTarget.recon_checks?.findings ?? []).length > 0 && (
              <ReportActions targetId={detailTarget.id} program={programs.find(p => p.id === detailTarget.program_id) ?? null} target={detailTarget} />
            )}
          </div>
        )}
      </Modal>
    </div>
  );
}
