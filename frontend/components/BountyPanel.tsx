"use client";

import { Fragment, useEffect, useState, useCallback } from "react";
import {
  fetchBountyPrograms,
  fetchBountyTargets,
  fetchBountyStats,
  fetchProgramFlow,
  createBountyProgram,
  suggestBountyScope,
  triggerBountyRecon,
  clearBountyProgramError,
  submitBountyToHackerOne,
  triggerBountyTargetScan,
  deleteBountyProgram,
  fetchBountyReport,
  syncBugScraperPrograms,
  deleteAllBountyPrograms,
  type BountyProgram,
  type BountyTarget,
  type BountyStats,
  type BountyProgramFlow,
} from "@/lib/api";

const REFRESH_MS = 10_000;
const HIGH_ONLY_STORAGE_KEY = "bounty-high-only-by-program";

const PLATFORM_OPTS = [
  { value: "hackerone", label: "HackerOne" },
  { value: "bugcrowd", label: "Bugcrowd" },
  { value: "intigriti", label: "Intigriti" },
  { value: "yeswehack", label: "YesWeHack" },
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
    <div className="rounded-lg bg-slate-800/60 border border-slate-700/50 px-4 py-3 text-center">
      <div className="text-2xl font-bold text-white tabular-nums">{value}</div>
      <div className="text-[11px] text-slate-400 uppercase tracking-wider mt-0.5">{label}</div>
    </div>
  );
}

/** HackerOne: botão só habilitado quando o report cumpre o mínimo (título, descrição, passos, impacto, PoC). */
function targetFulfillsHackerOneRules(target: BountyTarget): boolean {
  const findings = target.recon_checks?.findings ?? [];
  if (findings.length === 0) return false;
  const hasTitle = findings.some((f) => (f.title || "").trim().length > 0);
  const hasEvidence = findings.some((f) => (f.evidence || "").trim().length > 0);
  return hasTitle && (target.domain || "").trim().length > 0 && hasEvidence;
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
  const [submitHackerOneLoading, setSubmitHackerOneLoading] = useState<string | null>(null);
  const [submitTargetToH1Loading, setSubmitTargetToH1Loading] = useState<string | null>(null);
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

  const loadPrograms = useCallback(async () => {
    try {
      const [p, s] = await Promise.all([fetchBountyPrograms(), fetchBountyStats()]);
      const list = Array.isArray(p) ? p : [];
      const inError = list.filter((prog) => prog.status === "error");
      if (inError.length > 0) {
        for (const prog of inError) {
          try {
            await clearBountyProgramError(prog.id);
          } catch (e) {
            console.error("Auto-clear error for program:", prog.id, e);
          }
        }
        const [p2, s2] = await Promise.all([fetchBountyPrograms(), fetchBountyStats()]);
        setPrograms(Array.isArray(p2) ? p2 : []);
        setStats(s2);
      } else {
        setPrograms(list);
        setStats(s);
      }
    } catch (e) {
      console.error("BountyPanel load error:", e);
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
    try {
      const [t, flow] = await Promise.all([
        fetchBountyTargets(programId),
        fetchProgramFlow(programId).catch(() => null),
      ]);
      setTargets(Array.isArray(t) ? t : []);
      if (flow) setFlowByProgram((prev) => ({ ...prev, [programId]: flow }));
    } catch (e) {
      console.error("Failed to load targets:", e);
      setTargets([]);
    } finally {
      setLoadingTargets(false);
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

  const handleSubmitHackerOne = async (programId: string) => {
    setSubmitHackerOneLoading(programId);
    try {
      const res = await submitBountyToHackerOne(programId);
      if (res.url) {
        window.open(res.url, "_blank", "noopener,noreferrer");
        alert("Report enviado ao HackerOne. Abrindo o report em nova aba.");
      } else {
        alert("Report enviado ao HackerOne.");
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      alert(`Falha ao enviar ao HackerOne: ${msg}\n\nConfigure HACKERONE_API_USERNAME e HACKERONE_API_TOKEN no backend.`);
    } finally {
      setSubmitHackerOneLoading(null);
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

  const handleSubmitTargetToHackerOne = async (program: BountyProgram, target: BountyTarget) => {
    if (!(program.platform === "hackerone" && (program.url || "").includes("hackerone.com"))) return;
    setSubmitTargetToH1Loading(target.id);
    try {
      const body = buildReportTemplate(program, target);
      const titleLine = body.split("\n").find((l) => l.startsWith("# "));
      const title = (titleLine?.replace(/^#\s*/, "") || `Report ${target.domain}`).slice(0, 250);
      const severity = maxSeverity(target.recon_checks?.findings ?? []);
      const res = await submitBountyToHackerOne(program.id, {
        title,
        vulnerability_information: body,
        severity_rating: severity,
      });
      if (res.url) {
        window.open(res.url, "_blank", "noopener,noreferrer");
        alert("Report enviado ao HackerOne. Abrindo em nova aba.");
      } else {
        alert("Report enviado ao HackerOne.");
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      alert(`Falha ao enviar: ${msg}`);
    } finally {
      setSubmitTargetToH1Loading(null);
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

  return (
    <div className="space-y-4">
      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <StatBox label="Programas" value={stats.programs} />
          <StatBox label="Targets" value={stats.targets} />
          <StatBox label="Vivos" value={stats.alive_targets} />
          <StatBox label="Recons OK" value={stats.recon?.recons_completed ?? 0} />
        </div>
      )}

      {/* Actions + Filtro por etapa */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 px-4 py-3 flex flex-wrap items-center gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={() => { setShowForm(!showForm); setShowCsvImport(false); }}
            className="rounded-lg bg-emerald-600 hover:bg-emerald-500 px-4 py-2 text-sm font-semibold text-white shadow-sm transition"
          >
            {showForm ? "Cancelar" : "+ Novo Programa"}
          </button>
          <button
            onClick={() => { setShowCsvImport(!showCsvImport); setShowForm(false); }}
            className="rounded-lg bg-slate-600 hover:bg-slate-500 px-4 py-2 text-sm font-semibold text-white transition"
          >
            {showCsvImport ? "Fechar" : "Importar CSV"}
          </button>
          {programs.length > 0 && (
            <button
              type="button"
              onClick={handleDeleteAllPrograms}
              disabled={clearingAll}
              className="rounded-lg bg-red-700/80 hover:bg-red-600 px-4 py-2 text-xs font-semibold text-red-50 disabled:opacity-50 transition"
            >
              {clearingAll ? "Removendo tudo..." : "Remover todos os programas"}
            </button>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-3 ml-auto">
          <div className="flex items-center gap-2 text-sm text-slate-300">
            <button
              type="button"
              onClick={handleBugScraperSync}
              disabled={bugScraperLoading}
              className="rounded-lg border border-slate-600/70 bg-slate-900/60 px-3 py-2 text-xs font-semibold text-slate-100 hover:border-emerald-500/60 hover:bg-slate-900 disabled:opacity-50 transition"
            >
              {bugScraperLoading ? "Sincronizando Bug Scraper..." : "Descobrir programas (Bug Scraper)"}
            </button>
            {bugScraperInserted !== null && (
              <span className="text-[11px] text-slate-400">
                {bugScraperInserted > 0
                  ? `${bugScraperInserted} novo(s) programa(s) adicionados`
                  : "Nenhum programa novo encontrado"}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 text-sm text-slate-300">
          <span className="text-slate-500 hidden sm:inline">Filtrar por etapa</span>
          <select
            value={filterFlowStep}
            onChange={(e) => setFilterFlowStep(e.target.value === "" ? "" : Number(e.target.value))}
            className="rounded-lg bg-slate-950/70 border border-slate-700 px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none"
          >
            <option value="">Todas</option>
            {[1, 2, 3, 4, 5, 6, 7].map((n) => (
              <option key={n} value={n}>Etapa {n}</option>
            ))}
          </select>
          </div>
        </div>
      </div>

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

      {/* Program list */}
      {programs.length === 0 && !showForm && (
        <p className="text-center text-sm text-slate-500 py-6">
          Nenhum programa cadastrado. Clique &quot;+ Novo Programa&quot; para comecar.
        </p>
      )}

      {filterFlowStep !== "" && programs.filter((p) => (p.flow_step ?? 1) === filterFlowStep).length === 0 && programs.length > 0 && (
        <p className="text-center text-sm text-slate-500 py-4">
          Nenhum programa na etapa {filterFlowStep}. Altere o filtro ou avance os programas.
        </p>
      )}

      <div className="space-y-3">
        {(filterFlowStep === "" ? programs : programs.filter((p) => (p.flow_step ?? 1) === filterFlowStep)).map(p => {
          const isExpanded = expandedProgram === p.id;
          const isReconRunning = p.status === "reconning" || reconning.has(p.id);
          const reconButtonLabel = isReconRunning ? "Recon..." : p.status === "error" ? "Recon (retry)" : "Recon";
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
            <Fragment key={p.id}>
              <div
                className={`group rounded-xl border transition-colors ${
                  isExpanded
                    ? "border-emerald-500/60 bg-slate-900/70 shadow-[0_0_0_1px_rgba(16,185,129,0.25)]"
                    : "border-slate-700/60 bg-slate-900/40 hover:border-emerald-500/40 hover:bg-slate-900/60"
                }`}
              >
                {/* Header */}
                <div
                  className="flex flex-col gap-2 px-4 py-3 cursor-pointer sm:flex-row sm:items-center sm:justify-between"
                  onClick={() => setExpandedProgram(isExpanded ? null : p.id)}
                >
                  <div className="flex flex-col gap-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                        {p.platform || "N/A"}
                      </span>
                      <span className="font-semibold text-white truncate">{p.name}</span>
                    </div>
                    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                      <span className={`inline-flex items-center gap-1 text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded-full border ${
                        p.status === "reconning"
                          ? "bg-blue-500/15 text-blue-300 border-blue-500/40"
                          : p.status === "error"
                            ? "bg-red-500/15 text-red-300 border-red-500/40"
                            : "bg-emerald-500/15 text-emerald-300 border-emerald-500/40"
                      }`}>
                        <span
                          className={`h-1.5 w-1.5 rounded-full ${
                            p.status === "reconning"
                              ? "bg-blue-400"
                              : p.status === "error"
                                ? "bg-red-400"
                                : "bg-emerald-400"
                          }`}
                        />
                        {p.status || "active"}
                      </span>
                      <span className="text-slate-500">
                        {p.in_scope?.length ?? 0} escopo(s)
                      </span>
                      <span
                        className="inline-flex items-center gap-1 text-[10px] text-slate-300 border border-slate-600/80 rounded-full px-2 py-0.5"
                        title="Etapa do fluxo HackerOne"
                      >
                        <span className="h-1 w-1 rounded-full bg-emerald-400/80" />
                        Etapa {(p.flow_step ?? 1)}
                      </span>
                    </div>
                    {p.status === "error" && p.last_recon_error && (
                      <p className="text-[11px] text-amber-300/90">
                        Recon: {p.last_recon_error}
                      </p>
                    )}
                  </div>

                  <div className="flex items-center gap-3 text-xs shrink-0">
                    <span className="text-slate-400">{p.target_count ?? 0} targets</span>
                    <span className="text-green-400">{p.alive_count ?? 0} vivos</span>
                    <span className="text-red-400">{p.vuln_count ?? 0} vulns</span>

                    {(p.status === "error" || p.status === "reconning") && (
                      <button
                        onClick={e => { e.stopPropagation(); handleClearError(p.id); }}
                        className={`rounded px-2.5 py-1 text-[11px] font-semibold text-white transition ${
                          p.status === "reconning" ? "bg-slate-600 hover:bg-slate-500" : "bg-amber-600 hover:bg-amber-500"
                        }`}
                      >
                        {p.status === "reconning" ? "Cancelar recon" : "Limpar erro"}
                      </button>
                    )}
                    <button
                      onClick={e => { e.stopPropagation(); handleRecon(p.id); }}
                      disabled={isReconRunning}
                      className="rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-40 px-2.5 py-1 text-[11px] font-semibold text-white transition"
                    >
                      {reconButtonLabel}
                    </button>
                    <button
                      onClick={e => { e.stopPropagation(); handleReport(p.id); }}
                      disabled={reportLoading === p.id}
                      className="rounded bg-slate-600 hover:bg-slate-500 disabled:opacity-40 px-2.5 py-1 text-[11px] font-semibold text-white transition"
                    >
                      {reportLoading === p.id ? "..." : "Report"}
                    </button>
                    {(p.platform === "hackerone" && (p.url || "").includes("hackerone.com")) && (
                      <button
                        onClick={e => { e.stopPropagation(); handleSubmitHackerOne(p.id); }}
                        disabled={submitHackerOneLoading === p.id}
                        className="rounded bg-orange-600 hover:bg-orange-500 disabled:opacity-40 px-2.5 py-1 text-[11px] font-semibold text-white transition"
                      >
                        {submitHackerOneLoading === p.id ? "..." : "Enviar ao HackerOne"}
                      </button>
                    )}
                    <button
                      onClick={e => { e.stopPropagation(); handleDelete(p.id); }}
                      className="rounded bg-red-700/60 hover:bg-red-600 px-2 py-1 text-[11px] font-semibold text-red-200 transition"
                    >
                      X
                    </button>

                    <svg
                      className={`w-4 h-4 text-slate-400 transition-transform ${isExpanded ? "rotate-180" : ""}`}
                      fill="none" viewBox="0 0 24 24" stroke="currentColor"
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                  </div>
                </div>

                {/* Expanded: Fluxo HackerOne + targets table */}
                {isExpanded && (
                  <div className="border-t border-slate-700/40 px-4 py-3">
                    {/* Fluxo HackerOne (algoritmo 1–7) */}
                    {flowByProgram[p.id] && (
                      <div className="mb-4 rounded-lg border border-slate-700/70 bg-slate-950/60 p-3">
                        <div className="mb-2 flex items-center justify-between gap-2">
                          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                            Fluxo HackerOne
                          </p>
                          <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-300">
                            Passo {flowByProgram[p.id].current_step} de 7
                          </span>
                        </div>
                        <ol className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-1.5 text-[11px]">
                          {flowByProgram[p.id].steps.map((s) => (
                            <li
                              key={s.n}
                              className={`flex items-center gap-2 rounded-lg border px-2 py-1 ${
                                s.done
                                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200"
                                  : "border-slate-700/70 bg-slate-900/70 text-slate-300"
                              }`}
                            >
                              <span
                                className={`flex h-4 w-4 items-center justify-center rounded-full text-[10px] font-semibold ${
                                  s.done
                                    ? "bg-emerald-500 text-slate-950"
                                    : "bg-slate-800 text-slate-300"
                                }`}
                              >
                                {s.done ? "✓" : s.n}
                              </span>
                              <span className="leading-snug">{s.label}</span>
                            </li>
                          ))}
                        </ol>
                      </div>
                    )}
                    {/* Scope info */}
                    <div className="mb-3 flex flex-wrap gap-4 text-xs text-slate-400">
                      <div>
                        <span className="font-semibold text-slate-300">In-scope:</span>{" "}
                        {(p.in_scope ?? []).map((s: string, i: number) => (
                          <code key={i} className="ml-1 rounded bg-slate-700/40 px-1 py-0.5 text-emerald-300">{s}</code>
                        ))}
                      </div>
                      {(p.out_of_scope ?? []).length > 0 && (
                        <div>
                          <span className="font-semibold text-slate-300">Out-of-scope:</span>{" "}
                          {p.out_of_scope.map((s: string, i: number) => (
                            <code key={i} className="ml-1 rounded bg-slate-700/40 px-1 py-0.5 text-red-300">{s}</code>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="mb-3 flex items-center justify-between gap-2">
                      <label className="inline-flex items-center gap-2 text-xs text-slate-300">
                        <input
                          type="checkbox"
                          checked={highOnly}
                          onChange={(e) =>
                            setHighOnlyByProgram(prev => ({ ...prev, [p.id]: e.target.checked }))
                          }
                          className="rounded border-slate-600 bg-slate-900"
                        />
                        Mostrar somente alvos com achados HIGH
                      </label>
                      <button
                        type="button"
                        onClick={() => handleExportTopTargets(p, prioritizedTargets)}
                        className="rounded bg-slate-700 hover:bg-slate-600 px-2.5 py-1 text-[11px] font-semibold text-white transition"
                      >
                        Exportar top-targets.md
                      </button>
                    </div>

                    {loadingTargets ? (
                      <p className="text-xs text-slate-500 py-2">Carregando targets...</p>
                    ) : visibleTargets.length === 0 ? (
                      <p className="text-xs text-slate-500 py-2">Nenhum target encontrado. Execute &quot;Recon&quot; primeiro.</p>
                    ) : (
                      <div className="space-y-3">
                        <div className="overflow-x-auto max-h-80 overflow-y-auto">
                          <table className="w-full text-xs">
                            <thead className="sticky top-0 bg-slate-800">
                              <tr className="text-left text-slate-400 border-b border-slate-700/50">
                                <th className="py-1.5 px-2">Dominio</th>
                                <th className="py-1.5 px-2">IPs</th>
                                <th className="py-1.5 px-2">Status</th>
                                <th className="py-1.5 px-2">HTTP</th>
                                <th className="py-1.5 px-2">Tech</th>
                                <th className="py-1.5 px-2">Checks</th>
                                <th className="py-1.5 px-2 text-right">Acao</th>
                              </tr>
                            </thead>
                            <tbody>
                              {visibleTargets.map(t => (
                                <tr key={t.id} className="border-b border-slate-700/30 hover:bg-slate-700/20">
                                  <td className="py-1.5 px-2 font-mono text-emerald-300">{t.domain}</td>
                                  <td className="py-1.5 px-2 text-slate-300">{(t.ips ?? []).join(", ") || "-"}</td>
                                  <td className={`py-1.5 px-2 font-semibold ${STATUS_COLORS[t.status] ?? "text-slate-400"}`}>
                                    {t.status}
                                  </td>
                                  <td className="py-1.5 px-2 text-slate-300">
                                    {t.httpx?.status_code ? `${t.httpx.status_code}` : "-"}
                                    {t.httpx?.title ? ` - ${t.httpx.title.slice(0, 30)}` : ""}
                                  </td>
                                  <td className="py-1.5 px-2 text-slate-400">
                                    {(t.httpx?.tech ?? []).slice(0, 3).join(", ") || "-"}
                                  </td>
                                  <td className="py-1.5 px-2 text-slate-300">
                                    {t.recon_checks?.checked ? (
                                      <span
                                        className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold ${
                                          (t.recon_checks?.high ?? 0) > 0
                                            ? "bg-red-500/20 text-red-300"
                                            : (t.recon_checks?.medium ?? 0) > 0
                                              ? "bg-amber-500/20 text-amber-300"
                                              : (t.recon_checks?.total_findings ?? 0) > 0
                                                ? "bg-slate-600/40 text-slate-200"
                                                : "bg-emerald-500/20 text-emerald-300"
                                        }`}
                                        title={(t.recon_checks?.findings ?? []).map(f => `${f.severity}: ${f.title}`).join(" | ")}
                                      >
                                        {t.recon_checks?.total_findings ?? 0} achado(s)
                                        {(t.recon_checks?.high ?? 0) > 0 ? ` | H:${t.recon_checks?.high}` : ""}
                                      </span>
                                    ) : (
                                      "-"
                                    )}
                                  </td>
                                  <td className="py-1.5 px-2 text-right">
                                    <div className="inline-flex flex-wrap items-center gap-1">
                                      <button
                                        onClick={() => handleCopyTemplate(p, t)}
                                        className="rounded bg-slate-600 hover:bg-slate-500 px-2 py-0.5 text-[10px] font-semibold text-white transition"
                                      >
                                        {copiedTemplateId === t.id ? "Copiado" : "Template"}
                                      </button>
                                      {p.platform === "hackerone" && (p.url || "").includes("hackerone.com") && (
                                        <button
                                          onClick={() => handleSubmitTargetToHackerOne(p, t)}
                                          disabled={submitTargetToH1Loading === t.id || !targetFulfillsHackerOneRules(t)}
                                          title={!targetFulfillsHackerOneRules(t) ? "Requer ao menos 1 finding do recon com título e evidência (regras HackerOne)" : "Enviar report ao HackerOne"}
                                          className="rounded bg-orange-600 hover:bg-orange-500 disabled:opacity-40 disabled:cursor-not-allowed px-2 py-0.5 text-[10px] font-semibold text-white transition"
                                        >
                                          {submitTargetToH1Loading === t.id ? "..." : "Enviar ao H1"}
                                        </button>
                                      )}
                                      <button
                                        onClick={() => handleOpenTarget(t)}
                                        className="rounded bg-sky-700 hover:bg-sky-600 px-2 py-0.5 text-[10px] font-semibold text-white transition"
                                      >
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
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                        <div className="rounded border border-slate-700/40 bg-slate-900/30 p-3">
                          <p className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider">
                            Plano de Caca (Top 5 por risco)
                          </p>
                          {prioritizedTargets.length === 0 ? (
                            <p className="mt-2 text-xs text-slate-500">Sem targets vivos para priorizacao ainda.</p>
                          ) : (
                            <div className="mt-2 space-y-1.5">
                              {prioritizedTargets.map((t, idx) => (
                                <div key={t.id} className="flex items-center justify-between gap-2 text-xs">
                                  <div>
                                    <span className="text-slate-400 mr-2">#{idx + 1}</span>
                                    <span className="font-mono text-emerald-300">{t.domain}</span>
                                    <span className="text-slate-500 ml-2">
                                      score {t.recon_checks?.risk_score ?? 0} | achados {t.recon_checks?.total_findings ?? 0}
                                    </span>
                                  </div>
                                  <div className="inline-flex gap-1">
                                    <button
                                      onClick={() => handleCopyTemplate(p, t)}
                                      className="rounded bg-sky-700 hover:bg-sky-600 px-2 py-0.5 text-[10px] font-semibold text-white transition"
                                    >
                                      Copiar report
                                    </button>
                                    {p.platform === "hackerone" && (p.url || "").includes("hackerone.com") && (
                                      <button
                                        onClick={() => handleSubmitTargetToHackerOne(p, t)}
                                        disabled={submitTargetToH1Loading === t.id || !targetFulfillsHackerOneRules(t)}
                                        title={!targetFulfillsHackerOneRules(t) ? "Requer ao menos 1 finding com título e evidência" : "Enviar ao HackerOne"}
                                        className="rounded bg-orange-600 hover:bg-orange-500 disabled:opacity-40 disabled:cursor-not-allowed px-2 py-0.5 text-[10px] font-semibold text-white transition"
                                      >
                                        {submitTargetToH1Loading === t.id ? "..." : "Enviar ao H1"}
                                      </button>
                                    )}
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}
                          <div className="mt-3 text-[11px] text-slate-400">
                            Checklist rapido: validar impacto real, reproduzir sem dano, coletar prova e enviar report claro.
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </Fragment>
          );
        })}
      </div>

      {/* Preview do template copiado */}
      {templatePreview && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
          onClick={() => setTemplatePreview(null)}
        >
          <div
            className="relative max-h-[85vh] w-full max-w-2xl rounded-lg border border-slate-600 bg-slate-900 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-slate-700 px-4 py-2">
              <span className="text-sm font-semibold text-slate-200">Report copiado — preview</span>
              <button
                type="button"
                onClick={() => setTemplatePreview(null)}
                className="rounded bg-slate-600 px-3 py-1 text-xs font-medium text-white hover:bg-slate-500"
              >
                Fechar
              </button>
            </div>
            <pre className="max-h-[70vh] overflow-auto whitespace-pre-wrap p-4 text-left text-xs text-slate-300">
              {templatePreview}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
