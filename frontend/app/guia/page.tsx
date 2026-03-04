"use client";

import { useState } from "react";

// ─── tipos locais ────────────────────────────────────────────────────────────

interface DataItem {
  label: string;
  what: string;
  why: string;
  source: string;
}

interface FlowStep {
  n: number;
  title: string;
  desc: string;
  output: string;
}

interface Module {
  id: string;
  name: string;
  color: string;       // tailwind text color
  bg: string;          // tailwind bg/border color
  dot: string;         // tailwind bg for dot
  icon: React.ReactNode;
  summary: string;
  steps: FlowStep[];
  collects: string[];
  feeds: string[];
}

// ─── dados coletados ─────────────────────────────────────────────────────────

const DATA_ITEMS: DataItem[] = [
  {
    label: "IPs e Portas",
    what: "Endereços IP públicos e as portas TCP abertas em cada um",
    why: "Identificar serviços expostos (HTTP, SSH, banco de dados, etc.) que podem ter vulnerabilidades conhecidas",
    source: "Scanner de Rede (Masscan/async TCP)",
  },
  {
    label: "Subdomínios",
    what: "Todos os subdomínios pertencentes ao escopo do programa (ex: api.acme.com, admin.acme.com)",
    why: "Expandir a superfície de ataque — cada subdomínio pode ter vulnerabilidades independentes ou expor serviços internos",
    source: "Recon Pipeline: subfinder, crt.sh, AlienVault, HackerTarget, RapidDNS, Anubis, Wayback",
  },
  {
    label: "Registros DNS",
    what: "Registros A, CNAME, MX, TXT e NS. Também verifica Zone Transfer",
    why: "Revelar infraestrutura interna, IPs reais atrás de CDN, e configurações incorretas como zone transfer aberto",
    source: "Recon Pipeline: resolução DNS + dnsx",
  },
  {
    label: "Blocos ASN / CIDR",
    what: "Blocos de IPs registrados na organização via ASN (Sistema Autônomo)",
    why: "Descobrir IPs da organização fora do escopo declarado que podem ser testados como ativos relacionados",
    source: "Recon Pipeline: ipinfo, RIPE, BGP lookup",
  },
  {
    label: "Hosts Vivos (HTTP/HTTPS)",
    what: "Quais subdomínios respondem a requisições HTTP — título da página, código de status, servidor, tecnologias",
    why: "Filtrar o que realmente está ativo e acessível. Identifica tecnologias (CMS, frameworks) para direcionar ataques",
    source: "httpx probe",
  },
  {
    label: "Security Headers",
    what: "Presença/ausência de HSTS, CSP, X-Frame-Options, X-Content-Type, Referrer-Policy",
    why: "Headers ausentes indicam configurações inseguras e podem ser reportados como vulnerabilidades de média severidade",
    source: "Recon: security_checks",
  },
  {
    label: "CORS",
    what: "Política de Cross-Origin Resource Sharing: wildcards, origin refletido, credentials permitidos",
    why: "CORS mal configurado permite que sites maliciosos façam requisições autenticadas em nome do usuário (roubo de dados)",
    source: "Recon: security_checks",
  },
  {
    label: "Arquivos Sensíveis Expostos",
    what: ".git, .env, .DS_Store, /server-status, /phpinfo.php, /actuator/*, /swagger-ui",
    why: "Expõem código-fonte, credenciais, chaves de API e detalhes de infraestrutura que viabilizam ataques maiores",
    source: "Recon: security_checks",
  },
  {
    label: "URLs Históricas (Wayback)",
    what: "URLs arquivadas pelo Wayback Machine e GetAllUrls (GAU) — incluindo endpoints antigos e parâmetros",
    why: "Endpoints removidos podem ainda estar ativos no servidor. Parâmetros históricos indicam superfície de ataque",
    source: "Recon: Wayback Machine + GAU",
  },
  {
    label: "Parâmetros de URL",
    what: "Query strings e formulários com parâmetros (ex: ?id=, ?redirect=, ?file=)",
    why: "Parâmetros são o principal vetor de SQLi, XSS, IDOR, SSRF e Open Redirect. Quanto mais parâmetros, maior o risco",
    source: "Recon: ParamSpider + Katana",
  },
  {
    label: "Secrets em JavaScript",
    what: "Chaves de API, tokens, credenciais hardcoded encontrados em arquivos .js públicos",
    why: "Secrets expostos permitem acesso direto a sistemas internos, AWS, Stripe, Twilio, etc.",
    source: "Recon: extração de JS + regex patterns",
  },
  {
    label: "GitHub Dorks",
    what: "Repositórios públicos com código da organização contendo secrets, configs, ou informações de infraestrutura",
    why: "Desenvolvedores frequentemente commitam .env, chaves SSH, credenciais de banco. Isso vira vulnerabilidade crítica",
    source: "Recon: GitHub Search API",
  },
  {
    label: "Vulnerabilidades (CVEs / Templates)",
    what: "Vulnerabilidades conhecidas detectadas via Nuclei: CVEs, misconfigs, exposições, RCE, SQLi, XSS, etc.",
    why: "Achados diretos e reportáveis. Cada finding do Nuclei é um candidato a relatório no HackerOne",
    source: "Nuclei (75 workers paralelos)",
  },
  {
    label: "Endpoints GraphQL / APIs",
    what: "Endpoints GraphQL com introspection habilitada, APIs REST sem autenticação",
    why: "GraphQL com introspection expõe o schema completo. APIs sem auth são vulnerabilidades críticas",
    source: "GraphQL Scanner",
  },
];

// ─── módulos / programas rodando ─────────────────────────────────────────────

const MODULES: Module[] = [
  {
    id: "network",
    name: "Scanner de Rede",
    color: "text-blue-400",
    bg: "border-blue-500/20 bg-blue-500/5",
    dot: "bg-blue-500",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.75} stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" d="M8.288 15.038a5.25 5.25 0 017.424 0M5.106 11.856c3.807-3.808 9.98-3.808 13.788 0M1.924 8.674c5.565-5.565 14.587-5.565 20.152 0M12.53 18.22l-.53.53-.53-.53a.75.75 0 011.06 0z" />
      </svg>
    ),
    summary: "Varre a internet escaneando IPs e portas abertas. Roda 24/7 com até 500 workers assíncronos.",
    steps: [
      { n: 1, title: "Geração de IPs", desc: "Gera ranges de IPs aleatórios ou recebe IPs de programas cadastrados", output: "Lista de IPs para testar" },
      { n: 2, title: "Scan TCP", desc: "Testa 40+ portas por IP (80, 443, 22, 3306, 6379, 27017...) com conexões async", output: "IPs alive + portas abertas" },
      { n: 3, title: "Enriquecimento Shodan", desc: "Consulta InternetDB (Shodan) para obter CVEs, hostnames e tags de cada IP", output: "CVEs associados, hostnames, tags" },
      { n: 4, title: "GeoIP + Threat Intel", desc: "Consulta IPinfo e AbuseIPDB para localização e reputação do IP", output: "País, ASN, score de abuso" },
      { n: 5, title: "Matching de Programas", desc: "Verifica se o IP pertence ao escopo de algum programa de bug bounty cadastrado", output: "IP associado a programa" },
      { n: 6, title: "Fila de Vuln Scan", desc: "IPs com CVEs ou portas interessantes são enfileirados para o Nuclei", output: "Queue para scanner de vulnerabilidades" },
    ],
    collects: ["IPs", "Portas abertas", "CVEs via Shodan", "Hostnames", "ASN", "País"],
    feeds: ["Scanner de Vulnerabilidades (Nuclei)", "Program Matcher"],
  },
  {
    id: "recon",
    name: "Recon Pipeline",
    color: "text-cyan-400",
    bg: "border-cyan-500/20 bg-cyan-500/5",
    dot: "bg-cyan-500",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.75} stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
      </svg>
    ),
    summary: "Pipeline de 17 etapas que mapeia toda a superfície de ataque de um programa. Roda por programa, manualmente ou em loop automático.",
    steps: [
      { n: 1, title: "Extração de Domínios", desc: "Extrai root domains do escopo do programa (ex: acme.com)", output: "Root domains" },
      { n: 2, title: "Enum de Subdomínios", desc: "7 fontes em paralelo: subfinder, crt.sh, AlienVault, HackerTarget, RapidDNS, Anubis, Wayback", output: "Lista de subdomínios" },
      { n: 3, title: "Filtro de Escopo", desc: "Remove subdomínios fora do in_scope / dentro do out_of_scope do programa", output: "Subdomínios válidos" },
      { n: 4, title: "DNS + Zone Transfer", desc: "Resolve A/CNAME de cada subdomínio e testa zone transfer aberto", output: "IPs, registros DNS, zone transfers" },
      { n: 5, title: "Descoberta de ASN", desc: "Identifica blocos de IP registrados na organização via lookup de ASN", output: "CIDR blocks da org" },
      { n: 6, title: "Reverse DNS", desc: "Faz lookup reverso nos blocos CIDR para encontrar subdomínios não listados", output: "Subdomínios extras via rDNS" },
      { n: 7, title: "Merge + Filtro 2", desc: "Combina todos os subdomínios encontrados e filtra pelo escopo novamente", output: "Lista final de subdomínios" },
      { n: 8, title: "httpx Probe", desc: "Testa quais hosts respondem HTTP/HTTPS, captura título, status, tecnologias", output: "Hosts vivos + metadata HTTP" },
      { n: 9, title: "Security Checks (40+)", desc: "Verifica CORS, headers, arquivos sensíveis, painéis admin, open redirect, TRACE, takeover...", output: "Findings com severidade + evidências" },
      { n: 10, title: "HTTP Port Scanner", desc: "Testa portas HTTP alternativas (8080, 8443, 8888, etc.) em hosts vivos", output: "Serviços HTTP em portas não-padrão" },
      { n: 11, title: "Wayback + ParamSpider", desc: "Coleta URLs históricas e descobre parâmetros de query string", output: "URLs + parâmetros para testar" },
      { n: 12, title: "GitHub + Katana + GAU + JS", desc: "GitHub dorking, crawling de endpoints, coleta de URLs públicas, extração de secrets em JS", output: "Secrets, endpoints, credenciais" },
      { n: 13, title: "Scans Avançados", desc: "IDOR, SSRF, GraphQL introspection, Race Conditions em paralelo", output: "Findings avançados por tipo" },
      { n: 14, title: "Change Detection", desc: "Compara com recon anterior: novos subdomínios, removidos, mudanças", output: "Delta de mudanças" },
      { n: 15, title: "Salvar no Redis", desc: "Persiste todos os targets com seus findings, metadata e scores", output: "Targets salvos no banco" },
      { n: 16, title: "Nuclei Auto-Queue", desc: "Enfileira hosts vivos para scan de vulnerabilidades com Nuclei", output: "Queue de vuln scan" },
      { n: 17, title: "AI Analysis (background)", desc: "Thread separada analisa findings, prioriza alvos, detecta chains e gera relatório executivo", output: "Análise AI salva no programa" },
    ],
    collects: ["Subdomínios", "DNS records", "ASN/CIDR", "HTTP metadata", "Security findings", "Wayback URLs", "Parâmetros", "JS secrets", "GitHub leaks"],
    feeds: ["Nuclei (vuln scan)", "AI Analyzer", "HackerOne (auto-submit)"],
  },
  {
    id: "nuclei",
    name: "Scanner de Vulnerabilidades",
    color: "text-orange-400",
    bg: "border-orange-500/20 bg-orange-500/5",
    dot: "bg-orange-500",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.75} stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
      </svg>
    ),
    summary: "Roda templates Nuclei contra alvos enfileirados pelo recon e pelo scanner de rede. 75 workers paralelos, filtra por severidade.",
    steps: [
      { n: 1, title: "Consumir Fila", desc: "Pega URLs/IPs da fila Redis (enfileirados pelo recon ou scanner de rede)", output: "Alvo para scan" },
      { n: 2, title: "Executar Nuclei", desc: "Roda nuclei com templates de critical/high/medium contra o alvo, com rate limiting", output: "Raw findings do Nuclei" },
      { n: 3, title: "Nmap NSE", desc: "Complementa com scripts NSE do Nmap para detecção de serviços e versões", output: "Serviços, versões, banners" },
      { n: 4, title: "Filtrar Severidade", desc: "Aplica filtro de severidade mínima (configurável via NUCLEI_SEVERITY)", output: "Findings filtrados" },
      { n: 5, title: "Deduplicação", desc: "Remove findings duplicados (mesmo IP + título + tipo)", output: "Findings únicos" },
      { n: 6, title: "Classificação AI", desc: "Opcionalmente usa AI para classificar true/false positives e calcular confidence score", output: "Findings com confidence + classification" },
      { n: 7, title: "Salvar vuln_results", desc: "Persiste no Redis com severidade, CVSS, CWE, CVE IDs, evidência e remediação", output: "Vulnerabilidade confirmada no banco" },
      { n: 8, title: "Matching de Programas", desc: "Verifica se a vulnerabilidade está no escopo de algum programa de bug bounty", output: "Vuln associada a programa elegível" },
    ],
    collects: ["CVEs encontrados", "Misconfigs", "Exposições", "CVSS score", "Evidências (URL + resposta)"],
    feeds: ["AI Report Writer", "HackerOne Submission"],
  },
  {
    id: "ai",
    name: "AI Analyzer",
    color: "text-purple-400",
    bg: "border-purple-500/20 bg-purple-500/5",
    dot: "bg-purple-500",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.75} stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
      </svg>
    ),
    summary: "Módulo de inteligência que roda em background após cada recon. Suporta OpenAI, Anthropic e Ollama.",
    steps: [
      { n: 1, title: "Análise de Findings", desc: "Para cada finding do recon, gera explicação de impacto real e guia de exploração específico", output: "ai_impact + ai_guidance por finding" },
      { n: 2, title: "Cadeias de Vulnerabilidade", desc: "Identifica combinações de findings que juntos formam ataques maiores (ex: CORS + OAuth = token theft)", output: "Chains com severity escalada" },
      { n: 3, title: "Priorização de Alvos", desc: "Ranqueia todos os alvos alive por potencial de ataque: severity, parâmetros, histórico, tecnologias", output: "Rank 1..N com attack_angle" },
      { n: 4, title: "Relatório Executivo", desc: "Gera resumo consolidado do programa: top estratégias de ataque, ativos críticos, próximos passos", output: "ai_report salvo no programa" },
      { n: 5, title: "Escrita de Relatório H1", desc: "Para vulns confirmadas, escreve relatório completo no formato HackerOne: título, impacto, CVSS, PoC", output: "Relatório pronto para submissão" },
    ],
    collects: ["Findings enriquecidos com AI", "Chains de vulns", "Ranking de alvos", "Relatórios H1 gerados"],
    feeds: ["Página de Análises", "HackerOne Submission"],
  },
  {
    id: "h1",
    name: "HackerOne Submission",
    color: "text-emerald-400",
    bg: "border-emerald-500/20 bg-emerald-500/5",
    dot: "bg-emerald-500",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.75} stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" d="M6 12L3.269 3.126A59.768 59.768 0 0121.485 12 59.77 59.77 0 013.27 20.876L5.999 12zm0 0h7.5" />
      </svg>
    ),
    summary: "Submete vulnerabilidades elegíveis ao HackerOne via API. Evita duplicatas, rastreia status e monitora bounties recebidos.",
    steps: [
      { n: 1, title: "Filtro de Elegibilidade", desc: "Verifica se a vuln está no escopo do programa, severidade mínima e se já foi submetida antes", output: "Relatórios elegíveis para submissão" },
      { n: 2, title: "Geração do Relatório", desc: "Usa relatório gerado pela AI (ou template padrão) com título, descrição, impacto e PoC", output: "Payload JSON para API H1" },
      { n: 3, title: "Submissão via API", desc: "POST na HackerOne API com retry automático em caso de erro de rate limit", output: "Report ID no H1" },
      { n: 4, title: "Tracking de Status", desc: "Monitora estado do relatório: triagem, aceito, duplicado, recompensa paga", output: "Status atualizado no banco" },
      { n: 5, title: "ROI Tracking", desc: "Registra bounties recebidos, calcula retorno por programa e esforço", output: "Métricas de ROI no dashboard" },
    ],
    collects: ["Report ID H1", "Status de triagem", "Bounty pago ($)", "Tempo de resposta"],
    feeds: ["Dashboard (métricas)", "ROI Tracker"],
  },
];

// ─── animações ──────────────────────────────────────────────────────────────

const animStyles = `
  @keyframes slideDown {
    from { opacity: 0; transform: translateY(-10px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  @keyframes fadeIn {
    from { opacity: 0; }
    to   { opacity: 1; }
  }
  @keyframes pipeFlow {
    0%   { opacity: 0; transform: translateX(-6px); }
    100% { opacity: 1; transform: translateX(0); }
  }
  .anim-slide-down { animation: slideDown 0.25s ease both; }
  .anim-fade-up    { animation: fadeUp 0.22s ease both; }
  .anim-fade-in    { animation: fadeIn 0.2s ease both; }
  .anim-pipe       { animation: pipeFlow 0.2s ease both; }
`;

// ─── componentes ─────────────────────────────────────────────────────────────

function Badge({ color, children }: { color: string; children: React.ReactNode }) {
  return (
    <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-[10px] font-semibold border ${color}`}>
      {children}
    </span>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="text-base font-bold text-[var(--foreground)] flex items-center gap-2">
      {children}
    </h2>
  );
}

function ModuleCard({ mod, open, onToggle }: { mod: Module; open: boolean; onToggle: () => void }) {
  return (
    <div className={`rounded-2xl border ${mod.bg} overflow-hidden`}>
      {/* Header */}
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 px-5 py-4 hover:bg-white/[0.02] transition-all text-left"
      >
        <span className={mod.color}>{mod.icon}</span>
        <div className="flex-1 min-w-0">
          <div className={`font-semibold text-sm ${mod.color}`}>{mod.name}</div>
          <div className="text-xs text-[var(--muted)] mt-0.5 truncate">{mod.summary}</div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className={`relative flex h-2 w-2`}>
            <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${mod.dot} opacity-60`} />
            <span className={`relative inline-flex rounded-full h-2 w-2 ${mod.dot}`} />
          </span>
          <svg className={`w-4 h-4 text-[var(--muted)] transition-transform ${open ? "rotate-180" : ""}`} fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
          </svg>
        </div>
      </button>

      {open && (
        <div className="border-t border-[var(--border)] px-5 pb-5 pt-4 space-y-5 anim-slide-down">
          {/* Flow steps */}
          <div>
            <div className="text-[10px] font-bold uppercase tracking-wider text-[var(--muted)] mb-3">Fluxo de execução</div>
            <ol className="space-y-3">
              {mod.steps.map((step, i) => (
                <li key={step.n} className="flex gap-3 anim-fade-up" style={{ animationDelay: `${i * 45}ms` }}>
                  <span className={`shrink-0 w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold ${mod.color} bg-[var(--background)] border border-[var(--border)]`}>
                    {step.n}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-semibold text-[var(--foreground)]">{step.title}</div>
                    <div className="text-xs text-[var(--muted)] mt-0.5 leading-relaxed">{step.desc}</div>
                    <div className="flex items-center gap-1 mt-1">
                      <svg className="w-3 h-3 text-[var(--muted)] shrink-0" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                      </svg>
                      <span className="text-[10px] text-[var(--muted)] italic">{step.output}</span>
                    </div>
                  </div>
                </li>
              ))}
            </ol>
          </div>

          {/* Collects + Feeds */}
          <div className="grid grid-cols-2 gap-4 pt-1">
            <div>
              <div className="text-[10px] font-bold uppercase tracking-wider text-[var(--muted)] mb-2">Coleta</div>
              <ul className="space-y-1">
                {mod.collects.map((c, i) => (
                  <li key={c} className="flex items-center gap-1.5 text-xs text-[var(--foreground)]/80 anim-fade-up" style={{ animationDelay: `${i * 35}ms` }}>
                    <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${mod.dot}`} />
                    {c}
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <div className="text-[10px] font-bold uppercase tracking-wider text-[var(--muted)] mb-2">Alimenta</div>
              <ul className="space-y-1">
                {mod.feeds.map((f, i) => (
                  <li key={f} className="flex items-center gap-1.5 text-xs text-[var(--foreground)]/80 anim-fade-up" style={{ animationDelay: `${i * 40}ms` }}>
                    <svg className="w-3 h-3 text-[var(--muted)] shrink-0" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                    </svg>
                    {f}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── página principal ─────────────────────────────────────────────────────────

export default function GuiaPage() {
  const [openModule, setOpenModule] = useState<string | null>("recon");
  const [tab, setTab] = useState<"fluxo" | "dados">("fluxo");

  const toggle = (id: string) => setOpenModule(prev => prev === id ? null : id);

  return (
    <div className="space-y-6 max-w-4xl">
      <style>{animStyles}</style>
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-[var(--foreground)]">Guia & Fluxo</h1>
        <p className="text-sm text-[var(--muted)] mt-1">
          O que cada módulo coleta, para que serve, e como os dados fluem até o relatório final no HackerOne.
        </p>
      </div>

      {/* Pipeline overview */}
      <div className="rounded-2xl border border-[var(--border)] bg-[var(--card)]/60 p-5">
        <div className="text-[10px] font-bold uppercase tracking-wider text-[var(--muted)] mb-4">Fluxo completo end-to-end</div>
        <div className="flex items-center gap-1 flex-wrap">
          {[
            { label: "Scanner de Rede", color: "bg-blue-500/15 text-blue-400 border-blue-500/20" },
            { label: "→", color: "text-[var(--muted)] bg-transparent border-transparent" },
            { label: "Recon Pipeline", color: "bg-cyan-500/15 text-cyan-400 border-cyan-500/20" },
            { label: "→", color: "text-[var(--muted)] bg-transparent border-transparent" },
            { label: "Nuclei", color: "bg-orange-500/15 text-orange-400 border-orange-500/20" },
            { label: "→", color: "text-[var(--muted)] bg-transparent border-transparent" },
            { label: "AI Analyzer", color: "bg-purple-500/15 text-purple-400 border-purple-500/20" },
            { label: "→", color: "text-[var(--muted)] bg-transparent border-transparent" },
            { label: "HackerOne", color: "bg-emerald-500/15 text-emerald-400 border-emerald-500/20" },
          ].map((item, i) => (
            <span key={i} className={`rounded-lg border px-2.5 py-1 text-xs font-medium anim-pipe ${item.color}`} style={{ animationDelay: `${i * 60}ms` }}>
              {item.label}
            </span>
          ))}
        </div>
        <p className="text-xs text-[var(--muted)] mt-3 leading-relaxed">
          Todos os módulos rodam em <span className="text-[var(--foreground)]">threads paralelas e independentes</span>.
          O Scanner de Rede alimenta o Nuclei com IPs. O Recon Pipeline descobre alvos por programa e também alimenta o Nuclei.
          O AI Analyzer roda em background após cada recon. O HackerOne Submission é o destino final.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 rounded-xl border border-[var(--border)] bg-[var(--card)] p-1 w-fit">
        {(["fluxo", "dados"] as const).map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`rounded-lg px-4 py-2 text-sm font-medium transition-all capitalize ${
              tab === t
                ? "bg-[var(--accent)]/15 text-[var(--accent-light)]"
                : "text-[var(--muted)] hover:text-[var(--foreground)]"
            }`}>
            {t === "fluxo" ? "Módulos & Fluxo" : "Dados Coletados"}
          </button>
        ))}
      </div>

      {/* Tab: Módulos */}
      {tab === "fluxo" && (
        <div className="space-y-3 anim-fade-in">
          {MODULES.map(mod => (
            <ModuleCard
              key={mod.id}
              mod={mod}
              open={openModule === mod.id}
              onToggle={() => toggle(mod.id)}
            />
          ))}
        </div>
      )}

      {/* Tab: Dados coletados */}
      {tab === "dados" && (
        <div className="rounded-2xl border border-[var(--border)] bg-[var(--card)]/60 overflow-hidden anim-fade-in">
          <div className="px-5 py-3 border-b border-[var(--border)] grid grid-cols-4 gap-4 text-[10px] font-bold uppercase tracking-wider text-[var(--muted)]">
            <span>Dado</span>
            <span>O que é</span>
            <span>Para que serve</span>
            <span>Fonte</span>
          </div>
          <ul className="divide-y divide-[var(--border)]">
            {DATA_ITEMS.map((item, i) => (
              <li key={item.label} className="px-5 py-3.5 grid grid-cols-4 gap-4 hover:bg-[var(--card-hover)] transition-all anim-fade-up" style={{ animationDelay: `${i * 35}ms` }}>
                <div className="font-semibold text-xs text-[var(--foreground)]">{item.label}</div>
                <div className="text-xs text-[var(--foreground)]/70 leading-relaxed">{item.what}</div>
                <div className="text-xs text-[var(--foreground)]/70 leading-relaxed">{item.why}</div>
                <div className="text-[10px] text-[var(--muted)] leading-relaxed font-mono">{item.source}</div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
