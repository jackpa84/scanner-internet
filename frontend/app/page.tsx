"use client";

import { useEffect, useState, useCallback, useRef, Component, type ReactNode } from "react";
import StatsChart from "@/components/StatsChart";
import ResultsTable from "@/components/ResultsTable";
import RouterModal from "@/components/RouterModal";
import CountryBar from "@/components/CountryBar";
import VulnPanel from "@/components/VulnPanel";
import {
  fetchStats,
  fetchResults,
  fetchRouterInfo,
  fetchPrioritizedFindings,
  fetchHealth,
  type Stats,
  type ScanResult,
  type RouterInfo,
  type HealthInfo,
} from "@/lib/api";

const REFRESH_MS = 5_000;

class ErrorBoundary extends Component<{ children: ReactNode }, { error: string | null }> {
  state = { error: null as string | null };
  static getDerivedStateFromError(err: Error) {
    return { error: err.message };
  }
  render() {
    if (this.state.error) {
      return (
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-300">
          Erro no componente: {this.state.error}
        </div>
      );
    }
    return this.props.children;
  }
}

function LiveDot() {
  return (
    <span className="relative ml-2 flex h-2.5 w-2.5">
      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
      <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-500" />
    </span>
  );
}

function StatCard({
  label,
  desc,
  value,
  color,
}: {
  label: string;
  desc: string;
  value: number;
  color: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-card px-4 py-3 group relative">
      <div className={`text-2xl font-bold tabular-nums ${color}`}>
        {(value ?? 0).toLocaleString("pt-BR")}
      </div>
      <div className="text-xs font-medium text-foreground/80 mt-0.5">{label}</div>
      <div className="text-[10px] text-muted mt-0.5 leading-tight">{desc}</div>
    </div>
  );
}

function RiskBadge({ level, score }: { level?: string; score?: number }) {
  const l = level ?? "low";
  const cls =
    l === "high"
      ? "bg-red-500/15 text-red-300 border-red-500/40"
      : l === "medium"
        ? "bg-amber-500/15 text-amber-300 border-amber-500/40"
        : "bg-emerald-500/15 text-emerald-300 border-emerald-500/40";
  return (
    <span className={`inline-flex shrink-0 items-center rounded-md border px-2 py-0.5 text-xs font-semibold ${cls}`}>
      {l.toUpperCase()} ({score ?? 0})
    </span>
  );
}

function SectionHeader({ title, desc }: { title: string; desc: string }) {
  return (
    <div className="mb-4">
      <h2 className="text-sm font-semibold text-[var(--foreground)] uppercase tracking-wider">{title}</h2>
      <p className="text-[11px] text-[var(--muted)] mt-0.5">{desc}</p>
    </div>
  );
}

export default function Home() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [prioritized, setPrioritized] = useState<ScanResult[]>([]);
  const [modalOpen, setModalOpen] = useState(false);
  const [routerInfo, setRouterInfo] = useState<RouterInfo[]>([]);
  const [routerLoading, setRouterLoading] = useState(false);
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const prevTotal = useRef(0);
  const [newCount, setNewCount] = useState(0);

  const load = useCallback(async () => {
    try {
      const [s, r, p, h] = await Promise.all([
        fetchStats(),
        fetchResults(),
        fetchPrioritizedFindings(15, 30),
        fetchHealth(),
      ]);
      setHealth(h);
      if (s && s.total > prevTotal.current && prevTotal.current > 0) {
        setNewCount(s.total - prevTotal.current);
        setTimeout(() => setNewCount(0), 3000);
      }
      prevTotal.current = s?.total ?? 0;
      setStats(s);
      setResults(Array.isArray(r) ? r : []);
      setPrioritized(Array.isArray(p) ? p : []);
      setLastUpdate(new Date());
    } catch (e) {
      console.error("Dashboard load error:", e);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  const showRouter = useCallback(async (scanId: string) => {
    setModalOpen(true);
    setRouterLoading(true);
    setRouterInfo([]);
    try {
      setRouterInfo(await fetchRouterInfo(scanId));
    } finally {
      setRouterLoading(false);
    }
  }, []);

  const threats = results.filter((r) => r.threat_intel?.known_threat === true);
  const proxies = results.filter((r) => r.network?.proxy === true || r.geo?.proxy === true);
  const topCountries = stats?.top_countries ?? [];
  const ss = health?.scan_stats;
  const ff = health?.feeds;
  const hitRate = ss && ss.tested > 0 ? ((ss.alive / ss.tested) * 100).toFixed(1) : "0";

  return (
    <>
      <header className="mb-8">
        <div className="flex items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-[var(--foreground)] md:text-3xl flex items-center gap-2">
              Monitoramento
              <LiveDot />
            </h1>
            <p className="mt-1 text-sm text-[var(--muted)] max-w-2xl">
              Varredura contínua: CIDRs hosting, BGP/RIPE, DShield, Blocklist.de, masscan → Shodan InternetDB → IPinfo → ThreatFox → MongoDB.
            </p>
          </div>
          <div className="text-right text-xs text-[var(--muted)] shrink-0">
            {lastUpdate && <p>Atualizado: {lastUpdate.toLocaleTimeString("pt-BR")}</p>}
            {newCount > 0 && (
              <p className="text-emerald-400 font-semibold animate-pulse">+{newCount} novos</p>
            )}
            <p className="mt-0.5">Auto-refresh: {REFRESH_MS / 1000}s</p>
          </div>
        </div>
      </header>

      {/* API Status + Pipeline */}
      {health && (
        <section className="mb-6">
          <SectionHeader
            title="Status das APIs e Pipeline"
            desc="Monitoramento em tempo real de cada API externa. Quando uma API retorna 429 (rate limit), o circuit breaker pausa todos os workers automaticamente até o cooldown expirar."
          />
          <div className="flex flex-wrap gap-2">
            {health.apis.map((api) => {
              const descriptions: Record<string, string> = {
                "Shodan InternetDB": "Portas abertas, CVEs e hostnames",
                "IPinfo.io": "Geolocalização, ASN e organização",
                "ip-api.com": "ISP, detecção de proxy/VPN/hosting",
                "ThreatFox": "Indicadores de comprometimento (IOC)",
              };
              return (
                <div
                  key={api.name}
                  className={`rounded-lg border px-3 py-2 text-xs ${
                    api.blocked
                      ? "border-red-500/40 bg-red-500/10"
                      : "border-emerald-500/30 bg-emerald-500/5"
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className={`h-2 w-2 rounded-full shrink-0 ${api.blocked ? "bg-red-500 animate-pulse" : "bg-emerald-500"}`} />
                    <span className="font-semibold">{api.name}</span>
                    {api.blocked ? (
                      <span className="text-red-400 font-bold">
                        bloqueada &middot; {api.remaining_seconds}s
                      </span>
                    ) : (
                      <span className="text-emerald-400 font-semibold">OK</span>
                    )}
                  </div>
                  <div className="text-[10px] text-muted mt-0.5 pl-4">
                    {descriptions[api.name] ?? ""}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Pipeline stats */}
          {ss && (
            <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-5">
              <div className="rounded-lg border border-border bg-card px-3 py-2">
                <div className="text-lg font-bold tabular-nums">{health.workers}</div>
                <div className="text-[10px] text-muted">Workers paralelos</div>
              </div>
              <div className="rounded-lg border border-border bg-card px-3 py-2">
                <div className="text-lg font-bold tabular-nums">{ss.tested?.toLocaleString("pt-BR") ?? 0}</div>
                <div className="text-[10px] text-muted">IPs testados (pre-scan paralelo)</div>
              </div>
              <div className="rounded-lg border border-border bg-card px-3 py-2">
                <div className="text-lg font-bold tabular-nums text-emerald-400">{ss.alive?.toLocaleString("pt-BR") ?? 0}</div>
                <div className="text-[10px] text-muted">IPs vivos ({hitRate}% hit rate)</div>
              </div>
              <div className="rounded-lg border border-border bg-card px-3 py-2">
                <div className="text-lg font-bold tabular-nums text-accent">{ss.saved?.toLocaleString("pt-BR") ?? 0}</div>
                <div className="text-[10px] text-muted">Salvos no MongoDB</div>
              </div>
              <div className="rounded-lg border border-border bg-card px-3 py-2">
                <div className="text-lg font-bold tabular-nums text-red-400">{ss.dead?.toLocaleString("pt-BR") ?? 0}</div>
                <div className="text-[10px] text-muted">IPs mortos (descartados)</div>
              </div>
            </div>
          )}

          {/* Feed stats */}
          {ff && (
            <div className="mt-3">
              <div className="text-[10px] font-bold text-foreground/60 uppercase mb-1.5">Fontes de IPs</div>
              <div className="flex flex-wrap gap-2">
                <div className="rounded border border-cyan-500/30 bg-cyan-500/5 px-2.5 py-1.5 text-xs">
                  <span className="text-cyan-400 font-semibold">{ff.hosting_cidrs}</span>
                  <span className="text-muted ml-1">CIDRs hosting</span>
                </div>
                <div className="rounded border border-indigo-500/30 bg-indigo-500/5 px-2.5 py-1.5 text-xs">
                  <span className="text-indigo-400 font-semibold">{ff.discovered_prefixes?.toLocaleString("pt-BR") ?? 0}</span>
                  <span className="text-muted ml-1">Prefixos BGP (RIPE)</span>
                </div>
                <div className="rounded border border-amber-500/30 bg-amber-500/5 px-2.5 py-1.5 text-xs">
                  <span className="text-amber-400 font-semibold">{ff.dshield_ips?.toLocaleString("pt-BR") ?? 0}</span>
                  <span className="text-muted ml-1">DShield/SANS</span>
                </div>
                <div className="rounded border border-rose-500/30 bg-rose-500/5 px-2.5 py-1.5 text-xs">
                  <span className="text-rose-400 font-semibold">{ff.blocklist_ips?.toLocaleString("pt-BR") ?? 0}</span>
                  <span className="text-muted ml-1">Blocklist.de</span>
                </div>
                {(ff.abuseipdb_ips ?? 0) > 0 && (
                  <div className="rounded border border-orange-500/30 bg-orange-500/5 px-2.5 py-1.5 text-xs">
                    <span className="text-orange-400 font-semibold">{ff.abuseipdb_ips.toLocaleString("pt-BR")}</span>
                    <span className="text-muted ml-1">AbuseIPDB</span>
                  </div>
                )}
                {ff.masscan_running && (
                  <div className="rounded border border-emerald-500/30 bg-emerald-500/5 px-2.5 py-1.5 text-xs">
                    <span className="text-emerald-400 font-semibold">{ff.masscan_ips?.toLocaleString("pt-BR") ?? 0}</span>
                    <span className="text-muted ml-1">masscan</span>
                    <span className="ml-1 inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  </div>
                )}
                <div className="rounded border border-border bg-card px-2.5 py-1.5 text-xs">
                  <span className="font-semibold">{ff.queue_size?.toLocaleString("pt-BR") ?? 0}</span>
                  <span className="text-muted ml-1">na fila</span>
                </div>
              </div>
            </div>
          )}
        </section>
      )}

      {/* Stats Cards */}
      <section className="mb-6">
        <SectionHeader
          title="Dados coletados"
          desc="Totais acumulados no banco de dados MongoDB. Cada IP salvo passa por Shodan (portas/CVEs), probes de serviço (HTTP/SSH/Telnet) e enriquecimento de geo/threat."
        />
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          <StatCard
            label="Total IPs"
            desc="IPs únicos salvos no MongoDB"
            value={stats?.total ?? 0}
            color="text-accent"
          />
          <StatCard
            label="Com portas"
            desc="IPs com pelo menos 1 porta aberta no Shodan"
            value={stats?.with_ports ?? 0}
            color="text-sky-300"
          />
          <StatCard
            label="Com vulns"
            desc="IPs com CVEs conhecidas reportadas"
            value={stats?.with_vulns ?? 0}
            color="text-amber-300"
          />
          <StatCard
            label="Risco alto"
            desc="Score >= 70 (vulns + portas críticas)"
            value={stats?.with_high_risk ?? 0}
            color="text-red-400"
          />
          <StatCard
            label="Com geo"
            desc="IPs com geolocalização via IPinfo/ip-api"
            value={stats?.with_geo ?? 0}
            color="text-violet-300"
          />
          <StatCard
            label="Router info"
            desc="IPs com serviços detectados (HTTP/SSH/Telnet)"
            value={stats?.with_router_info ?? 0}
            color="text-emerald-300"
          />
        </div>
      </section>

      {/* Charts row */}
      <section className="mb-6 grid gap-4 lg:grid-cols-2">
        <div className="rounded-lg border border-border bg-card p-4">
          <SectionHeader
            title="Distribuição"
            desc="Proporção entre as categorias de dados coletados. Doughnut chart atualizado em tempo real."
          />
          <ErrorBoundary>
            {stats ? <StatsChart stats={stats} /> : <p className="text-muted text-sm">Carregando...</p>}
          </ErrorBoundary>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <SectionHeader
            title="Top Países"
            desc="Origem geográfica dos IPs encontrados. Dados de IPinfo.io e ip-api.com combinados por código de país."
          />
          <ErrorBoundary>
            {topCountries.length > 0 ? (
              <CountryBar countries={topCountries} />
            ) : (
              <p className="text-muted text-sm">Sem dados de geolocalização ainda. Aguarde os próximos scans.</p>
            )}
          </ErrorBoundary>
        </div>
      </section>

      {/* Alerts row */}
      {(threats.length > 0 || proxies.length > 0) && (
        <section className="mb-6 grid gap-3 sm:grid-cols-2">
          {threats.length > 0 && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-4">
              <SectionHeader
                title={`Ameaças conhecidas (${threats.length})`}
                desc="IPs identificados como C2 de malware, botnet ou IOC pelo ThreatFox (abuse.ch). Alta prioridade para investigação."
              />
              {threats.map((t) => (
                <div key={t.id} className="flex items-center justify-between py-1.5 text-sm border-b border-red-500/10 last:border-0">
                  <div>
                    <span className="font-mono text-red-300">{t.ip}</span>
                    {t.geo?.country && <span className="ml-2 text-xs text-muted">{t.geo.country}</span>}
                  </div>
                  <div className="text-right">
                    <div className="text-xs font-semibold text-red-400">
                      {t.threat_intel?.threats?.[0]?.malware_printable ?? "malware"}
                    </div>
                    <div className="text-[10px] text-muted">
                      {t.threat_intel?.threats?.[0]?.threat_type ?? ""} &middot; confiança: {t.threat_intel?.threats?.[0]?.confidence ?? "?"}%
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
          {proxies.length > 0 && (
            <div className="rounded-lg border border-violet-500/30 bg-violet-500/5 p-4">
              <SectionHeader
                title={`Proxies / VPNs (${proxies.length})`}
                desc="IPs identificados como proxy, VPN ou serviço de anonimização pelo ip-api.com. Podem mascarar a origem real do tráfego."
              />
              {proxies.slice(0, 8).map((p) => (
                <div key={p.id} className="flex items-center justify-between py-1.5 text-sm border-b border-violet-500/10 last:border-0">
                  <div>
                    <span className="font-mono text-violet-300">{p.ip}</span>
                    {p.rdns && <span className="ml-2 text-[10px] text-muted">{p.rdns}</span>}
                  </div>
                  <div className="text-xs text-muted text-right">
                    <div>{p.geo?.country ?? "?"} &middot; {p.geo?.city ?? ""}</div>
                    <div className="text-[10px]">{p.geo?.isp ?? p.network?.isp ?? ""}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {/* Prioritized findings */}
      <section className="mb-6">
        <SectionHeader
          title="Top riscos priorizados"
          desc="IPs com maior score de risco, calculado por heurística: CVEs reportadas (+até 60pts), portas sensíveis (+até 20pts), Telnet exposto (+20pts), IOC ThreatFox (+30pts), proxy/hosting (+5-8pts)."
        />
        <div className="rounded-lg border border-border bg-card p-4">
          {prioritized.length === 0 ? (
            <p className="text-muted text-sm">Sem achados prioritários ainda.</p>
          ) : (
            <div className="grid gap-2">
              {prioritized.map((item) => (
                <div
                  key={item.id}
                  className="flex items-center justify-between rounded-md border border-border px-3 py-2 hover:bg-background/30 transition-colors"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-accent">{item.ip}</span>
                      {item.geo?.country && (
                        <span className="text-xs text-muted">{item.geo.country} {item.geo.city ?? ""}</span>
                      )}
                      {item.threat_intel?.known_threat === true && (
                        <span className="rounded bg-red-500/20 px-1.5 py-0.5 text-[10px] font-bold text-red-400 uppercase">
                          threat
                        </span>
                      )}
                      {(item.network?.proxy === true || item.geo?.proxy === true) && (
                        <span className="rounded bg-violet-500/20 px-1.5 py-0.5 text-[10px] font-bold text-violet-400 uppercase">
                          proxy
                        </span>
                      )}
                      {(item.network?.hosting === true || item.geo?.hosting === true) && (
                        <span className="rounded bg-blue-500/20 px-1.5 py-0.5 text-[10px] font-bold text-blue-400 uppercase">
                          hosting
                        </span>
                      )}
                      {item.rdns && (
                        <span className="text-[10px] text-muted truncate max-w-[200px]" title={item.rdns}>
                          {item.rdns}
                        </span>
                      )}
                    </div>
                    <div className="text-[11px] text-muted mt-0.5">
                      {item.risk?.reasons?.slice(0, 4).join(" · ") ?? "—"}
                    </div>
                    {item.geo?.isp && (
                      <div className="text-[10px] text-muted/70 mt-0.5">
                        ISP: {item.geo.isp} {item.geo.as ? `(${item.geo.as})` : ""}
                      </div>
                    )}
                  </div>
                  <div className="text-right shrink-0 ml-2">
                    <RiskBadge level={item.risk?.level} score={item.risk?.score} />
                    <div className="text-[10px] text-muted mt-1">
                      {(item.ports?.length ?? 0)} porta{(item.ports?.length ?? 0) !== 1 ? "s" : ""} &middot; {(item.vulns?.length ?? 0)} CVE{(item.vulns?.length ?? 0) !== 1 ? "s" : ""}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>

      {/* Vulnerability Scanner */}
      <section className="mb-6">
        <SectionHeader
          title="Vulnerabilidades Confirmadas"
          desc="Scan ativo com Nuclei (8000+ templates de CVEs e misconfigs) e Nmap NSE (scripts de vuln/auth). IPs de alto risco sao escaneados automaticamente. Clique em qualquer linha para ver detalhes e prova."
        />
        <ErrorBoundary>
          <VulnPanel />
        </ErrorBoundary>
      </section>

      {/* Results table */}
      <section>
        <SectionHeader
          title="Últimos 100 IPs encontrados"
          desc="Tabela completa dos IPs mais recentes com dados do Shodan InternetDB. Clique em 'Router' para ver banners de serviços detectados (HTTP title/server, SSH banner, Telnet)."
        />
        <ErrorBoundary>
          <ResultsTable results={results} onShowRouter={showRouter} />
        </ErrorBoundary>
      </section>

      <RouterModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        items={routerInfo}
        loading={routerLoading}
      />
    </>
  );
}
