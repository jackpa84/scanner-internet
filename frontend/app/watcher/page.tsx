"use client";

import { useState, useCallback, useEffect } from "react";
import { RefreshBadge } from "@/components/RefreshBadge";
import {
  fetchWatcherStatus,
  triggerWatcherCheck,
  triggerWatcherCheckSingle,
  fetchWatcherPrograms,
  type WatcherStatusResponse,
  type WatcherCheckResponse,
} from "@/lib/api";

/* ═══════════════════════════════════════════════════════════════
   Cores por plataforma
   ═══════════════════════════════════════════════════════════════ */
const PLATFORM_COLORS: Record<string, { text: string; border: string; bg: string; icon: string }> = {
  hackerone:  { text: "text-purple-400",  border: "border-purple-500/30",  bg: "bg-purple-500/10",  icon: "🟣" },
  bugcrowd:  { text: "text-orange-400",  border: "border-orange-500/30",  bg: "bg-orange-500/10",  icon: "🟠" },
  intigriti: { text: "text-blue-400",    border: "border-blue-500/30",    bg: "bg-blue-500/10",    icon: "🔵" },
  yeswehack: { text: "text-red-400",     border: "border-red-500/30",     bg: "bg-red-500/10",     icon: "🔴" },
  bughunt:   { text: "text-green-400",   border: "border-green-500/30",   bg: "bg-green-500/10",   icon: "🟢" },
};

const defaultColor = { text: "text-gray-400", border: "border-gray-500/30", bg: "bg-gray-500/10", icon: "⚪" };

/* ═══════════════════════════════════════════════════════════════
   Página dedicada — Platform Watcher
   ═══════════════════════════════════════════════════════════════ */
export default function WatcherPage() {
  const [status, setStatus] = useState<WatcherStatusResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<WatcherCheckResponse | null>(null);
  const [lastUpdated, setLastUpdated] = useState(0);
  const [selectedPlatform, setSelectedPlatform] = useState<string | null>(null);
  const [platformPrograms, setPlatformPrograms] = useState<Record<string, unknown>[] | null>(null);
  const [programsLoading, setProgramsLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<"overview" | "programs" | "config">("overview");

  /* ── Carregar status ───────────────────────────────────── */
  const loadStatus = useCallback(async () => {
    try {
      const s = await fetchWatcherStatus();
      setStatus(s);
      setLastUpdated(Date.now());
    } catch (e) {
      console.error("[WATCHER] Erro ao carregar status:", e);
    }
  }, []);

  useEffect(() => {
    loadStatus();
    const id = setInterval(loadStatus, 20000);
    return () => clearInterval(id);
  }, [loadStatus]);

  /* ── Check todas as plataformas ────────────────────────── */
  const handleCheckAll = async () => {
    setLoading(true);
    try {
      const res = await triggerWatcherCheck();
      setResults(res);
      await loadStatus();
    } catch (e) { console.error(e); }
    setLoading(false);
  };

  /* ── Check uma plataforma ──────────────────────────────── */
  const handleCheckSingle = async (platform: string) => {
    setLoading(true);
    try {
      const res = await triggerWatcherCheckSingle(platform);
      setResults(prev => ({
        results: { ...(prev?.results || {}), ...res.results },
      }));
      await loadStatus();
    } catch (e) { console.error(e); }
    setLoading(false);
  };

  /* ── Carregar programas de uma plataforma ──────────────── */
  const handleLoadPrograms = async (platform: string) => {
    setSelectedPlatform(platform);
    setProgramsLoading(true);
    try {
      const data = await fetchWatcherPrograms(platform);
      setPlatformPrograms(data.programs || []);
    } catch (e) {
      console.error(e);
      setPlatformPrograms([]);
    }
    setProgramsLoading(false);
  };

  /* ── Stats helpers ─────────────────────────────────────── */
  const totalFound = status
    ? Object.values(status.stats.programs_found).reduce((a, b) => a + b, 0)
    : 0;

  const tabs = [
    { id: "overview" as const, label: "Visão Geral",  icon: "📊" },
    { id: "programs" as const, label: "Programas",     icon: "🎯" },
    { id: "config"   as const, label: "Configuração",  icon: "⚙️" },
  ];

  return (
    <div className="space-y-4">
      {/* ═══ Header ═══ */}
      <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl p-5">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-base font-bold flex items-center gap-2">
              👁 Platform Watcher
              {status?.stats.running && (
                <span className="text-[9px] bg-emerald-600/20 text-emerald-400 px-2 py-0.5 rounded-full animate-pulse">
                  ● ATIVO
                </span>
              )}
              <RefreshBadge intervalSec={20} lastUpdated={lastUpdated} />
            </h1>
            <p className="text-[11px] text-[var(--muted)] mt-1">
              Scraping ativo das APIs oficiais de plataformas de bug bounty —
              detecta novos programas, mudanças de escopo e remoções em tempo real.
            </p>
          </div>
          <button
            onClick={handleCheckAll}
            disabled={loading}
            className="px-4 py-2 text-xs font-medium rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {loading ? (
              <><span className="animate-spin">⏳</span> Verificando...</>
            ) : (
              <>🔄 Verificar Todas</>
            )}
          </button>
        </div>

        {/* Stats strip */}
        <div className="grid grid-cols-2 md:grid-cols-6 gap-2 mt-4">
          {[
            { label: "Checks Totais", value: status?.stats.total_checks || 0, color: "text-emerald-400" },
            { label: "Programas", value: totalFound, color: "text-blue-400" },
            { label: "Novos", value: status?.stats.new_programs || 0, color: "text-yellow-400" },
            { label: "Escopo Alterado", value: status?.stats.scope_changes || 0, color: "text-orange-400" },
            { label: "Erros", value: status?.stats.errors || 0, color: "text-red-400" },
            { label: "Plataformas", value: status?.platforms.filter(p => p.configured).length || 0, color: "text-cyan-400" },
          ].map(s => (
            <div key={s.label} className="bg-black/20 rounded-lg p-2.5 text-center">
              <div className={`text-lg font-bold ${s.color}`}>{s.value}</div>
              <div className="text-[9px] text-[var(--muted)]">{s.label}</div>
            </div>
          ))}
        </div>

        {status?.stats.last_check && (
          <div className="text-[9px] text-[var(--muted)] mt-3 flex items-center gap-3">
            <span>🕐 Último check: {new Date(status.stats.last_check).toLocaleString("pt-BR")}</span>
            <span>|</span>
            <span>Intervalo: a cada 30 min</span>
          </div>
        )}
      </div>

      {/* ═══ Sub-tabs ═══ */}
      <div className="flex items-center gap-1 bg-[var(--card)] border border-[var(--border)] rounded-xl p-1 w-fit">
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            className={`px-4 py-2 text-xs font-medium rounded-lg transition-all flex items-center gap-1.5 ${
              activeTab === t.id
                ? "bg-white/10 text-white shadow-sm"
                : "text-[var(--muted)] hover:text-white hover:bg-white/5"
            }`}
          >
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {/* ═══ TAB: Visão Geral ═══ */}
      {activeTab === "overview" && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {status?.platforms.map(p => {
            const c = PLATFORM_COLORS[p.name] || defaultColor;
            const found = status.stats.programs_found[p.name] || 0;
            const lastResult = results?.results?.[p.name];

            return (
              <div key={p.name} className={`bg-[var(--card)] border ${c.border} rounded-xl p-4 transition-all hover:border-opacity-60`}>
                {/* Cabeçalho */}
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <span className="text-base">{c.icon}</span>
                    <span className={`text-sm font-bold uppercase ${c.text}`}>{p.name}</span>
                    {p.configured ? (
                      <span className="text-[8px] bg-emerald-600/20 text-emerald-400 px-1.5 py-0.5 rounded">✓ OK</span>
                    ) : (
                      <span className="text-[8px] bg-red-600/20 text-red-400 px-1.5 py-0.5 rounded">✗ Sem token</span>
                    )}
                  </div>
                  <div className="flex gap-1.5">
                    <button
                      onClick={() => handleLoadPrograms(p.name)}
                      disabled={!p.configured}
                      className="px-2 py-1 text-[9px] rounded bg-white/5 hover:bg-white/10 transition-colors disabled:opacity-30"
                      title="Ver programas"
                    >
                      📋
                    </button>
                    <button
                      onClick={() => handleCheckSingle(p.name)}
                      disabled={loading || !p.configured}
                      className="px-2 py-1 text-[9px] rounded bg-white/5 hover:bg-white/10 transition-colors disabled:opacity-30"
                      title="Executar scraping"
                    >
                      ▶️
                    </button>
                  </div>
                </div>

                {/* Métricas */}
                <div className="space-y-1.5 text-[10px]">
                  <div className="flex justify-between">
                    <span className="text-[var(--muted)]">Programas em cache</span>
                    <span className="font-mono font-semibold">{found}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[var(--muted)]">Habilitado</span>
                    <span>{p.enabled ? "✅" : "❌"}</span>
                  </div>

                  {/* Resultado do último scan */}
                  {lastResult && (
                    <div className="border-t border-[var(--border)] pt-2 mt-2">
                      <div className="text-[9px] text-[var(--muted)] mb-1.5 font-medium">Último resultado:</div>
                      {lastResult.status === "ok" ? (
                        <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
                          <div className="flex justify-between">
                            <span className="text-[var(--muted)]">Programas</span>
                            <span className="font-mono text-blue-400">{lastResult.programs}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-[var(--muted)]">Novos</span>
                            <span className="font-mono text-emerald-400">+{lastResult.new || 0}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-[var(--muted)]">Escopo</span>
                            <span className="font-mono text-yellow-400">~{lastResult.scope_changed || 0}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-[var(--muted)]">Importados</span>
                            <span className="font-mono">{lastResult.imported || 0}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-[var(--muted)]">Atualizados</span>
                            <span className="font-mono">{lastResult.updated || 0}</span>
                          </div>
                          {lastResult.elapsed_seconds != null && (
                            <div className="flex justify-between">
                              <span className="text-[var(--muted)]">Tempo</span>
                              <span className="font-mono text-gray-400">{lastResult.elapsed_seconds}s</span>
                            </div>
                          )}
                        </div>
                      ) : lastResult.status === "skipped" ? (
                        <div className="text-yellow-400 text-[9px]">⏭ Ignorado: {lastResult.reason}</div>
                      ) : (
                        <div className="text-red-400 text-[9px]">❌ Erro: {lastResult.error}</div>
                      )}
                    </div>
                  )}
                </div>

                {/* Barra de progresso visual */}
                <div className={`mt-3 h-1 rounded-full ${c.bg}`}>
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      found > 0 ? c.text.replace("text-", "bg-") : "bg-transparent"
                    }`}
                    style={{ width: `${Math.min((found / Math.max(totalFound, 1)) * 100, 100)}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ═══ TAB: Programas ═══ */}
      {activeTab === "programs" && (
        <div className="space-y-3">
          {/* Seletor de plataforma */}
          <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl p-4">
            <h3 className="text-xs font-semibold mb-3">Selecione uma plataforma para ver os programas coletados:</h3>
            <div className="flex flex-wrap gap-2">
              {status?.platforms.filter(p => p.configured).map(p => {
                const c = PLATFORM_COLORS[p.name] || defaultColor;
                const found = status.stats.programs_found[p.name] || 0;
                const active = selectedPlatform === p.name;
                return (
                  <button
                    key={p.name}
                    onClick={() => handleLoadPrograms(p.name)}
                    className={`px-3 py-2 text-[10px] font-medium rounded-lg transition-all flex items-center gap-2 border ${
                      active
                        ? `${c.border} ${c.bg} ${c.text}`
                        : "border-[var(--border)] text-[var(--muted)] hover:bg-white/5"
                    }`}
                  >
                    {c.icon} <span className="uppercase font-bold">{p.name}</span>
                    <span className="font-mono text-[9px] opacity-70">({found})</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Lista de programas */}
          {selectedPlatform && (
            <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-xs font-semibold flex items-center gap-2">
                  {(PLATFORM_COLORS[selectedPlatform] || defaultColor).icon}
                  <span className="uppercase">{selectedPlatform}</span>
                  <span className="text-[9px] text-[var(--muted)] font-normal">
                    — {platformPrograms?.length || 0} programas
                  </span>
                </h3>
                <button
                  onClick={() => handleCheckSingle(selectedPlatform)}
                  disabled={loading}
                  className="px-2.5 py-1 text-[9px] rounded-lg bg-emerald-600/20 text-emerald-400 hover:bg-emerald-600/30 transition-colors disabled:opacity-50"
                >
                  🔄 Atualizar
                </button>
              </div>

              {programsLoading ? (
                <div className="text-center text-[var(--muted)] text-xs py-8">
                  <span className="animate-spin inline-block mr-2">⏳</span> Carregando programas...
                </div>
              ) : platformPrograms && platformPrograms.length > 0 ? (
                <div className="overflow-auto max-h-[520px]">
                  <table className="w-full text-[10px]">
                    <thead className="text-[var(--muted)] border-b border-[var(--border)]">
                      <tr>
                        <th className="text-left py-2 px-2 font-medium">Programa</th>
                        <th className="text-left py-2 px-2 font-medium">Tipo</th>
                        <th className="text-center py-2 px-2 font-medium">Escopo</th>
                        <th className="text-right py-2 px-2 font-medium">Max Bounty</th>
                        <th className="text-left py-2 px-2 font-medium">URL</th>
                      </tr>
                    </thead>
                    <tbody>
                      {platformPrograms.map((prog, i) => (
                        <tr key={i} className="border-b border-[var(--border)] hover:bg-white/[0.02] transition-colors">
                          <td className="py-2 px-2 font-medium text-white max-w-[200px] truncate">
                            {String(prog.name || "—")}
                          </td>
                          <td className="py-2 px-2">
                            <span className={`px-1.5 py-0.5 rounded text-[8px] font-medium ${
                              prog.reward_type === "bounty"
                                ? "bg-emerald-600/20 text-emerald-400"
                                : "bg-gray-600/20 text-gray-400"
                            }`}>
                              {String(prog.reward_type || "—")}
                            </span>
                          </td>
                          <td className="py-2 px-2 text-center font-mono">
                            {Array.isArray(prog.scope) ? prog.scope.length : 0}
                          </td>
                          <td className="py-2 px-2 text-right font-mono text-emerald-400">
                            {Number(prog.max_bounty) > 0 ? `$${Number(prog.max_bounty).toLocaleString()}` : "—"}
                          </td>
                          <td className="py-2 px-2 max-w-[180px] truncate">
                            {prog.url ? (
                              <a
                                href={String(prog.url)}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-blue-400 hover:underline"
                              >
                                {String(prog.url).replace(/^https?:\/\//, "").slice(0, 40)}
                              </a>
                            ) : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="text-center text-[var(--muted)] text-xs py-8">
                  Nenhum programa em cache.
                  <button
                    onClick={() => handleCheckSingle(selectedPlatform)}
                    className="ml-2 text-emerald-400 hover:underline"
                  >
                    Execute um scan primeiro.
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ═══ TAB: Configuração ═══ */}
      {activeTab === "config" && (
        <div className="space-y-4">
          {/* Status de cada plataforma */}
          <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl p-4">
            <h3 className="text-xs font-semibold mb-3">🔗 Status das Plataformas</h3>
            <div className="space-y-2">
              {status?.platforms.map(p => {
                const c = PLATFORM_COLORS[p.name] || defaultColor;
                return (
                  <div
                    key={p.name}
                    className={`flex items-center justify-between p-3 rounded-lg border ${c.border} ${c.bg}`}
                  >
                    <div className="flex items-center gap-3">
                      <span>{c.icon}</span>
                      <span className={`text-xs font-bold uppercase ${c.text}`}>{p.name}</span>
                    </div>
                    <div className="flex items-center gap-4 text-[10px]">
                      <div className="flex items-center gap-1.5">
                        <span className="text-[var(--muted)]">Token:</span>
                        {p.configured ? (
                          <span className="text-emerald-400">✓ Configurado</span>
                        ) : (
                          <span className="text-red-400">✗ Ausente</span>
                        )}
                      </div>
                      <div className="flex items-center gap-1.5">
                        <span className="text-[var(--muted)]">Ativo:</span>
                        <span>{p.enabled ? "✅" : "❌"}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Variáveis de ambiente */}
          <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl p-4">
            <h3 className="text-xs font-semibold mb-2">⚙️ Variáveis de Ambiente Necessárias</h3>
            <p className="text-[10px] text-[var(--muted)] mb-3">
              Adicione estas variáveis no arquivo <code className="bg-white/5 px-1 rounded">.env</code> ou
              no <code className="bg-white/5 px-1 rounded">docker-compose.yml</code> para ativar cada plataforma.
            </p>
            <div className="font-mono text-[10px] text-[var(--muted)] space-y-0.5 bg-black/30 p-4 rounded-lg overflow-x-auto">
              <div className="text-[9px] text-gray-600 mb-2"># ── Geral ──</div>
              <div><span className="text-emerald-400">PLATFORM_WATCHER_ENABLED</span>=<span className="text-white">true</span></div>
              <div><span className="text-emerald-400">PLATFORM_WATCHER_INTERVAL</span>=<span className="text-white">1800</span> <span className="text-gray-600"># segundos entre cada check</span></div>
              <div><span className="text-emerald-400">PLATFORM_WATCHER_PLATFORMS</span>=<span className="text-white">hackerone,bugcrowd,intigriti,yeswehack,bughunt</span></div>

              <div className="text-[9px] text-gray-600 mt-3 mb-2"># ── HackerOne ──</div>
              <div><span className="text-purple-400">HACKERONE_API_USERNAME</span>=<span className="text-white/40">your_username</span></div>
              <div><span className="text-purple-400">HACKERONE_API_TOKEN</span>=<span className="text-white/40">your_api_token</span></div>

              <div className="text-[9px] text-gray-600 mt-3 mb-2"># ── Bugcrowd ──</div>
              <div><span className="text-orange-400">BUGCROWD_API_TOKEN</span>=<span className="text-white/40">your_token</span></div>

              <div className="text-[9px] text-gray-600 mt-3 mb-2"># ── Intigriti ──</div>
              <div><span className="text-blue-400">INTIGRITI_API_TOKEN</span>=<span className="text-white/40">your_token</span></div>

              <div className="text-[9px] text-gray-600 mt-3 mb-2"># ── YesWeHack ──</div>
              <div><span className="text-red-400">YESWEHACK_TOKEN</span>=<span className="text-white/40">your_token</span></div>

              <div className="text-[9px] text-gray-600 mt-3 mb-2"># ── BugHunt ──</div>
              <div><span className="text-green-400">BUGHUNT_EMAIL</span>=<span className="text-white/40">email@domain.com</span></div>
              <div><span className="text-green-400">BUGHUNT_PASSWORD</span>=<span className="text-white/40">password</span></div>
              <div><span className="text-green-400">CAPSOLVER_API_KEY</span>=<span className="text-white/40">key</span> <span className="text-gray-600"># para captcha (opcional)</span></div>

              <div className="text-[9px] text-gray-600 mt-3 mb-2"># ── Notificações ──</div>
              <div><span className="text-yellow-400">DISCORD_WEBHOOK_URL</span>=<span className="text-white/40">https://discord.com/api/webhooks/...</span></div>
              <div><span className="text-yellow-400">SLACK_WEBHOOK_URL</span>=<span className="text-white/40">https://hooks.slack.com/services/...</span></div>
            </div>
          </div>

          {/* Como funciona */}
          <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl p-4">
            <h3 className="text-xs font-semibold mb-3">📖 Como Funciona</h3>
            <div className="space-y-3 text-[10px] text-[var(--muted)]">
              <div className="flex gap-3">
                <span className="text-lg">1️⃣</span>
                <div>
                  <div className="font-medium text-white">Scraping Ativo</div>
                  <div>Consulta diretamente as APIs oficiais de cada plataforma (diferente do bounty-targets-data que lê dumps estáticos do GitHub).</div>
                </div>
              </div>
              <div className="flex gap-3">
                <span className="text-lg">2️⃣</span>
                <div>
                  <div className="font-medium text-white">Detecção de Mudanças</div>
                  <div>Compara cada scrape com o cache anterior: novos programas, mudanças de escopo, programas removidos.</div>
                </div>
              </div>
              <div className="flex gap-3">
                <span className="text-lg">3️⃣</span>
                <div>
                  <div className="font-medium text-white">Persistência</div>
                  <div>Salva/atualiza programas na collection <code className="bg-white/5 px-1 rounded">bounty_programs</code> do Redis — disponível para recon e scanning.</div>
                </div>
              </div>
              <div className="flex gap-3">
                <span className="text-lg">4️⃣</span>
                <div>
                  <div className="font-medium text-white">Notificações</div>
                  <div>Envia alertas via Discord e/ou Slack quando detecta novos programas ou alterações de escopo.</div>
                </div>
              </div>
              <div className="flex gap-3">
                <span className="text-lg">5️⃣</span>
                <div>
                  <div className="font-medium text-white">Background</div>
                  <div>Roda automaticamente em background a cada intervalo configurado (padrão: 30 min).</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
