"use client";

import { useState } from "react";
import type { ScanResult } from "@/lib/api";
import { triggerVulnScan } from "@/lib/api";

function formatDate(iso: string | undefined) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("pt-BR", {
      day: "2-digit",
      month: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch (_e) {
    return iso;
  }
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
    <span className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[11px] font-semibold ${cls}`}>
      {l.toUpperCase()} {score ?? 0}
    </span>
  );
}

function FlagTag({ label, color }: { label: string; color: string }) {
  return (
    <span className={`rounded px-1 py-0.5 text-[10px] font-bold uppercase ${color}`}>
      {label}
    </span>
  );
}

function DetailRow({ label, value }: { label: string; value: string | undefined | null }) {
  if (!value) return null;
  return (
    <div className="flex gap-2 py-0.5">
      <span className="text-muted shrink-0 w-28">{label}:</span>
      <span className="text-foreground/90 break-all">{value}</span>
    </div>
  );
}

function ExpandedDetails({ r }: { r: ScanResult }) {
  const geo = r.geo;
  const net = r.network;
  const ti = r.threat_intel;

  return (
    <tr>
      <td colSpan={10} className="bg-card/80 px-4 py-3 border-b border-border">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4 text-xs">
          {/* Shodan InternetDB */}
          <div className="rounded-lg border border-sky-500/20 bg-sky-500/5 p-3">
            <div className="text-[10px] font-bold text-sky-400 uppercase mb-1.5">Shodan InternetDB</div>
            <DetailRow label="Portas" value={r.ports?.join(", ") || "Nenhuma"} />
            <DetailRow label="CVEs" value={r.vulns?.length ? r.vulns.join(", ") : "Nenhuma"} />
            <DetailRow label="Hostnames" value={r.hostnames?.length ? r.hostnames.join(", ") : undefined} />
            <DetailRow label="Reverse DNS" value={r.rdns} />
          </div>

          {/* Geolocalização */}
          <div className="rounded-lg border border-violet-500/20 bg-violet-500/5 p-3">
            <div className="text-[10px] font-bold text-violet-400 uppercase mb-1.5">Geolocalização (IPinfo + ip-api)</div>
            <DetailRow label="País" value={geo?.country} />
            <DetailRow label="Cidade" value={geo?.city} />
            <DetailRow label="Região" value={geo?.region} />
            <DetailRow label="ISP" value={geo?.isp} />
            <DetailRow label="Organização" value={geo?.org} />
            <DetailRow label="ASN" value={geo?.as} />
            <DetailRow label="Timezone" value={geo?.timezone} />
            {geo?.lat && geo?.lon && (
              <DetailRow label="Coordenadas" value={`${geo.lat}, ${geo.lon}`} />
            )}
          </div>

          {/* Rede / Classificação */}
          <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3">
            <div className="text-[10px] font-bold text-amber-400 uppercase mb-1.5">Rede (ip-api.com)</div>
            <DetailRow label="ISP" value={net?.isp} />
            <DetailRow label="Organização" value={net?.org} />
            <DetailRow label="ASN" value={net?.as} />
            <DetailRow label="Proxy/VPN" value={net?.proxy ? "Sim" : "Não"} />
            <DetailRow label="Hosting" value={net?.hosting ? "Sim" : "Não"} />
            <DetailRow label="Mobile" value={net?.mobile ? "Sim" : "Não"} />
          </div>

          {/* Threat Intel */}
          <div className={`rounded-lg border p-3 ${ti?.known_threat ? "border-red-500/30 bg-red-500/5" : "border-border bg-card/50"}`}>
            <div className="text-[10px] font-bold text-red-400 uppercase mb-1.5">ThreatFox (abuse.ch)</div>
            {ti?.known_threat ? (
              <>
                <div className="text-red-300 font-semibold text-[11px] mb-1">Ameaça identificada</div>
                {ti.threats?.map((t, i) => (
                  <div key={i} className="border-t border-red-500/10 pt-1 mt-1">
                    <DetailRow label="Malware" value={t.malware_printable} />
                    <DetailRow label="Tipo" value={t.threat_type} />
                    <DetailRow label="Confiança" value={`${t.confidence}%`} />
                    <DetailRow label="Primeiro visto" value={t.first_seen} />
                    {t.tags?.length > 0 && (
                      <DetailRow label="Tags" value={t.tags.join(", ")} />
                    )}
                  </div>
                ))}
              </>
            ) : (
              <div className="text-muted">Nenhum IOC conhecido</div>
            )}
          </div>
        </div>

        {/* Risk breakdown */}
        {r.risk && (
          <div className="mt-3 rounded-lg border border-border bg-card/50 p-3">
            <div className="text-[10px] font-bold text-foreground/80 uppercase mb-1">
              Análise de risco — Score: {r.risk.score} ({r.risk.level.toUpperCase()})
            </div>
            <div className="flex flex-wrap gap-2 text-[11px] text-muted">
              {r.risk.reasons?.map((reason, i) => (
                <span key={i} className="rounded bg-background px-2 py-0.5 border border-border">
                  {reason}
                </span>
              ))}
            </div>
          </div>
        )}
      </td>
    </tr>
  );
}

const COLUMN_HINTS: Record<string, string> = {
  IP: "Endereço IPv4 público + reverse DNS",
  País: "Geolocalização via IPinfo.io / ip-api.com",
  "ISP / Org": "Provedor de internet ou organização proprietária do bloco IP",
  Portas: "Portas TCP abertas detectadas pelo Shodan InternetDB",
  CVEs: "Vulnerabilidades conhecidas (CVE) associadas aos serviços nas portas",
  Flags: "Classificações: threat (ThreatFox), proxy/VPN (ip-api), hosting, mobile",
  Router: "Serviços com banner/título detectados via probes HTTP/SSH/Telnet",
  Risco: "Score heurístico (0-100) baseado em CVEs, portas, threats e proxy",
  Scan: "Scan ativo de vulnerabilidades com Nuclei + Nmap",
  Hora: "Timestamp do momento da varredura",
};

export default function ResultsTable({
  results,
  onShowRouter,
}: {
  results: ScanResult[];
  onShowRouter: (id: string) => void;
}) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [scanningIps, setScanningIps] = useState<Set<string>>(new Set());

  const handleVulnScan = async (ip: string) => {
    setScanningIps((prev) => new Set(prev).add(ip));
    try {
      await triggerVulnScan(ip);
    } catch (e) {
      console.error("Vuln scan trigger error:", e);
    }
    setTimeout(() => {
      setScanningIps((prev) => {
        const next = new Set(prev);
        next.delete(ip);
        return next;
      });
    }, 3000);
  };

  if (results.length === 0) {
    return (
      <p className="text-muted py-8 text-center">Nenhum resultado ainda. Os workers estão varrendo...</p>
    );
  }

  const toggle = (id: string) => setExpandedId((prev) => (prev === id ? null : id));

  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full text-left text-xs">
        <thead className="bg-card text-muted border-b border-border">
          <tr>
            {Object.entries(COLUMN_HINTS).map(([col, hint]) => (
              <th key={col} className="px-3 py-2.5 font-medium" title={hint}>
                <span className="cursor-help border-b border-dotted border-muted/30">{col}</span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {results.map((r) => {
            const geo = r.geo;
            const net = r.network;
            const isThreat = r.threat_intel?.known_threat;
            const isProxy = net?.proxy || geo?.proxy;
            const isHosting = net?.hosting || geo?.hosting;
            const isMobile = net?.mobile || geo?.mobile;
            const isExpanded = expandedId === r.id;

            return (
              <>
                <tr
                  key={r.id}
                  className={`hover:bg-card/50 transition-colors cursor-pointer ${isExpanded ? "bg-card/40" : ""}`}
                  onClick={() => toggle(r.id)}
                >
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-1">
                      <span className={`text-[10px] transition-transform ${isExpanded ? "rotate-90" : ""}`}>▶</span>
                      <div>
                        <div className="font-mono text-accent">{r.ip}</div>
                        {r.rdns && (
                          <div className="text-[10px] text-muted truncate max-w-[180px]" title={r.rdns}>
                            {r.rdns}
                          </div>
                        )}
                      </div>
                    </div>
                  </td>

                  <td className="px-3 py-2 text-muted">
                    {geo?.country ? (
                      <div>
                        <span className="font-semibold text-foreground">{geo.country}</span>
                        {geo.city && <span className="ml-1 text-[10px]">{geo.city}</span>}
                      </div>
                    ) : "—"}
                  </td>

                  <td className="px-3 py-2 text-muted max-w-[160px] truncate" title={geo?.isp || net?.isp || geo?.org || ""}>
                    {geo?.isp || net?.isp || geo?.org || "—"}
                  </td>

                  <td className="px-3 py-2 text-muted max-w-[120px]">
                    <span className="truncate block" title={r.ports?.join(", ")}>
                      {r.ports?.length ? r.ports.slice(0, 6).join(", ") : "—"}
                      {(r.ports?.length ?? 0) > 6 && <span className="text-accent"> +{r.ports.length - 6}</span>}
                    </span>
                  </td>

                  <td className="px-3 py-2 text-muted">
                    {r.vulns?.length ? (
                      <span className="text-amber-300" title={r.vulns.join(", ")}>
                        {r.vulns.length} CVE{r.vulns.length > 1 ? "s" : ""}
                      </span>
                    ) : "—"}
                  </td>

                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      {isThreat && <FlagTag label="threat" color="bg-red-500/20 text-red-400" />}
                      {isProxy && <FlagTag label="proxy" color="bg-violet-500/20 text-violet-400" />}
                      {isHosting && <FlagTag label="hosting" color="bg-blue-500/20 text-blue-400" />}
                      {isMobile && <FlagTag label="mobile" color="bg-orange-500/20 text-orange-400" />}
                      {!isThreat && !isProxy && !isHosting && !isMobile && (
                        <span className="text-muted">—</span>
                      )}
                    </div>
                  </td>

                  <td className="px-3 py-2">
                    {r.router_count > 0 ? (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onShowRouter(r.id);
                        }}
                        className="text-accent hover:underline"
                      >
                        {r.router_count} svc
                      </button>
                    ) : (
                      <span className="text-muted">—</span>
                    )}
                  </td>

                  <td className="px-3 py-2">
                    <RiskBadge level={r.risk?.level} score={r.risk?.score} />
                  </td>

                  <td className="px-3 py-2">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleVulnScan(r.ip);
                      }}
                      disabled={scanningIps.has(r.ip)}
                      className="rounded border border-purple-500/40 bg-purple-500/10 px-2 py-0.5 text-[10px] font-semibold text-purple-300 hover:bg-purple-500/20 transition-colors disabled:opacity-50"
                      title="Scan ativo com Nuclei + Nmap"
                    >
                      {scanningIps.has(r.ip) ? "Enfileirado" : "Scan"}
                    </button>
                  </td>

                  <td className="px-3 py-2 text-muted whitespace-nowrap">{formatDate(r.timestamp)}</td>
                </tr>
                {isExpanded && <ExpandedDetails key={`${r.id}-details`} r={r} />}
              </>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
