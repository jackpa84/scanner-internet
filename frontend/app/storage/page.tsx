"use client";

import { useEffect, useState, useCallback } from "react";
import { RefreshBadge } from "@/components/RefreshBadge";
import { fetchDbStats, DbStats, CollectionStat, MongoCollectionStat } from "@/lib/api";

const REFRESH_INTERVAL = 15;

function fmt(bytes: number): string {
  if (bytes >= 1_073_741_824) return (bytes / 1_073_741_824).toFixed(1) + " GB";
  if (bytes >= 1_048_576) return (bytes / 1_048_576).toFixed(1) + " MB";
  if (bytes >= 1_024) return (bytes / 1_024).toFixed(1) + " KB";
  return bytes + " B";
}

function fmtNum(n: number): string {
  return n.toLocaleString("pt-BR");
}

function fmtUptime(sec: number): string {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function UsageBar({ pct }: { pct: number | null }) {
  if (pct === null) return <span className="text-[var(--muted)] text-xs">sem limite</span>;
  const color = pct >= 90 ? "bg-red-500" : pct >= 70 ? "bg-amber-400" : "bg-emerald-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${Math.min(pct, 100)}%` }} />
      </div>
      <span className="text-[10px] font-mono text-[var(--muted)] w-10 text-right">{pct}%</span>
    </div>
  );
}

function CollectionRow({ col }: { col: CollectionStat }) {
  return (
    <div className="grid grid-cols-[200px_1fr_80px_80px] items-center gap-4 px-4 py-2.5 border-b border-[var(--border)] last:border-0 hover:bg-white/[0.02] transition-colors">
      <div>
        <span className="font-mono text-xs text-[var(--foreground)]">{col.name}</span>
        {col.error && <span className="ml-2 text-[10px] text-red-400">{col.error}</span>}
      </div>
      <UsageBar pct={col.usage_pct} />
      <span className="text-right font-mono text-xs text-[var(--foreground)]">{fmtNum(col.count)}</span>
      <span className="text-right font-mono text-xs text-[var(--muted)]">{fmt(col.size_bytes)}</span>
    </div>
  );
}

function MongoRow({ col }: { col: MongoCollectionStat }) {
  return (
    <div className="grid grid-cols-[180px_70px_90px_90px_60px_50px] items-center gap-3 px-4 py-2.5 border-b border-[var(--border)] last:border-0 hover:bg-white/[0.02] transition-colors">
      <span className="font-mono text-xs text-[var(--foreground)]">{col.name}</span>
      <span className="text-right font-mono text-xs text-[var(--foreground)]">{fmtNum(col.count)}</span>
      <span className="text-right font-mono text-xs text-[var(--muted)]">{fmt(col.size_bytes)}</span>
      <span className="text-right font-mono text-xs text-[var(--muted)]">{fmt(col.storage_size_bytes)}</span>
      <span className="text-right font-mono text-xs text-[var(--muted)]">{fmt(col.avg_obj_size)}</span>
      <span className="text-right font-mono text-xs text-[var(--muted)]">{col.indexes}</span>
    </div>
  );
}

function StatCard({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl px-4 py-3">
      <p className="text-[10px] text-[var(--muted)] uppercase tracking-wider mb-1">{label}</p>
      <p className="text-lg font-mono font-semibold text-[var(--foreground)]">{value}</p>
      {sub && <p className="text-[10px] text-[var(--muted)] mt-0.5">{sub}</p>}
    </div>
  );
}

export default function StoragePage() {
  const [data, setData] = useState<DbStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(0);

  const load = useCallback(async () => {
    try {
      const res = await fetchDbStats();
      setData(res);
      setLastUpdated(Date.now());
    } catch { /* silent */ } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, REFRESH_INTERVAL * 1000);
    return () => clearInterval(id);
  }, [load]);

  const redis = data?.redis;
  const hitRate = redis && (redis.keyspace_hits + redis.keyspace_misses) > 0
    ? ((redis.keyspace_hits / (redis.keyspace_hits + redis.keyspace_misses)) * 100).toFixed(1)
    : null;

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-[var(--foreground)]">Storage</h1>
        <RefreshBadge intervalSec={REFRESH_INTERVAL} lastUpdated={lastUpdated} label="refresh" />
      </div>

      {loading && !data && (
        <div className="text-[var(--muted)] text-xs">Carregando...</div>
      )}

      {/* Redis Info Cards */}
      {redis && !redis.error && (
        <section className="space-y-3">
          <h2 className="text-xs font-semibold text-[var(--muted)] uppercase tracking-wider">Redis</h2>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <StatCard label="Memória usada" value={redis.used_memory_human} sub={`pico: ${redis.used_memory_peak_human}`} />
            <StatCard label="Ops/s" value={fmtNum(redis.instantaneous_ops_per_sec)} sub={`total: ${fmtNum(redis.total_commands_processed)}`} />
            <StatCard label="Hit rate" value={hitRate ? `${hitRate}%` : "—"} sub={`hits: ${fmtNum(redis.keyspace_hits)}`} />
            <StatCard label="Clientes" value={String(redis.connected_clients)} sub={`uptime: ${fmtUptime(redis.uptime_seconds)}`} />
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <StatCard label="Total de keys" value={fmtNum(redis.total_keys)} />
            <StatCard label="Fragmentação" value={`${redis.mem_fragmentation_ratio.toFixed(2)}x`} />
            <StatCard label="Versão" value={`v${redis.version}`} sub={`max: ${redis.maxmemory_human}`} />
          </div>
        </section>
      )}

      {/* Redis Collections */}
      {data?.collections && data.collections.length > 0 && (
        <section className="space-y-2">
          <h2 className="text-xs font-semibold text-[var(--muted)] uppercase tracking-wider">Collections Redis</h2>
          <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl overflow-hidden">
            {/* Header */}
            <div className="grid grid-cols-[200px_1fr_80px_80px] gap-4 px-4 py-2 border-b border-[var(--border)] bg-white/[0.02]">
              <span className="text-[10px] text-[var(--muted)] uppercase tracking-wider">Collection</span>
              <span className="text-[10px] text-[var(--muted)] uppercase tracking-wider">Uso</span>
              <span className="text-right text-[10px] text-[var(--muted)] uppercase tracking-wider">Docs</span>
              <span className="text-right text-[10px] text-[var(--muted)] uppercase tracking-wider">Tamanho</span>
            </div>
            {data.collections.map(col => <CollectionRow key={col.name} col={col} />)}
          </div>
        </section>
      )}

      {/* MongoDB */}
      <section className="space-y-2">
        <div className="flex items-center gap-2">
          <h2 className="text-xs font-semibold text-[var(--muted)] uppercase tracking-wider">MongoDB</h2>
          {data?.mongo && (
            <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${
              data.mongo.connected
                ? "bg-emerald-500/15 text-emerald-400"
                : "bg-red-500/15 text-red-400"
            }`}>
              {data.mongo.connected ? "conectado" : "offline"}
            </span>
          )}
        </div>

        {data?.mongo?.connected && data.mongo.collections && data.mongo.collections.length > 0 ? (
          <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl overflow-hidden">
            <div className="grid grid-cols-[180px_70px_90px_90px_60px_50px] gap-3 px-4 py-2 border-b border-[var(--border)] bg-white/[0.02]">
              <span className="text-[10px] text-[var(--muted)] uppercase tracking-wider">Collection</span>
              <span className="text-right text-[10px] text-[var(--muted)] uppercase tracking-wider">Docs</span>
              <span className="text-right text-[10px] text-[var(--muted)] uppercase tracking-wider">Tamanho</span>
              <span className="text-right text-[10px] text-[var(--muted)] uppercase tracking-wider">Storage</span>
              <span className="text-right text-[10px] text-[var(--muted)] uppercase tracking-wider">Avg</span>
              <span className="text-right text-[10px] text-[var(--muted)] uppercase tracking-wider">Idx</span>
            </div>
            {data.mongo.collections.map(col => <MongoRow key={col.name} col={col} />)}
          </div>
        ) : data?.mongo?.connected ? (
          <div className="text-xs text-[var(--muted)] bg-[var(--card)] border border-[var(--border)] rounded-xl px-4 py-3">
            Nenhuma collection encontrada.
          </div>
        ) : (
          <div className="text-xs text-[var(--muted)] bg-[var(--card)] border border-[var(--border)] rounded-xl px-4 py-3">
            MongoDB offline — usando apenas Redis.
            {data?.mongo?.error && <span className="ml-2 text-red-400/70">{data.mongo.error}</span>}
          </div>
        )}
      </section>
    </div>
  );
}
