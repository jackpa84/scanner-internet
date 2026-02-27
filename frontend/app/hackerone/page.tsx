"use client";

import { useState, useCallback, useEffect } from "react";
import {
  fetchHackerOneReports,
  fetchHackerOneEarnings,
  fetchHackerOnePrograms,
  type HackerOneListResponse,
  type HackerOnePageParams,
} from "@/lib/api";

const PAGE_SIZE = 20;
type TabId = "reports" | "earnings" | "programs";

const TABS: { id: TabId; label: string }[] = [
  { id: "reports", label: "Reports" },
  { id: "earnings", label: "Earnings" },
  { id: "programs", label: "Programas" },
];

function extractCursor(link: string | undefined, kind: "after" | "before"): string | undefined {
  if (!link) return undefined;
  try {
    const url = new URL(link.startsWith("http") ? link : `https://api.hackerone.com/${link}`);
    return url.searchParams.get(kind === "after" ? "page[after]" : "page[before]") ?? undefined;
  } catch { return undefined; }
}

export default function HackerOnePage() {
  const [tab, setTab] = useState<TabId>("reports");
  const [data, setData] = useState<Record<TabId, HackerOneListResponse | null>>({ reports: null, earnings: null, programs: null });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchers: Record<TabId, (p: HackerOnePageParams) => Promise<HackerOneListResponse>> = {
    reports: fetchHackerOneReports,
    earnings: fetchHackerOneEarnings,
    programs: fetchHackerOnePrograms,
  };

  const loadTab = useCallback(async (t: TabId, params: HackerOnePageParams = { page_size: PAGE_SIZE }) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetchers[t](params);
      setData(prev => ({ ...prev, [t]: res }));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Erro ao carregar");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadTab(tab);
  }, [tab, loadTab]);

  const currentData = data[tab];
  const items = (currentData?.data ?? []) as Array<{ id: string; type: string; attributes?: Record<string, unknown>; relationships?: Record<string, unknown> }>;
  const hasNext = Boolean(currentData?.links?.next);
  const hasPrev = Boolean(currentData?.links?.prev);

  const navigate = (direction: "next" | "prev") => {
    const link = direction === "next" ? currentData?.links?.next : currentData?.links?.prev;
    const cursor = extractCursor(link, direction === "next" ? "after" : "before");
    if (cursor) {
      const params: HackerOnePageParams = { page_size: PAGE_SIZE };
      if (direction === "next") params.page_after = cursor;
      else params.page_before = cursor;
      loadTab(tab, params);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-xl font-bold text-[var(--foreground)]">HackerOne</h1>
        <p className="text-sm text-[var(--muted)] mt-1">Reports, earnings e programas da sua conta.</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 rounded-xl border border-[var(--border)] bg-[var(--card)] p-1 w-fit">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`rounded-lg px-4 py-2 text-sm font-medium transition-all ${
              tab === t.id
                ? "bg-[var(--accent)]/15 text-[var(--accent-light)] shadow-sm"
                : "text-[var(--muted)] hover:text-[var(--foreground)]"
            }`}>
            {t.label}
          </button>
        ))}
      </div>

      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 px-4 py-3 text-sm text-red-400">{error}</div>
      )}

      {loading && (
        <div className="py-8 text-center text-sm text-[var(--muted)]">Carregando...</div>
      )}

      {!loading && currentData && items.length === 0 && (
        <div className="rounded-2xl border border-dashed border-[var(--border)] bg-[var(--card)]/50 py-8 text-center text-sm text-[var(--muted)]">
          Nenhum item encontrado.
        </div>
      )}

      {!loading && items.length > 0 && (
        <div className="rounded-2xl border border-[var(--border)] bg-[var(--card)]/60 overflow-hidden">
          <ul className="divide-y divide-[var(--border)]">
            {tab === "reports" && items.map(item => {
              const a = (item.attributes ?? {}) as Record<string, unknown>;
              const title = String(a.title ?? "(sem titulo)");
              const state = a.state ? String(a.state) : "";
              const createdAt = a.created_at ? String(a.created_at) : "";
              const url = a.url ? String(a.url) : "";
              return (
                <li key={item.id} className="px-5 py-3.5 hover:bg-[var(--card-hover)] transition-all">
                  <div className="flex items-center justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="font-medium text-[var(--foreground)] text-sm truncate">{title}</div>
                      <div className="flex gap-2 mt-1 text-xs text-[var(--muted)]">
                        {state && <span className="rounded-md bg-[var(--background)] border border-[var(--border)] px-2 py-0.5">{state}</span>}
                        {createdAt && <span>{new Date(createdAt).toLocaleDateString("pt-BR")}</span>}
                      </div>
                    </div>
                    {url && <a href={url} target="_blank" rel="noopener noreferrer" className="text-xs text-[var(--accent-light)] hover:underline shrink-0">Abrir</a>}
                  </div>
                </li>
              );
            })}

            {tab === "earnings" && items.map(item => {
              const a = (item.attributes ?? {}) as Record<string, unknown>;
              const rels = (item.relationships ?? {}) as Record<string, { data?: { attributes?: { name?: string } } }>;
              const amount = typeof a.amount === "number" ? a.amount : null;
              const teamName = rels.team?.data?.attributes?.name ?? "";
              const createdAt = a.created_at ? String(a.created_at) : "";
              return (
                <li key={item.id} className="px-5 py-3.5 hover:bg-[var(--card-hover)] transition-all">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="font-bold text-emerald-400 text-sm">
                        {amount != null ? `$${amount.toLocaleString("en-US", { minimumFractionDigits: 2 })}` : "-"}
                      </div>
                      <div className="text-xs text-[var(--muted)] mt-0.5">
                        {teamName}
                        {createdAt && <span className="ml-2">{new Date(createdAt).toLocaleDateString("pt-BR")}</span>}
                      </div>
                    </div>
                  </div>
                </li>
              );
            })}

            {tab === "programs" && items.map(item => {
              const a = (item.attributes ?? {}) as Record<string, unknown>;
              const name = String(a.name || a.handle || item.id);
              const handle = a.handle ? String(a.handle) : "";
              const url = a.url ? String(a.url) : "";
              return (
                <li key={item.id} className="px-5 py-3.5 hover:bg-[var(--card-hover)] transition-all">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="font-medium text-[var(--foreground)] text-sm">{name}</div>
                      {handle && <div className="text-xs text-[var(--muted)] mt-0.5">@{handle}</div>}
                    </div>
                    {url && <a href={url} target="_blank" rel="noopener noreferrer" className="text-xs text-[var(--accent-light)] hover:underline shrink-0">Abrir</a>}
                  </div>
                </li>
              );
            })}
          </ul>

          {/* Pagination */}
          <div className="flex items-center justify-between border-t border-[var(--border)] px-5 py-3 bg-[var(--background)]/30">
            <button onClick={() => navigate("prev")} disabled={!hasPrev || loading}
              className="rounded-lg px-3 py-1.5 text-sm text-[var(--muted)] hover:text-[var(--foreground)] hover:bg-[var(--card)] disabled:opacity-30 disabled:pointer-events-none transition-all">
              Anteriores
            </button>
            <span className="text-xs text-[var(--muted)] tabular-nums">{items.length} itens</span>
            <button onClick={() => navigate("next")} disabled={!hasNext || loading}
              className="rounded-lg px-3 py-1.5 text-sm text-[var(--muted)] hover:text-[var(--foreground)] hover:bg-[var(--card)] disabled:opacity-30 disabled:pointer-events-none transition-all">
              Proximos
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
