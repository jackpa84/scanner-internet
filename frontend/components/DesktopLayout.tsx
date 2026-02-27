"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "./AuthProvider";
import { fetchHealth, type HealthInfo } from "@/lib/api";

const NAV = [
  {
    href: "/",
    label: "Dashboard",
    icon: "M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z",
  },
  {
    href: "/hackerone",
    label: "HackerOne",
    icon: "M12 21v-8.25M15.75 21v-8.25M8.25 21v-8.25M3 9l9-6 9 6m-1.5 12V10.332A48.36 48.36 0 0012 9.75c-2.551 0-5.056.2-7.5.582V21M3 21h18M12 6.75h.008v.008H12V6.75z",
  },
];

export default function DesktopLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { logout } = useAuth();
  const [health, setHealth] = useState<HealthInfo | null>(null);

  const loadHealth = useCallback(async () => {
    try {
      const h = await fetchHealth();
      setHealth(h);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    loadHealth();
    const id = setInterval(loadHealth, 10_000);
    return () => clearInterval(id);
  }, [loadHealth]);

  const apis = health?.apis ?? [];
  const blockedCount = apis.filter(a => a.blocked).length;

  return (
    <div className="h-screen bg-[var(--background)] text-[var(--foreground)] flex overflow-hidden">
      <aside className="w-[260px] shrink-0 border-r border-[var(--border)] bg-[var(--card)]/60 backdrop-blur-sm flex flex-col">
        <div className="flex items-center gap-3.5 px-6 py-6">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-[var(--accent)]/10 ring-1 ring-[var(--accent)]/20">
            <svg className="w-6 h-6 text-[var(--accent-light)]" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          </div>
          <div>
            <div className="text-lg font-bold tracking-tight text-[var(--foreground)]">Scanner</div>
            <div className="text-sm text-[var(--muted)] tracking-wide">Bug Bounty</div>
          </div>
        </div>

        <nav className="flex flex-col gap-1.5 px-4 pt-2 flex-1">
          {NAV.map(({ href, label, icon }) => {
            const isActive = pathname === href || (href !== "/" && pathname.startsWith(href));
            return (
              <Link
                key={href}
                href={href}
                className={`flex items-center gap-3.5 rounded-xl px-4 py-3.5 text-base font-medium transition-all ${
                  isActive
                    ? "bg-[var(--accent)]/10 text-[var(--accent-light)] shadow-sm"
                    : "text-[var(--muted)] hover:bg-white/[0.03] hover:text-[var(--foreground)]"
                }`}
              >
                <svg className="w-[22px] h-[22px] shrink-0" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" d={icon} />
                </svg>
                {label}
              </Link>
            );
          })}
        </nav>

        {/* API Status */}
        {apis.length > 0 && (
          <div className="px-4 pb-2">
            <div className="rounded-xl border border-[var(--border)] bg-[var(--background)]/50 p-3">
              <div className="flex items-center justify-between mb-2.5">
                <span className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">APIs</span>
                {blockedCount > 0 && (
                  <span className="rounded-full bg-red-500/20 text-red-400 px-2 py-0.5 text-xs font-bold tabular-nums animate-pulse">
                    {blockedCount} blocked
                  </span>
                )}
              </div>
              <div className="space-y-1.5">
                {apis.map((api) => (
                  <div
                    key={api.name}
                    className={`flex items-center justify-between gap-2 rounded-lg px-2.5 py-1.5 text-sm ${
                      api.blocked
                        ? "bg-red-500/5 text-red-400"
                        : "text-[var(--muted)]"
                    }`}
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`h-2 w-2 rounded-full shrink-0 ${api.blocked ? "bg-red-500 animate-pulse" : "bg-emerald-500"}`} />
                      <span className="font-medium truncate">{api.name}</span>
                    </div>
                    {api.blocked && (
                      <span className="text-red-300 font-semibold tabular-nums shrink-0">{api.remaining_seconds}s</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        <div className="px-4 pb-5 pt-3">
          <button
            onClick={logout}
            className="flex w-full items-center gap-3.5 rounded-xl px-4 py-3.5 text-base font-medium text-[var(--muted)] hover:text-red-400 hover:bg-red-500/5 transition-all"
          >
            <svg className="w-[22px] h-[22px] shrink-0" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9" />
            </svg>
            Sair
          </button>
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto">
        <div className="min-h-full px-8 py-8 xl:px-10">
          {children}
        </div>
      </main>
    </div>
  );
}
