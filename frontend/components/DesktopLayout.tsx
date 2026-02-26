"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "./AuthProvider";

const NAV = [
  { href: "/", label: "Programas", icon: "M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" },
];

export default function DesktopLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { logout } = useAuth();

  return (
    <div className="min-h-screen bg-[var(--background)] text-[var(--foreground)] flex flex-col">
      {/* Top header */}
      <header className="border-b border-[var(--border)] bg-[var(--card)]/95 backdrop-blur sticky top-0 z-40">
        <div className="mx-auto flex max-w-[1400px] items-center justify-between px-4 py-2.5 sm:py-3">
          <div className="flex items-center gap-2">
            <div className="flex h-7 w-7 sm:h-8 sm:w-8 items-center justify-center rounded-lg bg-[var(--accent)]/15 ring-1 ring-[var(--accent)]/30">
              <span className="text-xs sm:text-sm font-bold tracking-tight text-[var(--accent)]">S</span>
            </div>
            <div className="flex flex-col">
              <span className="text-sm font-semibold leading-tight tracking-tight">Scanner Bounty</span>
              <span className="text-[10px] text-[var(--muted)] leading-tight hidden sm:block">
                Recon · Bug bounty · HackerOne
              </span>
            </div>
          </div>

          {/* Desktop nav */}
          <nav className="hidden sm:flex items-center gap-2 text-sm">
            {NAV.map(({ href, label }) => {
              const isActive = pathname === href || (href !== "/" && pathname.startsWith(href));
              return (
                <Link
                  key={href}
                  href={href}
                  className={`rounded-full px-3 py-1.5 transition text-sm ${
                    isActive
                      ? "bg-[var(--accent)]/20 text-[var(--accent)] font-medium ring-1 ring-[var(--accent)]/40"
                      : "bg-[var(--background)]/60 text-[var(--foreground)]/80 hover:bg-[var(--border)]/40 hover:text-[var(--foreground)]"
                  }`}
                >
                  {label}
                </Link>
              );
            })}
            <button
              onClick={logout}
              className="rounded-full px-3 py-1.5 text-sm text-slate-400 hover:text-red-400 hover:bg-red-500/10 transition ml-1"
              title="Sair"
            >
              Sair
            </button>
          </nav>
        </div>
      </header>

      <main className="flex-1">
        <div className="mx-auto min-h-[calc(100vh-4rem)] max-w-[1400px] px-3 py-4 sm:px-6 sm:py-8">
          {children}
        </div>
      </main>

      {/* Mobile bottom nav */}
      <nav className="sm:hidden fixed bottom-0 inset-x-0 z-50 border-t border-[var(--border)] bg-[var(--card)]/95 backdrop-blur-lg">
        <div className="flex items-stretch">
          {NAV.map(({ href, label, icon }) => {
            const isActive = pathname === href || (href !== "/" && pathname.startsWith(href));
            return (
              <Link
                key={href}
                href={href}
                className={`flex-1 flex flex-col items-center justify-center gap-0.5 py-2 transition-colors ${
                  isActive
                    ? "text-[var(--accent)]"
                    : "text-[var(--muted)] active:text-[var(--foreground)]"
                }`}
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" d={icon} />
                </svg>
                <span className="text-[10px] font-medium">{label}</span>
              </Link>
            );
          })}
        </div>
      </nav>
    </div>
  );
}
