"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV = [
  { href: "/", label: "Monitoramento", desc: "Varredura Shodan, IPs, vulns" },
  { href: "/programas", label: "Programas", desc: "Bug bounty, recon, HackerOne" },
];

export default function DesktopLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <div className="min-h-screen bg-[var(--background)] text-[var(--foreground)] flex flex-col">
      <header className="border-b border-[var(--border)] bg-[var(--card)]/95 backdrop-blur">
        <div className="mx-auto flex max-w-[1400px] flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--accent)]/15 ring-1 ring-[var(--accent)]/30">
              <span className="text-sm font-bold tracking-tight text-[var(--accent)]">S</span>
            </div>
            <div className="flex flex-col">
              <span className="text-sm font-semibold leading-tight tracking-tight">Scanner Bounty</span>
              <span className="text-[10px] text-[var(--muted)] leading-tight">
                Recon · Bug bounty · HackerOne
              </span>
            </div>
          </div>
          <nav className="flex flex-wrap gap-2 text-sm">
            {NAV.map(({ href, label, desc }) => {
              const isActive = pathname === href || (href !== "/" && pathname.startsWith(href));
              return (
                <Link
                  key={href}
                  href={href}
                  className={`rounded-full px-3 py-1.5 transition text-xs sm:text-sm ${
                    isActive
                      ? "bg-[var(--accent)]/20 text-[var(--accent)] font-medium ring-1 ring-[var(--accent)]/40"
                      : "bg-[var(--background)]/60 text-[var(--foreground)]/80 hover:bg-[var(--border)]/40 hover:text-[var(--foreground)]"
                  }`}
                  title={desc}
                >
                  {label}
                </Link>
              );
            })}
          </nav>
        </div>
      </header>

      <main className="flex-1">
        <div className="mx-auto min-h-[calc(100vh-4rem)] max-w-[1400px] px-4 py-6 sm:px-6 sm:py-8">
          {children}
        </div>
      </main>
    </div>
  );
}

