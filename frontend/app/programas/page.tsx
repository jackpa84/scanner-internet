"use client";

import { Component, type ReactNode } from "react";
import BountyPanel from "@/components/BountyPanel";

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

function SectionHeader({ title, desc }: { title: string; desc: string }) {
  return (
    <div className="mb-4">
      <h2 className="text-sm font-semibold text-[var(--foreground)] uppercase tracking-wider">{title}</h2>
      <p className="text-[11px] text-[var(--muted)] mt-0.5">{desc}</p>
    </div>
  );
}

export default function ProgramasPage() {
  return (
    <>
      <header className="mb-8">
        <h1 className="text-2xl font-bold tracking-tight text-[var(--foreground)] md:text-3xl">
          Programas
        </h1>
        <p className="mt-1 text-sm text-[var(--muted)] max-w-2xl">
          Gestão de programas de bug bounty, escopo autorizado, recon automatizado e envio de reports ao HackerOne.
        </p>
      </header>

      <section>
        <SectionHeader
          title="Bug Bounty"
          desc="Programas (HackerOne, Bugcrowd), escopo, recon (subfinder + DNS + httpx), scans Nuclei/Nmap e envio direto ao HackerOne."
        />
        <ErrorBoundary>
          <BountyPanel />
        </ErrorBoundary>
      </section>
    </>
  );
}

