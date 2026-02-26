"use client";

import { Component, type ReactNode } from "react";
import BountyPanel from "@/components/BountyPanel";
import VulnPanel from "@/components/VulnPanel";

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

export default function Home() {
  return (
    <>
      <ErrorBoundary>
        <BountyPanel />
      </ErrorBoundary>

      <section className="mt-5 sm:mt-6">
        <ErrorBoundary>
          <VulnPanel />
        </ErrorBoundary>
      </section>
    </>
  );
}
