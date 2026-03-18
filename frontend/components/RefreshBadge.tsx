"use client";

import { useEffect, useState } from "react";

interface RefreshBadgeProps {
  /** Intervalo de atualização em segundos */
  intervalSec: number;
  /** Timestamp (ms) do último fetch concluído. Use Date.now() ao setar. */
  lastUpdated: number;
  /** Label opcional exibido antes do countdown */
  label?: string;
  /** Se true, mostra estado "atualizando..." */
  isRefreshing?: boolean;
}

/**
 * Badge de countdown para refresh automático.
 * Mostra um ponto colorido + tempo restante até o próximo refresh.
 * Verde quando há tempo, âmbar quando está próximo / atualizando.
 */
export function RefreshBadge({ intervalSec, lastUpdated, label, isRefreshing = false }: RefreshBadgeProps) {
  const [countdown, setCountdown] = useState(intervalSec);

  useEffect(() => {
    if (lastUpdated === 0) {
      setCountdown(intervalSec);
      return;
    }
    const calc = () => {
      const elapsed = Math.floor((Date.now() - lastUpdated) / 1000);
      return Math.max(0, intervalSec - elapsed);
    };
    setCountdown(calc());
    const id = setInterval(() => setCountdown(calc()), 1000);
    return () => clearInterval(id);
  }, [lastUpdated, intervalSec]);

  const pct = intervalSec > 0 ? countdown / intervalSec : 0;

  const dotClass = isRefreshing || countdown === 0
    ? "bg-amber-400 animate-pulse"
    : pct > 0.4
    ? "bg-emerald-500/70"
    : "bg-amber-400/70 animate-pulse";

  return (
    <span className="inline-flex items-center gap-1 text-[9px] text-[var(--muted)] font-mono select-none">
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 transition-colors ${dotClass}`} />
      {label && <span className="opacity-60">{label}</span>}
      {isRefreshing || countdown === 0 ? (
        <span className="text-amber-400/80">atualizando…</span>
      ) : (
        <span>{countdown}s</span>
      )}
    </span>
  );
}
