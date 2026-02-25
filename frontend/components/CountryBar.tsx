"use client";

import type { CountryStat } from "@/lib/api";

const BAR_COLORS = [
  "bg-sky-500", "bg-violet-500", "bg-emerald-500", "bg-amber-500", "bg-rose-500",
  "bg-cyan-500", "bg-pink-500", "bg-indigo-500", "bg-teal-500", "bg-orange-500",
];

export default function CountryBar({ countries }: { countries: CountryStat[] }) {
  if (!countries.length) return null;
  const max = countries[0].count;

  return (
    <div className="space-y-2">
      {countries.map((c, i) => {
        const pct = max > 0 ? (c.count / max) * 100 : 0;
        return (
          <div key={c.country} className="flex items-center gap-2">
            <span className="w-8 text-right text-xs font-semibold text-foreground">{c.country}</span>
            <div className="flex-1 h-5 rounded bg-background/50 overflow-hidden">
              <div
                className={`h-full rounded ${BAR_COLORS[i % BAR_COLORS.length]} transition-all duration-500`}
                style={{ width: `${Math.max(pct, 2)}%` }}
              />
            </div>
            <span className="w-8 text-xs text-muted tabular-nums">{c.count}</span>
          </div>
        );
      })}
    </div>
  );
}
