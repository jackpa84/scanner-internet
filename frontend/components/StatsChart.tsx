"use client";

import { useEffect, useRef } from "react";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from "chart.js";
import type { Stats } from "@/lib/api";

ChartJS.register(ArcElement, Tooltip, Legend);

const COLORS = ["#38bdf8", "#f472b6", "#a78bfa", "#34d399", "#f87171", "#fbbf24"];
const BORDERS = "#1e293b";

export default function StatsChart({ stats }: { stats: Stats }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const chartRef = useRef<ChartJS | null>(null);

  useEffect(() => {
    if (!canvasRef.current || !stats) return;

    if (chartRef.current) chartRef.current.destroy();

    const ctx = canvasRef.current.getContext("2d");
    if (!ctx) return;

    const labels = ["Com portas", "Com vulns", "Router info", "Alto risco", "Com geo"];
    const data = [
      stats.with_ports ?? 0,
      stats.with_vulns ?? 0,
      stats.with_router_info ?? 0,
      stats.with_high_risk ?? 0,
      stats.with_geo ?? 0,
    ];

    chartRef.current = new ChartJS(ctx, {
      type: "doughnut",
      data: {
        labels,
        datasets: [
          {
            data,
            backgroundColor: COLORS,
            borderColor: BORDERS,
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: "#94a3b8", font: { size: 11 } },
          },
        },
      },
    });

    return () => {
      if (chartRef.current) chartRef.current.destroy();
    };
  }, [stats]);

  return (
    <div className="h-56 w-full max-w-sm">
      <canvas ref={canvasRef} />
    </div>
  );
}
