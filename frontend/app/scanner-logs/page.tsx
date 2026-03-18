"use client";

import { useEffect, useRef, useState } from "react";
import DesktopLayout from "@/components/DesktopLayout";

export default function ScannerLogsPage() {
  const [logs, setLogs] = useState<string[]>([]);
  const [connected, setConnected] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || "";
    const wsUrl = apiUrl.replace(/^https?/, "ws") + "/api/ws/logs";

    const connect = () => {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        setTimeout(connect, 3000);
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (e) => {
        setLogs((prev) => [...prev.slice(-500), e.data]);
      };
    };

    connect();
    return () => wsRef.current?.close();
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  return (
    <DesktopLayout>
      <div className="p-4 space-y-3">
        <div className="flex items-center gap-2">
          <h1 className="text-sm font-semibold uppercase tracking-wider text-[var(--foreground)]">
            Scanner Logs
          </h1>
          <span
            className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
              connected
                ? "bg-green-500/20 text-green-400"
                : "bg-red-500/20 text-red-400"
            }`}
          >
            {connected ? "LIVE" : "DISCONNECTED"}
          </span>
          <button
            onClick={() => setLogs([])}
            className="ml-auto text-[10px] text-[var(--muted)] hover:text-[var(--foreground)] transition-colors"
          >
            Limpar
          </button>
        </div>

        <div
          className="bg-[var(--card)] border border-[var(--border)] rounded-lg p-3 font-mono text-[11px] h-[calc(100vh-120px)] overflow-y-auto"
          style={{ scrollbarWidth: "thin" }}
        >
          {logs.length === 0 ? (
            <p className="text-[var(--muted)]">Aguardando logs...</p>
          ) : (
            logs.map((log, i) => (
              <div key={i} className="text-[var(--foreground)] opacity-80 leading-5 whitespace-pre-wrap break-all">
                {log}
              </div>
            ))
          )}
          <div ref={bottomRef} />
        </div>
      </div>
    </DesktopLayout>
  );
}
