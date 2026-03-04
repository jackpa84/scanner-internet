"use client";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div style={{
      minHeight: "100vh",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      background: "#05080f",
      color: "#e2e8f0",
      fontFamily: "system-ui, sans-serif",
      padding: "2rem",
    }}>
      <div style={{
        maxWidth: 600,
        width: "100%",
        background: "#0a1120",
        border: "1px solid #1e2d45",
        borderRadius: 16,
        padding: "2rem",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
          <span style={{ fontSize: 32 }}>⚠️</span>
          <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>Erro no Dashboard</h1>
        </div>

        <div style={{
          background: "#1a0000",
          border: "1px solid #ff444440",
          borderRadius: 8,
          padding: 16,
          marginBottom: 16,
          fontFamily: "monospace",
          fontSize: 13,
          color: "#ff6b6b",
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
          maxHeight: 300,
          overflow: "auto",
        }}>
          {error.message}
          {error.stack && (
            <>
              {"\n\n"}
              <span style={{ color: "#ff6b6b80" }}>{error.stack}</span>
            </>
          )}
        </div>

        <div style={{ display: "flex", gap: 12 }}>
          <button
            onClick={reset}
            style={{
              background: "#6366f1",
              color: "white",
              border: "none",
              borderRadius: 8,
              padding: "10px 20px",
              fontSize: 14,
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            Tentar novamente
          </button>
          <button
            onClick={() => window.location.reload()}
            style={{
              background: "#1e2d45",
              color: "#e2e8f0",
              border: "1px solid #2d3f5c",
              borderRadius: 8,
              padding: "10px 20px",
              fontSize: 14,
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            Recarregar página
          </button>
        </div>

        <p style={{ fontSize: 12, color: "#5a6a80", marginTop: 16 }}>
          Se o problema persistir, verifique o console do navegador (F12) e os logs do backend.
        </p>
      </div>
    </div>
  );
}
