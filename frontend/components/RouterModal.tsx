"use client";

import type { RouterInfo } from "@/lib/api";

const SERVICE_DESC: Record<string, string> = {
  http: "Servidor web sem criptografia. Pode expor painéis de administração, firmware ou credenciais padrão.",
  https: "Servidor web com TLS. Certificado pode revelar domínios internos e organização.",
  ssh: "Acesso remoto Secure Shell. Banner revela versão do OpenSSH e SO do host.",
  telnet: "Acesso remoto sem criptografia. Extremamente inseguro — senhas trafegam em texto puro.",
  ftp: "Transferência de arquivos. FTP anônimo ou credenciais fracas são vetores comuns de ataque.",
  smtp: "Servidor de e-mail. Pode ser usado para spam relay se mal configurado.",
  dns: "Servidor DNS. Resolvers abertos podem ser usados em ataques de amplificação DDoS.",
  rdp: "Remote Desktop Protocol. Alvo frequente de brute-force e ransomware.",
  mysql: "Banco de dados MySQL exposto. Acesso direto pode levar a vazamento de dados.",
  redis: "Cache Redis exposto. Frequentemente sem autenticação, permite execução remota de comandos.",
};

function getServiceHint(service: string): string {
  const key = service.toLowerCase().replace(/\d+/g, "").trim();
  return SERVICE_DESC[key] ?? "Serviço de rede detectado via probe ativo.";
}

export default function RouterModal({
  open,
  onClose,
  items,
  loading,
}: {
  open: boolean;
  onClose: () => void;
  items: RouterInfo[];
  loading: boolean;
}) {
  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Detalhes do roteador"
    >
      <div
        className="w-full max-w-2xl rounded-xl border border-border bg-card p-6 shadow-xl max-h-[80vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold">Serviços detectados</h3>
            <p className="text-xs text-muted mt-0.5">
              Banners e títulos coletados via probes HTTP(S), SSH e Telnet diretos ao host.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-muted hover:bg-border hover:text-foreground text-xl leading-none"
            aria-label="Fechar"
          >
            ×
          </button>
        </div>
        {loading ? (
          <p className="text-muted py-4">Carregando...</p>
        ) : items.length === 0 ? (
          <p className="text-muted py-4">Nenhuma informação adicional.</p>
        ) : (
          <div className="space-y-3">
            {items.map((item, idx) => (
              <div key={idx} className="rounded-lg border border-border bg-background/50 p-3">
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-accent font-semibold">:{item.port}</span>
                    <span className="text-xs font-semibold text-foreground uppercase">{item.service}</span>
                  </div>
                  {item.server && (
                    <span className="text-[10px] text-muted font-mono">{item.server}</span>
                  )}
                </div>
                <p className="text-[10px] text-muted mb-2">{getServiceHint(item.service)}</p>
                {(item.title || item.banner) && (
                  <div className="rounded bg-card px-2 py-1.5 text-xs font-mono text-foreground/80 break-all border border-border">
                    {item.title && <div><span className="text-muted">Title:</span> {item.title}</div>}
                    {item.banner && <div className="mt-0.5"><span className="text-muted">Banner:</span> {item.banner}</div>}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
