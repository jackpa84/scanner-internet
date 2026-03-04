import type { Metadata } from "next";
import "./globals.css";
import AuthGate from "@/components/AuthGate";

export const metadata: Metadata = {
  title: "Scanner Bounty - HackerOne",
  description: "Bug bounty recon, scan e envio de reports ao HackerOne",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="pt-BR" className="dark">
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `
              window.onerror = function(msg, src, line, col, err) {
                var d = document.getElementById('__global_err');
                if (!d) {
                  d = document.createElement('div');
                  d.id = '__global_err';
                  d.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:99999;background:#1a0000;color:#ff6b6b;padding:16px;font-family:monospace;font-size:13px;white-space:pre-wrap;max-height:50vh;overflow:auto;border-bottom:2px solid #ff4444';
                  document.body.prepend(d);
                }
                d.textContent += '[ERROR] ' + msg + '\\nSource: ' + (src||'?') + ':' + line + ':' + col + '\\n' + (err && err.stack ? err.stack : '') + '\\n\\n';
              };
              window.addEventListener('unhandledrejection', function(e) {
                var d = document.getElementById('__global_err');
                if (!d) {
                  d = document.createElement('div');
                  d.id = '__global_err';
                  d.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:99999;background:#1a0000;color:#ff6b6b;padding:16px;font-family:monospace;font-size:13px;white-space:pre-wrap;max-height:50vh;overflow:auto;border-bottom:2px solid #ff4444';
                  document.body.prepend(d);
                }
                d.textContent += '[PROMISE] ' + (e.reason && e.reason.stack ? e.reason.stack : e.reason) + '\\n\\n';
              });
            `,
          }}
        />
      </head>
      <body className="font-sans antialiased">
        <AuthGate>{children}</AuthGate>
      </body>
    </html>
  );
}
