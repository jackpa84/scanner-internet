import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import DesktopLayout from "@/components/DesktopLayout";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Scanner Bounty - Monitoramento e HackerOne",
  description: "Varredura Shodan, bug bounty, recon e envio de reports ao HackerOne",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="pt-BR" className="dark">
      <body className={`${inter.className} antialiased`}>
        <DesktopLayout>{children}</DesktopLayout>
      </body>
    </html>
  );
}
