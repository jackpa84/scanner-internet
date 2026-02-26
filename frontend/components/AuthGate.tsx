"use client";

import { ReactNode } from "react";
import AuthProvider, { useAuth } from "./AuthProvider";
import LoginScreen from "./LoginScreen";
import DesktopLayout from "./DesktopLayout";

function Gate({ children }: { children: ReactNode }) {
  const { authenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950">
        <div className="animate-pulse text-slate-500 text-sm">Carregando...</div>
      </div>
    );
  }

  if (!authenticated) {
    return <LoginScreen />;
  }

  return <DesktopLayout>{children}</DesktopLayout>;
}

export default function AuthGate({ children }: { children: ReactNode }) {
  return (
    <AuthProvider>
      <Gate>{children}</Gate>
    </AuthProvider>
  );
}
