"use client";

import { ReactNode } from "react";
import AuthProvider from "./AuthProvider";
import DesktopLayout from "./DesktopLayout";

export default function AuthGate({ children }: { children: ReactNode }) {
  return (
    <AuthProvider>
      <DesktopLayout>{children}</DesktopLayout>
    </AuthProvider>
  );
}
