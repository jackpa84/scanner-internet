"use client";

import { useEffect, useRef, type ReactNode } from "react";

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  maxWidth?: string;
}

export default function Modal({
  open,
  onClose,
  title,
  children,
  maxWidth = "max-w-2xl",
}: ModalProps) {
  const overlayRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handler);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", handler);
      document.body.style.overflow = "";
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/60 backdrop-blur-sm sm:p-6"
      onClick={(e) => {
        if (e.target === overlayRef.current) onClose();
      }}
    >
      <div
        className={`relative w-full ${maxWidth} max-h-[90vh] sm:max-h-[85vh] rounded-t-2xl sm:rounded-2xl border border-[var(--border)] bg-[var(--card)] shadow-2xl flex flex-col`}
      >
        <div className="flex items-center justify-between border-b border-[var(--border)] px-3 sm:px-6 py-3 sm:py-4 shrink-0">
          <h2 className="text-lg sm:text-xl font-bold text-[var(--foreground)] truncate pr-2 sm:pr-4">
            {title}
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg bg-[var(--background)] hover:bg-[var(--border)] px-2 sm:px-4 py-1.5 sm:py-2 text-sm sm:text-base font-medium text-[var(--muted)] hover:text-[var(--foreground)] transition-all"
          >
            Fechar
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-3 sm:p-6">{children}</div>
      </div>
    </div>
  );
}
