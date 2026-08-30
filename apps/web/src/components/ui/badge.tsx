import type { ReactNode } from "react";

const base =
  "rounded-pill border border-outline-strong bg-surface-high px-3 py-1 text-sm text-on-surface-variant";

export function Badge({ className, children }: { className?: string; children: ReactNode }) {
  return <span className={className ? `${base} ${className}` : base}>{children}</span>;
}
