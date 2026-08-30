import type { ReactNode } from "react";

const base = "mx-auto w-full max-w-6xl px-5 sm:px-8";

export function Container({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={className ? `${base} ${className}` : base}>{children}</div>;
}
