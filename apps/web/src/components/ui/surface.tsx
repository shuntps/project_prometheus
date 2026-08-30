import type { ReactNode } from "react";

const tones = {
  surface: "bg-surface",
  high: "bg-surface-high",
  highest: "bg-surface-highest",
} as const;

export type SurfaceTone = keyof typeof tones;

const base = "rounded-card border border-outline";

/* Depth comes from the tonal step, not from a drop shadow. */
export function Surface({
  tone = "surface",
  className,
  children,
}: {
  tone?: SurfaceTone;
  className?: string;
  children: ReactNode;
}) {
  const resolved = `${base} ${tones[tone]}`;
  return <div className={className ? `${resolved} ${className}` : resolved}>{children}</div>;
}
