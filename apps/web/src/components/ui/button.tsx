import Link from "next/link";
import type { ComponentProps, ReactNode } from "react";

const base =
  "inline-flex items-center justify-center gap-2 rounded-pill px-6 py-3 text-base font-medium " +
  "transition-colors ease-standard duration-(--motion-duration)";

const variants = {
  primary:
    "bg-primary text-on-primary hover:bg-tertiary hover:text-on-tertiary " +
    "disabled:bg-surface-high disabled:text-disabled disabled:cursor-not-allowed",
  outline:
    "border border-outline-strong text-on-surface hover:bg-surface-high " +
    "disabled:text-disabled disabled:cursor-not-allowed",
} as const;

export type ButtonVariant = keyof typeof variants;

/* A caller adds to the styling; it cannot replace what the variant guarantees. */
function classes(variant: ButtonVariant, extra: string | undefined): string {
  return extra ? `${base} ${variants[variant]} ${extra}` : `${base} ${variants[variant]}`;
}

export function Button({
  variant = "primary",
  className,
  type = "button",
  children,
  ...rest
}: { variant?: ButtonVariant; children: ReactNode } & ComponentProps<"button">) {
  /* Never "submit" by default: a button inside a form would post it silently. */
  return (
    <button className={classes(variant, className)} type={type} {...rest}>
      {children}
    </button>
  );
}

/* A link navigates and a button acts; the two are never swapped for styling. */
export function ButtonLink({
  variant = "outline",
  className,
  children,
  ...rest
}: { variant?: ButtonVariant; children: ReactNode } & ComponentProps<typeof Link>) {
  return (
    <Link className={classes(variant, className)} {...rest}>
      {children}
    </Link>
  );
}
