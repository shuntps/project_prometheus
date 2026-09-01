"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useId, useRef, useState, type SubmitEvent } from "react";

import { Button } from "@/components/ui/button";
import { signIn } from "../browser-api";
import { sessionContent } from "../content";

const { signIn: copy } = sessionContent;

const messages: Record<string, string> = {
  invalid: copy.errors.invalid,
  rejected: copy.errors.rejected,
  "too-large": copy.errors.tooLarge,
  "rate-limited": copy.errors.limited,
  blocked: copy.errors.blocked,
  unavailable: copy.errors.unavailable,
};

const field =
  "mt-2 w-full rounded-card border border-outline bg-surface px-4 py-3 text-on-surface " +
  "transition-colors ease-standard duration-(--motion-duration) hover:border-outline-strong " +
  "disabled:cursor-not-allowed disabled:text-disabled";

export function SignInForm() {
  const router = useRouter();
  const emailId = useId();
  const passwordId = useId();
  const [submitting, setSubmitting] = useState(false);
  const [heldUntil, setHeldUntil] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const pending = useRef<AbortController | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      pending.current?.abort();
    };
  }, []);

  /* The hold releases on its own; it never submits anything by itself. */
  useEffect(() => {
    if (heldUntil === 0) {
      return;
    }
    const timer = setTimeout(() => setHeldUntil(0), Math.max(0, heldUntil - Date.now()));
    return () => clearTimeout(timer);
  }, [heldUntil]);

  const held = heldUntil > 0;
  const blocked = submitting || held;

  const submit = useCallback(
    async (email: string, password: string) => {
      const controller = new AbortController();
      pending.current?.abort();
      pending.current = controller;
      setSubmitting(true);
      setError(null);

      const outcome = await signIn(email, password, controller.signal);
      /* A reply that outlived the form decides nothing and navigates nowhere. */
      if (!mounted.current || controller.signal.aborted) {
        return;
      }
      if (outcome.status === "created") {
        /* Replace, so the browser's Back does not return to this form. */
        router.replace("/");
        return;
      }
      setSubmitting(false);
      if (outcome.status === "rate-limited") {
        setHeldUntil(Date.now() + outcome.retryAfterMs);
      }
      setError(messages[outcome.status] ?? copy.errors.unavailable);
    },
    [router],
  );

  function onSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (blocked) {
      return;
    }
    const form = new FormData(event.currentTarget);
    void submit(String(form.get("email") ?? ""), String(form.get("password") ?? ""));
  }

  return (
    <form onSubmit={onSubmit} noValidate>
      <div>
        <label htmlFor={emailId} className="text-sm text-on-surface-variant">
          {copy.email}
        </label>
        <input
          id={emailId}
          name="email"
          type="email"
          autoComplete="email"
          required
          disabled={blocked}
          className={field}
        />
      </div>
      <div className="mt-6">
        <label htmlFor={passwordId} className="text-sm text-on-surface-variant">
          {copy.password}
        </label>
        <input
          id={passwordId}
          name="password"
          type="password"
          autoComplete="current-password"
          required
          disabled={blocked}
          className={field}
        />
      </div>
      {error !== null && (
        <p role="alert" className="mt-6 text-error-text">
          {error}
        </p>
      )}
      <Button type="submit" className="mt-8 w-full" disabled={blocked}>
        {submitting ? copy.submitting : copy.submit}
      </Button>
    </form>
  );
}
