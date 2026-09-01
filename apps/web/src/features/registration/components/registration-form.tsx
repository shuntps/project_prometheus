"use client";

import { useCallback, useEffect, useId, useRef, useState, type SubmitEvent } from "react";

import { Button } from "@/components/ui/button";
import { registerAccount } from "../browser-api";
import { registrationContent } from "../content";
import { field } from "./field";
import { ResendForm } from "./resend-form";

const { register: copy } = registrationContent;

const messages: Record<string, string> = {
  invalid: copy.errors.invalid,
  "too-large": copy.errors.tooLarge,
  "rate-limited": copy.errors.limited,
  blocked: copy.errors.blocked,
  unavailable: copy.errors.unavailable,
};

export function RegistrationForm() {
  const emailId = useId();
  const passwordId = useId();
  const passwordHintId = useId();
  const confirmationId = useId();
  const confirmationHintId = useId();
  const [submitting, setSubmitting] = useState(false);
  const [accepted, setAccepted] = useState(false);
  const [heldUntil, setHeldUntil] = useState(0);
  const [error, setError] = useState<string | null>(null);
  /* Read and written in the same task as the submission, because a second one
     arriving before React re-renders would still see the old state. */
  const inFlight = useRef(false);
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

  const submit = useCallback(async (email: string, password: string) => {
    const controller = new AbortController();
    pending.current = controller;
    setSubmitting(true);
    setError(null);

    const outcome = await registerAccount(email, password, controller.signal);
    inFlight.current = false;
    /* A reply that outlived the form decides nothing. */
    if (!mounted.current || controller.signal.aborted) {
      return;
    }
    setSubmitting(false);
    if (outcome.status === "accepted") {
      setAccepted(true);
      return;
    }
    if (outcome.status === "rate-limited") {
      setHeldUntil(Date.now() + outcome.retryAfterMs);
    }
    setError(messages[outcome.status] ?? copy.errors.unavailable);
  }, []);

  function onSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (inFlight.current || blocked) {
      return;
    }
    const form = new FormData(event.currentTarget);
    /* Compared byte for byte, here alone: the confirmation never leaves. */
    const password = String(form.get("password") ?? "");
    if (password !== String(form.get("confirmation") ?? "")) {
      setError(copy.errors.mismatch);
      return;
    }
    inFlight.current = true;
    void submit(String(form.get("email") ?? ""), password);
  }

  if (accepted) {
    return (
      <>
        <div role="status">
          <h2 className="font-display text-2xl text-on-surface">{copy.accepted.heading}</h2>
          <p className="mt-4 text-on-surface-variant">{copy.accepted.body}</p>
        </div>
        {/* Nothing is carried over from the form: the address is asked again, so
            this panel stays the same one for every address. */}
        <div className="mt-8 border-t border-outline pt-8">
          <ResendForm />
        </div>
      </>
    );
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
          autoComplete="new-password"
          required
          disabled={blocked}
          aria-describedby={passwordHintId}
          className={field}
        />
        <p id={passwordHintId} className="mt-2 text-sm text-on-surface-variant">
          {copy.passwordHint}
        </p>
      </div>
      <div className="mt-6">
        <label htmlFor={confirmationId} className="text-sm text-on-surface-variant">
          {copy.confirmation}
        </label>
        <input
          id={confirmationId}
          name="confirmation"
          type="password"
          autoComplete="new-password"
          required
          disabled={blocked}
          aria-describedby={confirmationHintId}
          className={field}
        />
        <p id={confirmationHintId} className="mt-2 text-sm text-on-surface-variant">
          {copy.confirmationHint}
        </p>
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
