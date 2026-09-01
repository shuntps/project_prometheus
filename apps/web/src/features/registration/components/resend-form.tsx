"use client";

import { useCallback, useEffect, useId, useRef, useState, type SubmitEvent } from "react";

import { Button } from "@/components/ui/button";
import { resendVerification } from "../browser-api";
import { registrationContent } from "../content";
import { field } from "./field";

const { resend: copy } = registrationContent;

const messages: Record<string, string> = {
  invalid: copy.errors.invalid,
  "too-large": copy.errors.tooLarge,
  "rate-limited": copy.errors.limited,
  blocked: copy.errors.blocked,
  unavailable: copy.errors.unavailable,
};

/*
  Asking for another message, from wherever a person needs it. It carries the
  address alone, and every address leaves by the same door.
*/
export function ResendForm() {
  const emailId = useId();
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

  const submit = useCallback(async (email: string) => {
    const controller = new AbortController();
    pending.current = controller;
    setSubmitting(true);
    setError(null);

    const outcome = await resendVerification(email, controller.signal);
    inFlight.current = false;
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
    inFlight.current = true;
    const form = new FormData(event.currentTarget);
    void submit(String(form.get("email") ?? ""));
  }

  if (accepted) {
    return (
      <div role="status" data-resend="accepted">
        <h3 className="font-display text-xl text-on-surface">{copy.accepted.heading}</h3>
        <p className="mt-4 text-on-surface-variant">{copy.accepted.body}</p>
      </div>
    );
  }

  return (
    <form onSubmit={onSubmit} noValidate data-resend="asking">
      <h3 className="font-display text-xl text-on-surface">{copy.heading}</h3>
      <p className="mt-2 text-sm text-on-surface-variant">{copy.body}</p>
      <div className="mt-4">
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
      {error !== null && (
        <p role="alert" className="mt-4 text-error-text">
          {error}
        </p>
      )}
      <Button type="submit" variant="outline" className="mt-6 w-full" disabled={blocked}>
        {submitting ? copy.submitting : copy.submit}
      </Button>
    </form>
  );
}
