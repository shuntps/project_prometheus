"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { Button, ButtonLink } from "@/components/ui/button";
import { verifyEmail } from "../browser-api";
import { registrationContent } from "../content";
import { tokenFromFragment } from "../contract";
import { ResendForm } from "./resend-form";

const { verify: copy } = registrationContent;

type PanelState = "checking" | "verified" | "absent" | "refused" | "rate-limited" | "unavailable";

export function VerificationPanel() {
  const [state, setState] = useState<PanelState>("checking");
  const [heldUntil, setHeldUntil] = useState(0);
  /* On this side the token lives here alone: never in state, never in an
     attribute, never in the document, and in the address bar only until this
     component's first effect runs. It is then sent, in the request body. */
  const token = useRef<string | null>(null);
  const started = useRef(false);
  /* Read and written in the same task as the click, because a second one
     arriving before React re-renders would still see the old state. */
  const inFlight = useRef(false);

  const send = useCallback(async () => {
    const value = token.current;
    if (value === null || inFlight.current) {
      return;
    }
    inFlight.current = true;
    setState("checking");
    /* This component does not abort it: the token is single use, so cancelling
       here would leave the outcome unknown. Nothing keeps it alive if the
       document goes away. */
    const outcome = await verifyEmail(value);
    inFlight.current = false;
    if (outcome.status === "rate-limited") {
      setHeldUntil(Date.now() + outcome.retryAfterMs);
    }
    setState(outcome.status);
  }, []);

  useEffect(() => {
    /* One read and at most one send per page, whatever React does with this
       effect: a second run would find no fragment and refuse a valid link. */
    if (started.current) {
      return;
    }
    started.current = true;
    /* Read once, before the clearing below empties it. */
    const fragment = window.location.hash;
    token.current = tokenFromFragment(fragment);
    /* Cleared before the request leaves, and after hydration: this removes what
       the address bar still shows, not what the served document held — the
       fragment never reached the server that served it. */
    /* The entry's own state is handed back; null would discard the router's. */
    window.history.replaceState(window.history.state, "", window.location.pathname);
    if (token.current === null) {
      /* An empty fragment presented nothing, which is not a link that failed:
         a back navigation lands here once the address bar has been cleared. */
      setState(fragment === "" ? "absent" : "refused");
      return;
    }
    void send();
  }, [send]);

  /* The hold releases on its own; it never sends anything by itself. */
  useEffect(() => {
    if (heldUntil === 0) {
      return;
    }
    const timer = setTimeout(() => setHeldUntil(0), Math.max(0, heldUntil - Date.now()));
    return () => clearTimeout(timer);
  }, [heldUntil]);

  return (
    <div data-verification={state} aria-live="polite">
      {state === "checking" && <p className="text-on-surface-variant">{copy.checking}</p>}
      {state === "verified" && (
        <>
          <h2 className="font-display text-2xl text-on-surface">{copy.verified.heading}</h2>
          <p className="mt-4 text-on-surface-variant">{copy.verified.body}</p>
          <ButtonLink href="/sign-in" variant="primary" className="mt-8">
            {copy.verified.signIn}
          </ButtonLink>
        </>
      )}
      {(state === "absent" || state === "refused") && (
        <>
          <h2 className="font-display text-2xl text-on-surface">{copy[state].heading}</h2>
          <p className="mt-4 text-on-surface-variant">{copy[state].body}</p>
          <div className="mt-8 border-t border-outline pt-8">
            <ResendForm />
          </div>
          <ButtonLink href="/register" variant="primary" className="mt-8">
            {copy.register}
          </ButtonLink>
        </>
      )}
      {(state === "rate-limited" || state === "unavailable") && (
        <>
          <h2 className="font-display text-2xl text-on-surface">
            {state === "rate-limited" ? copy.limited.heading : copy.unavailable.heading}
          </h2>
          <p className="mt-4 text-on-surface-variant">
            {state === "rate-limited" ? copy.limited.body : copy.unavailable.body}
          </p>
          <Button className="mt-8" onClick={() => void send()} disabled={heldUntil > 0}>
            {copy.retry}
          </Button>
        </>
      )}
    </div>
  );
}
