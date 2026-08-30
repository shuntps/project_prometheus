"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { Button, ButtonLink } from "@/components/ui/button";
import { ActivityCadence } from "../activity";
import { reportActivity, resolveSession, signOut } from "../browser-api";
import { sessionContent } from "../content";
import type { SessionState } from "../session-contract";

const gestures = ["pointerdown", "keydown", "submit"] as const;

function foreground(): boolean {
  return document.visibilityState === "visible" && document.hasFocus();
}

/*
  One coherent client boundary: it resolves the session, holds the CSRF token in
  memory alone, ends the session and owns the activity reporter's lifetime.
*/
export function SessionControls() {
  const [state, setState] = useState<SessionState>({ status: "loading" });
  const [ending, setEnding] = useState(false);
  const [heldUntil, setHeldUntil] = useState(0);
  const resolving = useRef<AbortController | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      resolving.current?.abort();
    };
  }, []);

  /* Last resolution wins: the previous one is aborted and can no longer decide. */
  const resolve = useCallback(() => {
    resolving.current?.abort();
    const controller = new AbortController();
    resolving.current = controller;
    resolveSession(controller.signal).then(
      (next) => {
        if (!controller.signal.aborted && mounted.current) {
          setState(next);
          setHeldUntil(next.status === "rate-limited" ? Date.now() + next.retryAfterMs : 0);
        }
      },
      () => {
        if (!controller.signal.aborted && mounted.current) {
          setState({ status: "unavailable" });
        }
      },
    );
  }, []);

  useEffect(() => {
    resolve();
  }, [resolve]);

  /* A hold ends on its own, but never launches a request by itself. */
  useEffect(() => {
    if (heldUntil === 0) {
      return;
    }
    const timer = setTimeout(() => setHeldUntil(0), Math.max(0, heldUntil - Date.now()));
    return () => clearTimeout(timer);
  }, [heldUntil]);

  const csrfToken = state.status === "authenticated" ? state.session.csrfToken : null;

  useEffect(() => {
    if (csrfToken === null) {
      return;
    }
    const cadence = new ActivityCadence();
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | null = null;
    let stopped = false;

    const clearTimer = () => {
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
    };

    /* One shot for the exact instant a received gesture becomes admissible. */
    const arm = () => {
      clearTimer();
      const due = cadence.pendingDueAt();
      if (stopped || due === null) {
        return;
      }
      timer = setTimeout(
        () => {
          timer = null;
          if (stopped) {
            return;
          }
          /* Re-checked here, not when the gesture happened. Out of the foreground
             the waiting gesture is dropped: re-arming on a deadline already past
             would spin a chain of zero-delay timers. */
          if (!foreground()) {
            return;
          }
          if (cadence.dueAt(Date.now()) === "send") {
            void send();
          }
        },
        Math.max(0, due - Date.now()),
      );
    };

    const send = async () => {
      const report = await reportActivity(csrfToken, controller.signal);
      if (stopped) {
        return;
      }
      cadence.settle(report.outcome, Date.now(), report.retryAfterMs);
      if (report.outcome === "unauthenticated") {
        stopped = true;
        setState({ status: "anonymous" });
        return;
      }
      if (report.outcome === "forbidden") {
        /* Renewing is a capability; reading the session is not. Resolve again. */
        stopped = true;
        resolve();
        return;
      }
      /* A gesture received during the flight is re-armed for its own instant. */
      arm();
    };

    const onGesture = () => {
      if (stopped || !foreground()) {
        return;
      }
      if (cadence.interaction(Date.now()) === "send") {
        void send();
        return;
      }
      arm();
    };

    for (const name of gestures) {
      document.addEventListener(name, onGesture, { passive: true });
    }
    return () => {
      stopped = true;
      clearTimer();
      controller.abort();
      for (const name of gestures) {
        document.removeEventListener(name, onGesture);
      }
    };
  }, [csrfToken, resolve]);

  const end = useCallback(async () => {
    if (csrfToken === null) {
      return;
    }
    setEnding(true);
    /* Not aborted by this component; a late result is ignored by the UI. */
    const outcome = await signOut(csrfToken);
    if (!mounted.current) {
      return;
    }
    setEnding(false);
    setState(outcome === "failed" ? { status: "unavailable" } : { status: "anonymous" });
  }, [csrfToken]);

  const held = heldUntil > 0;

  /* One fixed box in every state, so resolving never moves the navigation. */
  return (
    <div
      className="flex h-11 w-52 shrink-0 items-center justify-end gap-3 overflow-hidden sm:w-64"
      data-session={state.status}
    >
      {state.status === "loading" && (
        <span className="truncate text-sm text-on-surface-variant" aria-live="polite">
          {sessionContent.header.loading}
        </span>
      )}
      {state.status === "anonymous" && (
        <ButtonLink href="/sign-in" className="px-4 py-2 text-sm">
          {sessionContent.header.signIn}
        </ButtonLink>
      )}
      {state.status === "authenticated" && (
        <>
          <span className="truncate text-sm text-on-surface-variant">
            {sessionContent.header.signedIn}
          </span>
          <Button
            variant="outline"
            className="shrink-0 px-4 py-2 text-sm"
            onClick={() => void end()}
            disabled={ending}
          >
            {sessionContent.header.signOut}
          </Button>
        </>
      )}
      {(state.status === "rate-limited" || state.status === "unavailable") && (
        <>
          <span className="truncate text-sm text-on-surface-variant" role="status">
            {state.status === "rate-limited"
              ? sessionContent.header.limited
              : sessionContent.header.unavailable}
          </span>
          <Button
            variant="outline"
            className="shrink-0 px-4 py-2 text-sm"
            onClick={resolve}
            disabled={held}
          >
            {sessionContent.header.retry}
          </Button>
        </>
      )}
    </div>
  );
}
