import "client-only";

import { retryAfterDelayMs } from "@/protocol/http/retry-after";
import {
  classifyResolution,
  classifySignIn,
  type SessionState,
  type SignInOutcome,
} from "./session-contract";

/*
  Relative, same-origin paths only: the browser sees one origin and the cookie
  travels on its own. Nothing here reads, writes or decodes it.
*/
const sessionPath = "/api/v1/auth/session";
const activityPath = "/api/v1/auth/session/activity";

const jsonHeaders = { "Content-Type": "application/json" } as const;

async function payloadOf(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

export async function resolveSession(signal?: AbortSignal): Promise<SessionState> {
  let response: Response;
  try {
    response = await fetch(sessionPath, {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
      ...(signal ? { signal } : {}),
    });
  } catch {
    return { status: "unavailable" };
  }
  return classifyResolution(
    response.status,
    await payloadOf(response),
    response.headers.get("Retry-After"),
  );
}

export async function signIn(
  email: string,
  password: string,
  signal?: AbortSignal,
): Promise<SignInOutcome> {
  let response: Response;
  try {
    response = await fetch(sessionPath, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: jsonHeaders,
      body: JSON.stringify({ email, password }),
      ...(signal ? { signal } : {}),
    });
  } catch {
    return { status: "unavailable" };
  }
  return classifySignIn(
    response.status,
    await payloadOf(response),
    response.headers.get("Retry-After"),
  );
}

export type SignOutOutcome = "ended" | "already-anonymous" | "failed";

/* This client does not intentionally abort sign-out when its caller unmounts. */
export async function signOut(csrfToken: string): Promise<SignOutOutcome> {
  let response: Response;
  try {
    response = await fetch(sessionPath, {
      method: "DELETE",
      credentials: "same-origin",
      cache: "no-store",
      headers: { ...jsonHeaders, "X-CSRF-Token": csrfToken },
      body: "{}",
    });
  } catch {
    return "failed";
  }
  if (response.status === 204) {
    return "ended";
  }
  return response.status === 401 ? "already-anonymous" : "failed";
}

export type ActivityReport = {
  outcome: "accepted" | "unauthenticated" | "forbidden" | "limited" | "failed";
  retryAfterMs: number | null;
};

export async function reportActivity(
  csrfToken: string,
  signal?: AbortSignal,
): Promise<ActivityReport> {
  let response: Response;
  try {
    response = await fetch(activityPath, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { ...jsonHeaders, "X-CSRF-Token": csrfToken },
      body: "{}",
      ...(signal ? { signal } : {}),
    });
  } catch {
    return { outcome: "failed", retryAfterMs: null };
  }
  switch (response.status) {
    case 204:
      return { outcome: "accepted", retryAfterMs: null };
    case 401:
      return { outcome: "unauthenticated", retryAfterMs: null };
    case 403:
      return { outcome: "forbidden", retryAfterMs: null };
    case 429:
      return {
        outcome: "limited",
        retryAfterMs: retryAfterDelayMs(response.headers.get("Retry-After")),
      };
    default:
      return { outcome: "failed", retryAfterMs: null };
  }
}
