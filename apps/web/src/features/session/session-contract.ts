import { maxRetryAfterMs, retryAfterDelayMs } from "@/protocol/http/retry-after";

/*
  The API is the sole authority. This module only decodes what it answered and
  classifies the outcome; it decides nothing about the caller.
*/
export type SessionView = {
  csrfToken: string;
  accountId: string;
  kind: string;
  surface: string;
  roles: readonly string[];
  expiresAt: Date;
};

export type SessionState =
  | { status: "loading" }
  | { status: "anonymous" }
  | { status: "authenticated"; session: SessionView }
  | { status: "rate-limited"; retryAfterMs: number }
  | { status: "unavailable" };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringField(source: Record<string, unknown>, name: string): string | null {
  const value = source[name];
  return typeof value === "string" && value.length > 0 ? value : null;
}

/* Unknown roles are carried through: this surface interprets none of them. */
function roleList(value: unknown): readonly string[] | null {
  if (!Array.isArray(value)) {
    return null;
  }
  return value.every((role) => typeof role === "string") ? (value as string[]) : null;
}

/* Structural validation only. Extra fields are accepted and ignored. */
export function decodeSessionView(payload: unknown): SessionView | null {
  if (!isRecord(payload)) {
    return null;
  }
  const csrfToken = stringField(payload, "csrf_token");
  const accountId = stringField(payload, "account_id");
  const kind = stringField(payload, "kind");
  const surface = stringField(payload, "surface");
  const roles = roleList(payload.roles);
  const rawExpiry = payload.expires_at;
  if (!csrfToken || !accountId || !kind || !surface || !roles || typeof rawExpiry !== "string") {
    return null;
  }
  const expiresAt = new Date(rawExpiry);
  if (Number.isNaN(expiresAt.getTime())) {
    return null;
  }
  return { csrfToken, accountId, kind, surface, roles, expiresAt };
}

export type SignInOutcome =
  | { status: "created"; session: SessionView }
  | { status: "invalid" }
  | { status: "rejected" }
  | { status: "too-large" }
  | { status: "rate-limited"; retryAfterMs: number }
  | { status: "blocked" }
  | { status: "unavailable" };

export function classifySignIn(
  httpStatus: number,
  payload: unknown,
  retryAfterHeader: string | null,
): SignInOutcome {
  switch (httpStatus) {
    case 201: {
      const session = decodeSessionView(payload);
      return session ? { status: "created", session } : { status: "unavailable" };
    }
    case 400:
      return { status: "invalid" };
    case 401:
      return { status: "rejected" };
    case 413:
      return { status: "too-large" };
    case 429:
      return {
        status: "rate-limited",
        retryAfterMs: retryAfterDelayMs(retryAfterHeader) ?? maxRetryAfterMs,
      };
    case 403:
    case 415:
      return { status: "blocked" };
    default:
      return { status: "unavailable" };
  }
}

/*
  A 403 here is a contract or security mismatch, not a state a person can be in:
  reading a live session is authenticated, never permissioned.
*/
export function classifyResolution(
  httpStatus: number,
  payload: unknown,
  retryAfterHeader: string | null,
): SessionState {
  switch (httpStatus) {
    case 200: {
      const session = decodeSessionView(payload);
      return session ? { status: "authenticated", session } : { status: "unavailable" };
    }
    case 401:
      return { status: "anonymous" };
    case 429:
      return {
        status: "rate-limited",
        retryAfterMs: retryAfterDelayMs(retryAfterHeader) ?? maxRetryAfterMs,
      };
    default:
      return { status: "unavailable" };
  }
}
