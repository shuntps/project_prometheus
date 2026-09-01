import { maxRetryAfterMs, retryAfterDelayMs } from "@/protocol/http/retry-after";

/*
  The API is the sole authority: it decides what an address and a password are
  worth, and this module only classifies the answer it gave. One admitted
  submission has exactly one shape here, whatever the address turned out to be.

  Registering and asking for another message are classified by one function
  because the service answers them through one and the same branch. What each
  screen then says about a refusal is its own copy, not its own classification.
*/
export type SubmissionOutcome =
  | { status: "accepted" }
  | { status: "invalid" }
  | { status: "too-large" }
  | { status: "rate-limited"; retryAfterMs: number }
  | { status: "blocked" }
  | { status: "unavailable" };

export function classifySubmission(
  httpStatus: number,
  retryAfterHeader: string | null,
): SubmissionOutcome {
  switch (httpStatus) {
    case 202:
      return { status: "accepted" };
    case 400:
      return { status: "invalid" };
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

/* A first consumption and a coherent second presentation both answer 204, so
   this side cannot tell them apart either, and does not try to. */
export type VerificationOutcome =
  | { status: "verified" }
  | { status: "refused" }
  | { status: "rate-limited"; retryAfterMs: number }
  | { status: "unavailable" };

export function classifyVerification(
  httpStatus: number,
  retryAfterHeader: string | null,
): VerificationOutcome {
  switch (httpStatus) {
    case 204:
      return { status: "verified" };
    case 400:
    case 403:
    case 413:
    case 415:
      return { status: "refused" };
    case 429:
      return {
        status: "rate-limited",
        retryAfterMs: retryAfterDelayMs(retryAfterHeader) ?? maxRetryAfterMs,
      };
    default:
      return { status: "unavailable" };
  }
}

/* The shape the API issues today: 32 bytes in unpadded base64url. A value of
   any other shape is refused here, so no request is spent on it. */
const issuedToken = /^[A-Za-z0-9_-]{43}$/;

/*
  The token travels in the fragment, which RFC 3986 section 3.5 separates before
  the reference is dereferenced. Exactly one parameter, named token, of the
  issued shape is accepted; an absent, repeated, accompanied or malformed one is
  refused without asking the server about it.
*/
export function tokenFromFragment(fragment: string): string | null {
  const raw = fragment.startsWith("#") ? fragment.slice(1) : fragment;
  if (raw === "") {
    return null;
  }
  const parameters = new URLSearchParams(raw);
  const names = [...parameters.keys()];
  if (names.length !== 1 || names[0] !== "token") {
    return null;
  }
  const token = parameters.get("token");
  return token !== null && issuedToken.test(token) ? token : null;
}
