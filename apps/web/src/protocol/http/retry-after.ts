/*
  One HTTP protocol detail, shared by every surface that reads it. It knows
  nothing of React, of a route or of a feature, and holds no application state.
*/

/* A ceiling of this side's own, so a server value cannot park the interface. */
export const maxRetryAfterMs = 60_000;

/* RFC 9110 allows delay-seconds or an HTTP-date. This reads delay-seconds only,
   because that is what the API sends; an HTTP-date is refused, not parsed. */
const delaySeconds = /^[0-9]+$/;

export function retryAfterDelayMs(header: string | null): number | null {
  if (header === null) {
    return null;
  }
  /* HTTP whitespace is SP and HTAB alone; nothing else is trimmed. */
  const value = header.replace(/^[ \t]+|[ \t]+$/g, "");
  if (!delaySeconds.test(value)) {
    return null;
  }
  const seconds = Number(value);
  if (seconds <= 0) {
    return null;
  }
  return Math.min(seconds * 1000, maxRetryAfterMs);
}
