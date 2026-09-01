import { expect, test } from "vitest";

import {
  classifySubmission,
  classifyVerification,
  tokenFromFragment,
} from "../../src/features/registration/contract";
import { maxRetryAfterMs } from "../../src/protocol/http/retry-after";

const token = "A".repeat(43);

/* One classification serves registering and asking for another message: the
   service answers both through the same branch, status for status. */
test("an admitted submission has one shape whatever the address was", () => {
  expect(classifySubmission(202, null)).toEqual({ status: "accepted" });
});

test("submission answers are classified exactly", () => {
  expect(classifySubmission(400, null)).toEqual({ status: "invalid" });
  expect(classifySubmission(413, null)).toEqual({ status: "too-large" });
  expect(classifySubmission(403, null)).toEqual({ status: "blocked" });
  expect(classifySubmission(415, null)).toEqual({ status: "blocked" });
  expect(classifySubmission(500, null)).toEqual({ status: "unavailable" });
  expect(classifySubmission(201, null)).toEqual({ status: "unavailable" });
  expect(classifySubmission(204, null)).toEqual({ status: "unavailable" });
});

test("a refused submission carries a bounded delay, present or not", () => {
  expect(classifySubmission(429, "3")).toEqual({ status: "rate-limited", retryAfterMs: 3_000 });
  expect(classifySubmission(429, null)).toEqual({
    status: "rate-limited",
    retryAfterMs: maxRetryAfterMs,
  });
  expect(classifySubmission(429, "soon")).toEqual({
    status: "rate-limited",
    retryAfterMs: maxRetryAfterMs,
  });
});

/* A first consumption and a coherent second presentation both answer 204. */
test("verification answers are classified exactly", () => {
  expect(classifyVerification(204, null)).toEqual({ status: "verified" });
  expect(classifyVerification(400, null)).toEqual({ status: "refused" });
  expect(classifyVerification(403, null)).toEqual({ status: "refused" });
  expect(classifyVerification(413, null)).toEqual({ status: "refused" });
  expect(classifyVerification(415, null)).toEqual({ status: "refused" });
  expect(classifyVerification(500, null)).toEqual({ status: "unavailable" });
  expect(classifyVerification(429, "2")).toEqual({ status: "rate-limited", retryAfterMs: 2_000 });
});

test("one token parameter of the issued shape is read from the fragment", () => {
  expect(tokenFromFragment(`#token=${token}`)).toBe(token);
  expect(tokenFromFragment(`token=${token}`)).toBe(token);
});

/* Every other fragment is refused here, so no request is spent on it. */
test("an absent, repeated, accompanied or malformed token is refused", () => {
  const refused = [
    "",
    "#",
    "#token=",
    "#token",
    `#token=${token}&token=${token}`,
    `#token=${token}&next=/`,
    `#next=/&token=${token}`,
    `#other=${token}`,
    `#${token}`,
    `#token=${"A".repeat(42)}`,
    `#token=${"A".repeat(44)}`,
    `#token=${"A".repeat(42)}+`,
    `#token=${"A".repeat(42)}=`,
    `#token=${"A".repeat(42)}.`,
    `#token=${"A".repeat(42)}%20`,
    `#TOKEN=${token}`,
  ];
  for (const fragment of refused) {
    expect(tokenFromFragment(fragment), fragment).toBeNull();
  }
});

/* The shape is the one the service issues: 32 bytes in unpadded base64url. */
test("every character of the issued alphabet is accepted", () => {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const value = alphabet.repeat(2).slice(0, 43);
  expect(value).toHaveLength(43);
  expect(tokenFromFragment(`#token=${value}`)).toBe(value);
});
