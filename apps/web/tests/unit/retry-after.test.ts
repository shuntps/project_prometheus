import { expect, test } from "vitest";

import { maxRetryAfterMs, retryAfterDelayMs } from "../../src/protocol/http/retry-after";

/* Only the delay-seconds form of RFC 9110 is read; an HTTP-date is refused. */
test("only 1*DIGIT is read as a delay, then bounded locally", () => {
  expect(retryAfterDelayMs("1")).toBe(1_000);
  expect(retryAfterDelayMs("60")).toBe(60_000);
  expect(retryAfterDelayMs("100000")).toBe(maxRetryAfterMs);
  expect(retryAfterDelayMs(" \t30 \t")).toBe(30_000);
});

test("every form that is not 1*DIGIT is refused", () => {
  const refused = [
    null,
    "",
    " ",
    "soon",
    "1e3",
    "0x10",
    "+3",
    "0.5",
    "-5",
    "0",
    "00",
    "3 4",
    "3s",
    "Wed, 21 Oct 2026 07:28:00 GMT",
  ];
  for (const value of refused) {
    expect(retryAfterDelayMs(value), JSON.stringify(value)).toBeNull();
  }
});
