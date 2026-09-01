import { expect, test } from "vitest";

import {
  classifyResolution,
  classifySignIn,
  decodeSessionView,
} from "../../src/features/session/session-contract";
import { maxRetryAfterMs } from "../../src/protocol/http/retry-after";

const valid = {
  csrf_token: "a-token",
  account_id: "1a5b6e6e-6f1e-4f3a-9a0f-6a2f4b1c8d90",
  kind: "viewer",
  surface: "public",
  roles: ["viewer"],
  expires_at: "2026-08-30T12:00:00Z",
};

test("a complete view decodes", () => {
  const view = decodeSessionView(valid);
  expect(view?.csrfToken).toBe("a-token");
  expect(view?.roles).toEqual(["viewer"]);
  expect(view?.expiresAt.toISOString()).toBe("2026-08-30T12:00:00.000Z");
});

test("an account holding no role is a valid view", () => {
  expect(decodeSessionView({ ...valid, roles: [] })?.roles).toEqual([]);
});

/* The interface interprets no role, so an unfamiliar one must not break it. */
test("an unknown role is carried through", () => {
  expect(decodeSessionView({ ...valid, roles: ["viewer", "future_role"] })?.roles).toEqual([
    "viewer",
    "future_role",
  ]);
});

test("an extra field is accepted and ignored", () => {
  const view = decodeSessionView({ ...valid, something_new: { nested: true } });
  expect(view).not.toBeNull();
  expect(Object.keys(view ?? {})).toEqual([
    "csrfToken",
    "accountId",
    "kind",
    "surface",
    "roles",
    "expiresAt",
  ]);
});

test("every required field is required", () => {
  for (const missing of Object.keys(valid)) {
    const partial: Record<string, unknown> = { ...valid };
    delete partial[missing];
    expect(decodeSessionView(partial), `${missing} absent`).toBeNull();
  }
});

test("every required field is typed", () => {
  const wrong: Record<string, unknown> = {
    csrf_token: 1,
    account_id: null,
    kind: [],
    surface: {},
    roles: "viewer",
    expires_at: 0,
  };
  for (const [field, value] of Object.entries(wrong)) {
    expect(decodeSessionView({ ...valid, [field]: value }), `${field} mistyped`).toBeNull();
  }
  expect(decodeSessionView({ ...valid, roles: ["viewer", 2] })).toBeNull();
  expect(decodeSessionView({ ...valid, csrf_token: "" })).toBeNull();
});

test("an unusable date is refused", () => {
  expect(decodeSessionView({ ...valid, expires_at: "not-a-date" })).toBeNull();
});

test("a non-object payload is refused", () => {
  for (const payload of [null, undefined, 3, "x", [valid]]) {
    expect(decodeSessionView(payload)).toBeNull();
  }
});

/* The HTTP status decides alone; no envelope, familiar or not, may override it. */
test("no error envelope can change a decision the status already made", () => {
  const envelopes = [
    { error: { code: "unauthorized", message: "m", request_id: "r" } },
    { error: { code: "a_code_added_later" } },
    { error: {} },
    { nope: 1 },
    null,
  ];
  for (const envelope of envelopes) {
    expect(classifyResolution(401, envelope, null).status, "401").toBe("anonymous");
    expect(classifyResolution(500, envelope, null).status, "500").toBe("unavailable");
    expect(classifyResolution(403, envelope, null).status, "403").toBe("unavailable");
    expect(classifySignIn(401, envelope, null).status, "sign-in 401").toBe("rejected");
    expect(classifySignIn(413, envelope, null).status, "sign-in 413").toBe("too-large");
  }
});

test("resolution states are classified exactly", () => {
  expect(classifyResolution(200, valid, null)).toEqual({
    status: "authenticated",
    session: decodeSessionView(valid),
  });
  expect(classifyResolution(401, { error: { code: "unauthorized" } }, null)).toEqual({
    status: "anonymous",
  });
  expect(classifyResolution(429, null, "2")).toEqual({
    status: "rate-limited",
    retryAfterMs: 2_000,
  });
  expect(classifyResolution(429, null, null)).toEqual({
    status: "rate-limited",
    retryAfterMs: maxRetryAfterMs,
  });
  for (const status of [500, 502, 503, 504]) {
    expect(classifyResolution(status, null, null)).toEqual({ status: "unavailable" });
  }
});

/* A 200 the contract cannot read is unavailable; asserting anonymity would lie. */
test("an unreadable 200 is unavailable, never anonymous", () => {
  expect(classifyResolution(200, { csrf_token: "only" }, null)).toEqual({ status: "unavailable" });
});

/* Reading a live session is authenticated, so a 403 is a contract mismatch. */
test("a 403 on resolution is not a user state", () => {
  expect(classifyResolution(403, { error: { code: "forbidden" } }, null)).toEqual({
    status: "unavailable",
  });
});

test("sign-in outcomes are classified exactly", () => {
  expect(classifySignIn(201, valid, null).status).toBe("created");
  expect(classifySignIn(201, { broken: true }, null).status).toBe("unavailable");
  expect(classifySignIn(400, null, null).status).toBe("invalid");
  expect(classifySignIn(401, null, null).status).toBe("rejected");
  expect(classifySignIn(413, null, null).status).toBe("too-large");
  expect(classifySignIn(403, null, null).status).toBe("blocked");
  expect(classifySignIn(415, null, null).status).toBe("blocked");
  expect(classifySignIn(500, null, null).status).toBe("unavailable");
  expect(classifySignIn(429, null, "4")).toEqual({ status: "rate-limited", retryAfterMs: 4_000 });
});
