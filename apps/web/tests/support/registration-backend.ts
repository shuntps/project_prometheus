import type { Page, Route } from "@playwright/test";

import { record, type Recorded } from "./recording";

/*
  A stand-in for the Go API, installed before navigation. It exercises neither
  PostgreSQL, nor a real token, nor the API itself.
*/
export const registrationRoute = "**/api/v1/auth/registration";
export const verificationRoute = "**/api/v1/auth/email-verification";
export const resendRoute = "**/api/v1/auth/email-verification/resend";

/* Only the shape matters here: 32 bytes in unpadded base64url, as issued. */
export const fixtureToken = "kJ8xQ2pR7vN4mL0aZ5tY9wB3cD6eF1gH2iJ4kL6mN8p";

export type Held = { release: () => Promise<void> };

export type RegistrationBackend = {
  requests: Recorded[];
  registrationStatus: number;
  registrationRetryAfter: string | null;
  holdRegistration: boolean;
  verificationStatus: number;
  verificationRetryAfter: string | null;
  /* When set, the request fails at the network layer rather than answering. */
  verificationFails: boolean;
  /* When set, a matching request is parked and released by the test itself. */
  holdVerification: boolean;
  resendStatus: number;
  resendRetryAfter: string | null;
  holdResend: boolean;
  /* When set, every answer tries to hand the browser a cookie. */
  answerSetsCookie: string | null;
  held: Held[];
};

function refusal(status: number, headers: Record<string, string>) {
  return {
    status,
    headers,
    body: JSON.stringify({ error: { code: "refused", message: "refused", request_id: "r" } }),
  };
}

export async function installRegistrationBackend(
  page: Page,
  initial: Partial<RegistrationBackend> = {},
): Promise<RegistrationBackend> {
  const backend: RegistrationBackend = {
    requests: [],
    registrationStatus: 202,
    registrationRetryAfter: null,
    holdRegistration: false,
    verificationStatus: 204,
    verificationRetryAfter: null,
    verificationFails: false,
    holdVerification: false,
    resendStatus: 202,
    resendRetryAfter: null,
    holdResend: false,
    answerSetsCookie: null,
    held: [],
    ...initial,
  };

  await page.route(registrationRoute, async (route: Route) => {
    await record(backend.requests, route.request());
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (backend.answerSetsCookie !== null) {
      headers["set-cookie"] = backend.answerSetsCookie;
    }
    if (backend.registrationRetryAfter !== null) {
      headers["retry-after"] = backend.registrationRetryAfter;
    }
    const answer = async () => {
      if (backend.registrationStatus === 202) {
        await route.fulfill({ status: 202, headers });
        return;
      }
      await route.fulfill(refusal(backend.registrationStatus, headers));
    };
    if (backend.holdRegistration) {
      backend.held.push({ release: answer });
      return;
    }
    await answer();
  });

  await page.route(verificationRoute, async (route: Route) => {
    await record(backend.requests, route.request());
    if (backend.verificationFails) {
      await route.abort("failed");
      return;
    }
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (backend.answerSetsCookie !== null) {
      headers["set-cookie"] = backend.answerSetsCookie;
    }
    if (backend.verificationRetryAfter !== null) {
      headers["retry-after"] = backend.verificationRetryAfter;
    }
    const answer = async () => {
      if (backend.verificationStatus === 204) {
        await route.fulfill({ status: 204, headers });
        return;
      }
      await route.fulfill(refusal(backend.verificationStatus, headers));
    };
    if (backend.holdVerification) {
      backend.held.push({ release: answer });
      return;
    }
    await answer();
  });

  await page.route(resendRoute, async (route: Route) => {
    await record(backend.requests, route.request());
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (backend.answerSetsCookie !== null) {
      headers["set-cookie"] = backend.answerSetsCookie;
    }
    if (backend.resendRetryAfter !== null) {
      headers["retry-after"] = backend.resendRetryAfter;
    }
    const answer = async () => {
      if (backend.resendStatus === 202) {
        await route.fulfill({ status: 202, headers });
        return;
      }
      await route.fulfill(refusal(backend.resendStatus, headers));
    };
    if (backend.holdResend) {
      backend.held.push({ release: answer });
      return;
    }
    await answer();
  });

  return backend;
}
