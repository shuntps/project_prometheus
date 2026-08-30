import type { Page, Request, Route } from "@playwright/test";

/*
  A stateful stand-in for the Go API, installed before navigation. It exercises
  neither a real cookie, nor PostgreSQL, nor the API itself.
*/
export const sessionPath = "**/api/v1/auth/session";
export const activityPath = "**/api/v1/auth/session/activity";

export const csrfToken = "fixture-csrf-token";

export type FakeSession = { roles: string[] };

export type Recorded = {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
};

export type Held = { release: (session: FakeSession | null) => Promise<void> };

export type SessionBackend = {
  requests: Recorded[];
  /* When set, a matching request is parked and released by the test itself. */
  holdResolve: number;
  holdActivity: boolean;
  heldActivity: (() => Promise<void>)[];
  holdSignIn: boolean;
  held: Held[];
  signedIn: FakeSession | null;
  resolveStatus: number | null;
  resolveRetryAfter: string | null;
  activityStatus: number;
  activityRetryAfter: string | null;
  signInStatus: number;
};

function viewOf(session: FakeSession) {
  return {
    csrf_token: csrfToken,
    account_id: "3f1c2a4d-5e6b-4a7c-8d9e-0f1a2b3c4d5e",
    kind: "viewer",
    surface: "public",
    roles: session.roles,
    expires_at: "2030-01-01T00:00:00Z",
  };
}

function record(backend: SessionBackend, request: Request): void {
  backend.requests.push({
    method: request.method(),
    url: request.url(),
    headers: request.headers(),
    body: request.postData() ?? "",
  });
}

export async function installSessionBackend(
  page: Page,
  initial: Partial<SessionBackend> = {},
): Promise<SessionBackend> {
  const backend: SessionBackend = {
    requests: [],
    holdResolve: 0,
    holdActivity: false,
    heldActivity: [],
    holdSignIn: false,
    held: [],
    signedIn: null,
    resolveStatus: null,
    resolveRetryAfter: null,
    activityStatus: 204,
    activityRetryAfter: null,
    signInStatus: 201,
    ...initial,
  };

  await page.route(activityPath, async (route: Route) => {
    record(backend, route.request());
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (backend.activityRetryAfter !== null) {
      headers["retry-after"] = backend.activityRetryAfter;
    }
    if (backend.holdActivity) {
      backend.heldActivity.push(async () => {
        await route.fulfill({ status: 204, headers });
      });
      return;
    }
    if (backend.activityStatus === 204) {
      await route.fulfill({ status: 204, headers });
      return;
    }
    await route.fulfill({
      status: backend.activityStatus,
      headers,
      body: JSON.stringify({ error: { code: "refused", message: "refused", request_id: "r" } }),
    });
  });

  await page.route(sessionPath, async (route: Route) => {
    const request = route.request();
    record(backend, request);
    const headers: Record<string, string> = { "content-type": "application/json" };

    if (request.method() === "POST") {
      if (backend.holdSignIn) {
        backend.held.push({
          release: async (session) => {
            backend.signedIn = session ?? { roles: ["viewer"] };
            await route.fulfill({
              status: 201,
              headers,
              body: JSON.stringify(viewOf(backend.signedIn)),
            });
          },
        });
        return;
      }
      if (backend.signInStatus !== 201) {
        await route.fulfill({
          status: backend.signInStatus,
          headers,
          body: JSON.stringify({ error: { code: "refused", message: "refused", request_id: "r" } }),
        });
        return;
      }
      backend.signedIn = { roles: ["viewer"] };
      await route.fulfill({ status: 201, headers, body: JSON.stringify(viewOf(backend.signedIn)) });
      return;
    }

    if (request.method() === "DELETE") {
      if (request.headers()["x-csrf-token"] !== csrfToken) {
        await route.fulfill({
          status: 403,
          headers,
          body: JSON.stringify({
            error: { code: "forbidden", message: "no token", request_id: "r" },
          }),
        });
        return;
      }
      backend.signedIn = null;
      await route.fulfill({ status: 204, headers });
      return;
    }

    if (backend.holdResolve > 0) {
      backend.holdResolve -= 1;
      backend.held.push({
        release: async (session) => {
          if (session === null) {
            await route.fulfill({
              status: 401,
              headers,
              body: JSON.stringify({
                error: { code: "unauthorized", message: "no", request_id: "r" },
              }),
            });
            return;
          }
          await route.fulfill({ status: 200, headers, body: JSON.stringify(viewOf(session)) });
        },
      });
      return;
    }
    if (backend.resolveStatus !== null) {
      if (backend.resolveRetryAfter !== null) {
        headers["retry-after"] = backend.resolveRetryAfter;
      }
      if (backend.resolveStatus >= 500) {
        await route.abort("failed");
        return;
      }
      await route.fulfill({
        status: backend.resolveStatus,
        headers,
        body: JSON.stringify({ error: { code: "refused", message: "refused", request_id: "r" } }),
      });
      return;
    }
    if (backend.signedIn === null) {
      await route.fulfill({
        status: 401,
        headers,
        body: JSON.stringify({ error: { code: "unauthorized", message: "no", request_id: "r" } }),
      });
      return;
    }
    await route.fulfill({ status: 200, headers, body: JSON.stringify(viewOf(backend.signedIn)) });
  });

  return backend;
}

export function requestsTo(backend: SessionBackend, method: string, suffix: string): Recorded[] {
  return backend.requests.filter((r) => r.method === method && r.url.endsWith(suffix));
}
