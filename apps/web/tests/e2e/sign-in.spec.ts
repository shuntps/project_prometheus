import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import {
  csrfToken,
  installSessionBackend,
  requestsTo,
  sessionPath,
  type SessionBackend,
} from "../support/session-backend";

/*
  Every request is served by a stand-in installed before navigation. No real
  cookie, no PostgreSQL and no Go API is exercised by any of these.
*/
const controls = (page: Page) => page.locator("[data-session]");

async function signInThrough(page: Page) {
  await page.getByLabel("Email address").fill("someone@example.com");
  await page.getByLabel("Password").fill("correct-horse-battery-staple");
  await page.getByRole("button", { name: "Sign in" }).click();
}

test("an anonymous visitor is offered the way in", async ({ page }) => {
  await installSessionBackend(page);
  await page.goto("/");
  await expect(controls(page)).toHaveAttribute("data-session", "anonymous");
  await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible();
});

test("signing in sends the expected body and replaces the form in history", async ({ page }) => {
  const backend = await installSessionBackend(page);
  await page.goto("/");
  await page.getByRole("link", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/sign-in$/);
  await signInThrough(page);

  await expect(page).toHaveURL(/\/$/);
  await expect(controls(page)).toHaveAttribute("data-session", "authenticated");

  const posted = requestsTo(backend, "POST", "/api/v1/auth/session");
  expect(posted).toHaveLength(1);
  expect(posted[0]?.headers["content-type"]).toContain("application/json");
  expect(JSON.parse(posted[0]?.body ?? "{}")).toEqual({
    email: "someone@example.com",
    password: "correct-horse-battery-staple",
  });

  /* Replace, not push: Back must not return to the form. */
  await page.goBack();
  await expect(page).not.toHaveURL(/\/sign-in$/);
});

test("a reload resolves the session again", async ({ page }) => {
  const backend = await installSessionBackend(page, { signedIn: { roles: ["viewer"] } });
  await page.goto("/");
  await expect(controls(page)).toHaveAttribute("data-session", "authenticated");
  await page.reload();
  await expect(controls(page)).toHaveAttribute("data-session", "authenticated");
  expect(requestsTo(backend, "GET", "/api/v1/auth/session").length).toBeGreaterThanOrEqual(2);
});

test("a session holding no role is shown as signed in and can sign out", async ({ page }) => {
  const backend = await installSessionBackend(page, { signedIn: { roles: [] } });
  await page.goto("/");
  await expect(controls(page)).toHaveAttribute("data-session", "authenticated");

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(controls(page)).toHaveAttribute("data-session", "anonymous");

  const deleted = requestsTo(backend, "DELETE", "/api/v1/auth/session");
  expect(deleted).toHaveLength(1);
  expect(deleted[0]?.headers["x-csrf-token"]).toBe(csrfToken);
});

test("an unauthenticated resolution shows the anonymous state", async ({ page }) => {
  await installSessionBackend(page, { resolveStatus: 401 });
  await page.goto("/");
  await expect(controls(page)).toHaveAttribute("data-session", "anonymous");
});

test("a rate-limited resolution offers a retry", async ({ page }) => {
  await installSessionBackend(page, { resolveStatus: 429, resolveRetryAfter: "5" });
  await page.goto("/");
  await expect(controls(page)).toHaveAttribute("data-session", "rate-limited");
  await expect(page.getByRole("button", { name: "Try again" })).toBeVisible();
});

test("a network failure shows the service as unavailable", async ({ page }) => {
  await installSessionBackend(page, { resolveStatus: 500 });
  await page.goto("/");
  await expect(controls(page)).toHaveAttribute("data-session", "unavailable");
});

async function gesture(page: Page) {
  await page.locator("main").click({ position: { x: 5, y: 5 } });
}

test("a foreground interaction reports activity once", async ({ page }) => {
  const backend = await installSessionBackend(page, { signedIn: { roles: ["viewer"] } });
  await page.goto("/");
  await expect(controls(page)).toHaveAttribute("data-session", "authenticated");

  await gesture(page);
  await expect
    .poll(() => requestsTo(backend, "POST", "/api/v1/auth/session/activity").length)
    .toBe(1);

  await gesture(page);
  await gesture(page);
  await page.waitForTimeout(500);
  const reported = requestsTo(backend, "POST", "/api/v1/auth/session/activity");
  expect(reported).toHaveLength(1);
  expect(reported[0]?.headers["x-csrf-token"]).toBe(csrfToken);
});

/* Nothing may report on a timer: with no gesture at all, nothing is sent. */
test("no activity is reported without a gesture", async ({ page }) => {
  const backend = await installSessionBackend(page, { signedIn: { roles: ["viewer"] } });
  await page.goto("/");
  await expect(controls(page)).toHaveAttribute("data-session", "authenticated");
  await page.waitForTimeout(3_000);
  expect(requestsTo(backend, "POST", "/api/v1/auth/session/activity")).toHaveLength(0);
});

test("a hidden document reports nothing", async ({ page }) => {
  const backend = await installSessionBackend(page, { signedIn: { roles: ["viewer"] } });
  await page.goto("/");
  await expect(controls(page)).toHaveAttribute("data-session", "authenticated");

  await page.evaluate(() => {
    Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await gesture(page);
  await page.waitForTimeout(500);
  expect(requestsTo(backend, "POST", "/api/v1/auth/session/activity")).toHaveLength(0);
});

test("a refused renewal resolves the session again and keeps sign-out", async ({ page }) => {
  const backend = await installSessionBackend(page, {
    signedIn: { roles: ["viewer"] },
    activityStatus: 403,
  });
  await page.goto("/");
  await expect(controls(page)).toHaveAttribute("data-session", "authenticated");

  backend.signedIn = { roles: [] };
  await gesture(page);
  await expect
    .poll(() => requestsTo(backend, "POST", "/api/v1/auth/session/activity").length)
    .toBe(1);
  await expect
    .poll(() => requestsTo(backend, "GET", "/api/v1/auth/session").length)
    .toBeGreaterThanOrEqual(2);
  await expect(controls(page)).toHaveAttribute("data-session", "authenticated");

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(controls(page)).toHaveAttribute("data-session", "anonymous");
});

test("an unauthenticated renewal returns the interface to anonymous", async ({ page }) => {
  await installSessionBackend(page, { signedIn: { roles: ["viewer"] }, activityStatus: 401 });
  await page.goto("/");
  await expect(controls(page)).toHaveAttribute("data-session", "authenticated");
  await gesture(page);
  await expect(controls(page)).toHaveAttribute("data-session", "anonymous");
});

test("a refused sign-in explains itself accessibly", async ({ page }) => {
  await installSessionBackend(page, { signInStatus: 401 });
  await page.goto("/sign-in");
  await signInThrough(page);
  /* Scoped to the form: Next's own route announcer also carries role=alert. */
  await expect(page.locator("form [role=alert]")).toContainText("credentials were not accepted");
  await expect(page).toHaveURL(/\/sign-in$/);
});

test("the sign-in form is reachable by keyboard with a visible focus", async ({ page }) => {
  await installSessionBackend(page);
  await page.goto("/sign-in");
  await page.keyboard.press("Tab");
  await page.keyboard.press("Tab");
  await expect(page.getByLabel("Email address")).toBeFocused();
  const ring = await page
    .getByLabel("Email address")
    .evaluate((n) => getComputedStyle(n).boxShadow);
  expect(ring).not.toBe("none");
});

test("an automated accessibility pass finds nothing on the new screens", async ({ page }) => {
  const backend = await installSessionBackend(page, { signedIn: { roles: [] } });
  for (const path of ["/sign-in", "/"]) {
    await page.goto(path);
    if (path === "/") {
      await expect(controls(page)).toHaveAttribute("data-session", "authenticated");
    }
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
      .analyze();
    expect(results.violations.map((v) => `${path} ${v.id}`)).toEqual([]);
  }
  expect(backend.requests.length).toBeGreaterThan(0);
});

/* Visible but unfocused is a distinct property from hidden; both must hold. */
test("an unfocused document reports nothing", async ({ page }) => {
  const backend = await installSessionBackend(page, { signedIn: { roles: ["viewer"] } });
  await page.goto("/");
  await expect(controls(page)).toHaveAttribute("data-session", "authenticated");

  await page.evaluate(() => {
    Object.defineProperty(document, "hasFocus", { value: () => false, configurable: true });
  });
  const stillVisible = await page.evaluate(() => document.visibilityState);
  expect(stillVisible).toBe("visible");

  await gesture(page);
  await page.waitForTimeout(500);
  expect(requestsTo(backend, "POST", "/api/v1/auth/session/activity")).toHaveLength(0);
});

test("a rate-limited resolution refuses a second request until its deadline", async ({ page }) => {
  const backend = await installSessionBackend(page, {
    resolveStatus: 429,
    resolveRetryAfter: "2",
  });
  await page.goto("/");
  await expect(controls(page)).toHaveAttribute("data-session", "rate-limited");
  const first = requestsTo(backend, "GET", "/api/v1/auth/session").length;

  const retry = page.getByRole("button", { name: "Try again" });
  await expect(retry).toBeDisabled();
  await retry.click({ force: true });
  await retry.click({ force: true });
  await page.waitForTimeout(300);
  expect(requestsTo(backend, "GET", "/api/v1/auth/session")).toHaveLength(first);

  /* The hold releases on its own, and launches nothing by itself. */
  await expect(retry).toBeEnabled({ timeout: 5_000 });
  expect(requestsTo(backend, "GET", "/api/v1/auth/session")).toHaveLength(first);

  backend.resolveStatus = null;
  backend.signedIn = { roles: ["viewer"] };
  await retry.click();
  await expect(controls(page)).toHaveAttribute("data-session", "authenticated");
});

test("a rate-limited sign-in refuses a second submission until its deadline", async ({ page }) => {
  const backend = await installSessionBackend(page);
  let limited = true;
  await page.route(sessionPath, async (route) => {
    if (route.request().method() !== "POST") {
      await route.fallback();
      return;
    }
    backend.requests.push({
      method: "POST",
      url: route.request().url(),
      headers: route.request().headers(),
      body: route.request().postData() ?? "",
    });
    if (limited) {
      await route.fulfill({
        status: 429,
        headers: { "content-type": "application/json", "retry-after": "2" },
        body: JSON.stringify({
          error: { code: "too_many_requests", message: "wait", request_id: "r" },
        }),
      });
      return;
    }
    backend.signedIn = { roles: ["viewer"] };
    await route.fulfill({
      status: 201,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        csrf_token: csrfToken,
        account_id: "3f1c2a4d-5e6b-4a7c-8d9e-0f1a2b3c4d5e",
        kind: "viewer",
        surface: "public",
        roles: ["viewer"],
        expires_at: "2030-01-01T00:00:00Z",
      }),
    });
  });

  await page.goto("/sign-in");
  await signInThrough(page);
  await expect(page.locator("form [role=alert]")).toContainText("Too many attempts");
  const afterFirst = requestsTo(backend, "POST", "/api/v1/auth/session").length;
  expect(afterFirst).toBe(1);

  /* Two attempts while the hold stands must reach the network zero times. */
  const submit = page.getByRole("button", { name: "Sign in" });
  await expect(submit).toBeDisabled();
  await submit.click({ force: true });
  await page.locator("form").evaluate((form: HTMLFormElement) => form.requestSubmit());
  await page.waitForTimeout(300);
  expect(requestsTo(backend, "POST", "/api/v1/auth/session")).toHaveLength(afterFirst);

  /* The hold releases on its own and submits nothing by itself. */
  await expect(submit).toBeEnabled({ timeout: 5_000 });
  expect(requestsTo(backend, "POST", "/api/v1/auth/session")).toHaveLength(afterFirst);

  limited = false;
  await signInThrough(page);
  await expect(page).toHaveURL(/\/$/);
  const posted = requestsTo(backend, "POST", "/api/v1/auth/session");
  expect(posted).toHaveLength(afterFirst + 1);
  expect(JSON.parse(posted[posted.length - 1]?.body ?? "{}")).toEqual({
    email: "someone@example.com",
    password: "correct-horse-battery-staple",
  });
});

test("only the most recent resolution decides the state", async ({ page }) => {
  const backend = await installSessionBackend(page, { resolveStatus: 500 });
  await page.goto("/");
  await expect(controls(page)).toHaveAttribute("data-session", "unavailable");

  /* Two resolutions are started by hand and both are parked by the stand-in. */
  backend.resolveStatus = null;
  backend.holdResolve = 2;
  const retry = page.getByRole("button", { name: "Try again" });
  await retry.click();
  await expect.poll(() => backend.held.length).toBe(1);
  await retry.click();
  await expect.poll(() => backend.held.length).toBe(2);

  const [stale, fresh] = backend.held;
  await fresh?.release({ roles: ["viewer"] });
  await expect(controls(page)).toHaveAttribute("data-session", "authenticated");

  /* The older answer is released last; it must decide nothing. */
  await stale?.release(null).catch(() => undefined);
  await page.waitForTimeout(500);
  await expect(controls(page)).toHaveAttribute("data-session", "authenticated");
});

test("a sign-in reply that outlives the form navigates nowhere", async ({ page }) => {
  const backend = await installSessionBackend(page, { holdSignIn: true });
  await page.goto("/sign-in");
  await signInThrough(page);
  await expect.poll(() => backend.held.length).toBe(1);

  /* The form is unmounted while its request is still parked. */
  await page.goto("/");
  await expect(controls(page)).toHaveAttribute("data-session", "anonymous");
  await backend.held[0]?.release({ roles: ["viewer"] });
  await page.waitForTimeout(500);
  await expect(page).toHaveURL(/\/$/);
  await expect(controls(page)).toHaveAttribute("data-session", "anonymous");
});

test("the account slot keeps one geometry in every state", async ({ page }) => {
  const boxes: Record<string, { width: number; height: number }> = {};
  const navOrigins: { x: number; y: number }[] = [];

  const measure = async (label: string) => {
    const slot = await controls(page).boundingBox();
    const nav = await page.getByRole("navigation").boundingBox();
    expect(slot, label).not.toBeNull();
    expect(nav, label).not.toBeNull();
    boxes[label] = { width: slot?.width ?? 0, height: slot?.height ?? 0 };
    navOrigins.push({ x: nav?.x ?? 0, y: nav?.y ?? 0 });
    /* Nothing may spill out of the fixed box. */
    const overflow = await controls(page).evaluate((node) => node.scrollWidth - node.clientWidth);
    expect(overflow, `${label} overflows`).toBeLessThanOrEqual(0);
  };

  const held = await installSessionBackend(page, { holdResolve: 1 });
  await page.goto("/");
  await expect(controls(page)).toHaveAttribute("data-session", "loading");
  await measure("loading");
  await held.held[0]?.release(null);
  await expect(controls(page)).toHaveAttribute("data-session", "anonymous");
  await measure("anonymous");

  const later: [string, Partial<SessionBackend>][] = [
    ["authenticated", { signedIn: { roles: [] } }],
    ["rate-limited", { resolveStatus: 429, resolveRetryAfter: "2" }],
    ["unavailable", { resolveStatus: 500 }],
  ];
  for (const [label, initial] of later) {
    await page.unrouteAll({ behavior: "ignoreErrors" });
    await installSessionBackend(page, initial);
    await page.goto("/");
    await expect(controls(page)).toHaveAttribute("data-session", label);
    await measure(label);
  }

  const sizes = Object.values(boxes);
  for (const size of sizes) {
    expect(size).toEqual(sizes[0]);
  }
  const first = navOrigins[0];
  for (const origin of navOrigins) {
    expect(origin.x).toBeCloseTo(first?.x ?? 0, 1);
    expect(origin.y).toBeCloseTo(first?.y ?? 0, 1);
  }
});

/*
  A gesture received while a request is out must still produce exactly one send
  once that request settles. Time is driven by the test clock, so the client
  window elapses without the suite waiting for it.
*/
test("a gesture during a long flight still sends once it settles", async ({ page }) => {
  await page.clock.install();
  const backend = await installSessionBackend(page, {
    signedIn: { roles: ["viewer"] },
    holdActivity: true,
  });
  await page.goto("/");
  await expect(controls(page)).toHaveAttribute("data-session", "authenticated");

  await gesture(page);
  await expect.poll(() => backend.heldActivity.length).toBe(1);

  /* A second gesture arrives while the first request is still parked. */
  await gesture(page);
  await page.clock.fastForward(31_000);
  expect(backend.heldActivity).toHaveLength(1);

  backend.holdActivity = false;
  await backend.heldActivity[0]?.();
  await expect
    .poll(() => requestsTo(backend, "POST", "/api/v1/auth/session/activity").length, {
      timeout: 15_000,
    })
    .toBe(2);
});

/*
  A gesture already due, then the window loses focus: the timer must drop it
  rather than re-arm on a deadline in the past and spin.
*/
test("a due gesture out of focus sends nothing and leaves the page responsive", async ({
  page,
}) => {
  await page.clock.install();
  const backend = await installSessionBackend(page, {
    signedIn: { roles: ["viewer"] },
    holdActivity: true,
  });
  await page.goto("/");
  await expect(controls(page)).toHaveAttribute("data-session", "authenticated");

  await gesture(page);
  await expect.poll(() => backend.heldActivity.length).toBe(1);
  /* Armed while the first request is parked, so it becomes due at its settling. */
  await gesture(page);

  await page.evaluate(() => {
    Object.defineProperty(document, "hasFocus", { value: () => false, configurable: true });
  });
  backend.holdActivity = false;
  await page.clock.fastForward(31_000);
  await backend.heldActivity[0]?.();
  await page.clock.fastForward(31_000);

  expect(requestsTo(backend, "POST", "/api/v1/auth/session/activity")).toHaveLength(1);
  /* Still responsive: a zero-delay timer chain would starve this evaluation. */
  expect(await page.evaluate(() => document.visibilityState)).toBe("visible");
  await expect(page.getByRole("button", { name: "Sign out" })).toBeEnabled();

  await page.evaluate(() => {
    Object.defineProperty(document, "hasFocus", { value: () => true, configurable: true });
  });
  await gesture(page);
  await expect
    .poll(() => requestsTo(backend, "POST", "/api/v1/auth/session/activity").length, {
      timeout: 15_000,
    })
    .toBe(2);
});
