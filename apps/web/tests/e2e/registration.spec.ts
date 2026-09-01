import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { serverOrigin } from "../support/fixture";
import { requestsTo } from "../support/recording";
import {
  fixtureToken,
  installRegistrationBackend,
  type RegistrationBackend,
} from "../support/registration-backend";
import { installSessionBackend } from "../support/session-backend";

/*
  Every request is served by a stand-in installed before navigation. No real
  token, no PostgreSQL and no Go API is exercised by any of these.
*/
const registrationPath = "/api/v1/auth/registration";
const verificationPath = "/api/v1/auth/email-verification";
const resendPath = "/api/v1/auth/email-verification/resend";

const panel = (page: Page) => page.locator("[data-verification]");
const resend = (page: Page) => page.locator("[data-resend]");

async function askForAnother(page: Page, address: string) {
  await resend(page).getByLabel("Email address", { exact: true }).fill(address);
  await page.getByRole("button", { name: "Ask for a message" }).click();
}

/* Spaces, case and a character outside ASCII: none of it may be touched. */
const passphrase = "  Ünicode  Pass Phrase ﬁ  ";

async function fillRegistration(
  page: Page,
  email: string,
  password = passphrase,
  confirm = password,
) {
  await page.getByLabel("Email address", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByLabel("Repeat the password", { exact: true }).fill(confirm);
}

async function submitRegistration(page: Page) {
  await page.getByRole("button", { name: "Create the account" }).click();
}

/* Every URL the browser asked for, so a token in one of them is visible here. */
function watchRequests(page: Page): string[] {
  const urls: string[] = [];
  page.on("request", (request) => urls.push(request.url()));
  return urls;
}

test("the landing page offers a real way to create an account", async ({ page }) => {
  await installSessionBackend(page);
  await installRegistrationBackend(page);
  await page.goto("/");
  await page.getByRole("link", { name: "Create an account" }).click();
  await expect(page).toHaveURL(/\/register$/);
  await expect(page.getByRole("heading", { name: "Create an account" })).toBeVisible();
});

test("the two account screens link to each other", async ({ page }) => {
  await installSessionBackend(page);
  await installRegistrationBackend(page);
  await page.goto("/register");
  await page.getByRole("link", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/sign-in$/);
  await page.getByRole("link", { name: "Create an account" }).click();
  await expect(page).toHaveURL(/\/register$/);
});

test("the password is sent exactly as typed and the confirmation is never sent", async ({
  page,
}) => {
  const backend = await installRegistrationBackend(page);
  await page.goto("/register");
  await fillRegistration(page, "someone@example.com");
  await submitRegistration(page);

  const posted = requestsTo(backend, "POST", registrationPath);
  expect(posted).toHaveLength(1);
  expect(posted[0]?.headers["content-type"]).toContain("application/json");
  const body = posted[0]?.body ?? "";
  expect(body).not.toContain("confirmation");
  const parsed = JSON.parse(body) as Record<string, unknown>;
  expect(Object.keys(parsed).sort()).toEqual(["email", "password"]);
  /* Byte for byte: no trimming, no case folding, no Unicode normalisation. */
  expect(parsed.password).toBe(passphrase);
  expect(parsed.email).toBe("someone@example.com");
});

test("a confirmation that differs is refused here, and nothing is sent", async ({ page }) => {
  const backend = await installRegistrationBackend(page);
  await page.goto("/register");
  await fillRegistration(page, "someone@example.com", passphrase, `${passphrase} `);
  await submitRegistration(page);

  await expect(page.locator("form [role=alert]")).toContainText("not identical");
  expect(backend.requests).toHaveLength(0);
});

test("an accepted registration answers the same way for every address", async ({ page }) => {
  await installRegistrationBackend(page);
  const answers: string[] = [];
  for (const address of ["unknown@example.com", "already-there@example.com"]) {
    await page.goto("/register");
    await fillRegistration(page, address);
    await submitRegistration(page);
    const accepted = page.getByRole("status");
    await expect(accepted).toBeVisible();
    answers.push((await accepted.innerText()).trim());
    /* The form is gone, so nothing invites a second identical attempt. */
    await expect(page.getByRole("button", { name: "Create the account" })).toHaveCount(0);
  }
  expect(answers[0]).toBe(answers[1]);
  expect(answers[0]).not.toContain("@");
});

test("a rate-limited registration refuses a second submission until its deadline", async ({
  page,
}) => {
  const backend = await installRegistrationBackend(page, {
    registrationStatus: 429,
    registrationRetryAfter: "2",
  });
  await page.goto("/register");
  await fillRegistration(page, "someone@example.com");
  await submitRegistration(page);
  await expect(page.locator("form [role=alert]")).toContainText("Too many attempts");
  const afterFirst = requestsTo(backend, "POST", registrationPath).length;
  expect(afterFirst).toBe(1);

  const submit = page.getByRole("button", { name: "Create the account" });
  await expect(submit).toBeDisabled();
  await submit.click({ force: true });
  await page.locator("form").evaluate((form: HTMLFormElement) => form.requestSubmit());
  await page.waitForTimeout(300);
  expect(requestsTo(backend, "POST", registrationPath)).toHaveLength(afterFirst);

  /* The hold releases on its own and submits nothing by itself. */
  await expect(submit).toBeEnabled({ timeout: 5_000 });
  expect(requestsTo(backend, "POST", registrationPath)).toHaveLength(afterFirst);

  backend.registrationStatus = 202;
  await submitRegistration(page);
  await expect(page.getByRole("status")).toBeVisible();
  expect(requestsTo(backend, "POST", registrationPath)).toHaveLength(afterFirst + 1);
});

test("a confirmation link is consumed once, and the token goes only into the body", async ({
  page,
}) => {
  const backend = await installRegistrationBackend(page);
  const urls = watchRequests(page);
  await page.goto(`/verify-email#token=${fixtureToken}`);
  await expect(panel(page)).toHaveAttribute("data-verification", "verified");

  const posted = requestsTo(backend, "POST", verificationPath);
  expect(posted).toHaveLength(1);
  expect(JSON.parse(posted[0]?.body ?? "{}")).toEqual({ token: fixtureToken });
  expect(backend.requests.every((r) => r.method === "POST")).toBe(true);

  /* The browser does not send a fragment, so no request URL carried the token.
     The body of the request above carries it, deliberately and once. */
  expect(urls.filter((url) => url.includes(fixtureToken))).toEqual([]);

  /* What the four checks below cover, and only that: the address bar after
     hydration, the request URLs, the document, the cookies and both web
     storages. The body of the POST carries the token on purpose. */
  expect(page.url()).not.toContain(fixtureToken);
  expect(page.url()).not.toContain("#");
  expect(page.url()).not.toContain("?");
  const traces = await page.evaluate(() => ({
    markup: document.documentElement.outerHTML,
    cookie: document.cookie,
    local: JSON.stringify(Object.entries(localStorage)),
    session: JSON.stringify(Object.entries(sessionStorage)),
  }));
  for (const [where, value] of Object.entries(traces)) {
    expect(value, where).not.toContain(fixtureToken);
  }
});

/*
  Parked before it can answer: whatever the service ends up saying, the address
  bar has already stopped carrying the token by the time anything is sent.
*/
test("the address bar is cleared before anything is sent", async ({ page }) => {
  const backend = await installRegistrationBackend(page, { holdVerification: true });
  await page.goto(`/verify-email#token=${fixtureToken}`);
  await expect.poll(() => backend.held.length).toBe(1);
  await expect(panel(page)).toHaveAttribute("data-verification", "checking");

  expect(page.url()).not.toContain(fixtureToken);
  expect(page.url()).not.toContain("#");
  expect(page.url()).not.toContain("?");

  await backend.held[0]?.release();
  await expect(panel(page)).toHaveAttribute("data-verification", "verified");
  expect(requestsTo(backend, "POST", verificationPath)).toHaveLength(1);
});

test("a confirmed address opens no session and offers a real way in", async ({ page }) => {
  await installRegistrationBackend(page);
  await installSessionBackend(page);
  await page.goto(`/verify-email#token=${fixtureToken}`);
  await expect(panel(page)).toHaveAttribute("data-verification", "verified");
  await page.getByRole("link", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/sign-in$/);
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
});

/*
  An empty fragment presented nothing at all, so the page says so rather than
  reporting a link that failed. Anything else presented in the fragment, usable
  or not, leaves by the one generic refusal.
*/
const readLocally: [string, string, string][] = [
  ["no fragment at all", "", "absent"],
  ["a token in the query string", `?token=${fixtureToken}`, "absent"],
  ["a repeated token", `#token=${fixtureToken}&token=${fixtureToken}`, "refused"],
  ["an accompanied token", `#token=${fixtureToken}&next=/`, "refused"],
  ["a differently named parameter", `#access=${fixtureToken}`, "refused"],
  ["a token of another shape", `#token=${fixtureToken.slice(1)}`, "refused"],
];

for (const [name, suffix, shown] of readLocally) {
  test(`${name} is settled without asking the server`, async ({ page }) => {
    const backend = await installRegistrationBackend(page);
    await page.goto(`/verify-email${suffix}`);
    await expect(panel(page)).toHaveAttribute("data-verification", shown);
    expect(backend.requests).toHaveLength(0);
    /* Whatever it carried, the address bar keeps none of it. */
    expect(page.url()).not.toContain("#");
    expect(page.url()).not.toContain("?");
  });
}

test("a refused token is explained in one generic way", async ({ page }) => {
  const backend = await installRegistrationBackend(page, { verificationStatus: 400 });
  await page.goto(`/verify-email#token=${fixtureToken}`);
  await expect(panel(page)).toHaveAttribute("data-verification", "refused");
  await expect(panel(page)).toContainText("cannot be used");
  expect(requestsTo(backend, "POST", verificationPath)).toHaveLength(1);
  await page.getByRole("link", { name: "Create an account" }).click();
  await expect(page).toHaveURL(/\/register$/);
});

test("a rate-limited verification retries only when a person asks", async ({ page }) => {
  const backend = await installRegistrationBackend(page, {
    verificationStatus: 429,
    verificationRetryAfter: "2",
  });
  await page.goto(`/verify-email#token=${fixtureToken}`);
  await expect(panel(page)).toHaveAttribute("data-verification", "rate-limited");
  const afterFirst = requestsTo(backend, "POST", verificationPath).length;
  expect(afterFirst).toBe(1);

  const retry = page.getByRole("button", { name: "Try again" });
  await expect(retry).toBeDisabled();
  await retry.click({ force: true });
  await page.waitForTimeout(300);
  expect(requestsTo(backend, "POST", verificationPath)).toHaveLength(afterFirst);

  /* The hold releases on its own, and sends nothing by itself. */
  await expect(retry).toBeEnabled({ timeout: 5_000 });
  expect(requestsTo(backend, "POST", verificationPath)).toHaveLength(afterFirst);

  backend.verificationStatus = 204;
  await retry.click();
  await expect(panel(page)).toHaveAttribute("data-verification", "verified");
  expect(requestsTo(backend, "POST", verificationPath)).toHaveLength(afterFirst + 1);
});

test("a network failure keeps the token and waits for a person", async ({ page }) => {
  const backend = await installRegistrationBackend(page, { verificationFails: true });
  await page.goto(`/verify-email#token=${fixtureToken}`);
  await expect(panel(page)).toHaveAttribute("data-verification", "unavailable");
  expect(requestsTo(backend, "POST", verificationPath)).toHaveLength(1);

  await page.waitForTimeout(1_000);
  expect(requestsTo(backend, "POST", verificationPath)).toHaveLength(1);

  backend.verificationFails = false;
  await page.getByRole("button", { name: "Try again" }).click();
  await expect(panel(page)).toHaveAttribute("data-verification", "verified");
  const posted = requestsTo(backend, "POST", verificationPath);
  expect(posted).toHaveLength(2);
  /* The retry sent the same token, which the URL no longer carries. */
  expect(JSON.parse(posted[1]?.body ?? "{}")).toEqual({ token: fixtureToken });
});

/* Asking for another message: the address alone, and nothing else, ever. */
test("asking for another message carries the address and nothing else", async ({ page }) => {
  const backend = await installRegistrationBackend(page);
  await page.goto("/register");
  await fillRegistration(page, "someone@example.com");
  await submitRegistration(page);
  await expect(resend(page)).toHaveAttribute("data-resend", "asking");

  await askForAnother(page, "someone-else@example.com");
  await expect(resend(page)).toHaveAttribute("data-resend", "accepted");

  const asked = requestsTo(backend, "POST", resendPath);
  expect(asked).toHaveLength(1);
  expect(asked[0]?.headers["content-type"]).toContain("application/json");
  const body = asked[0]?.body ?? "";
  for (const forbidden of ["password", "confirmation", "token"]) {
    expect(body, forbidden).not.toContain(forbidden);
  }
  expect(JSON.parse(body)).toEqual({ email: "someone-else@example.com" });
});

/* The address is asked again rather than carried over, so the panel a person
   sees after registering is the same one for every address. */
test("the accepted panel carries no address into the resend form", async ({ page }) => {
  await installRegistrationBackend(page);
  await page.goto("/register");
  await fillRegistration(page, "someone@example.com");
  await submitRegistration(page);
  await expect(resend(page)).toHaveAttribute("data-resend", "asking");
  await expect(resend(page).getByLabel("Email address", { exact: true })).toHaveValue("");
});

test("another message can be asked for from a link that was refused", async ({ page }) => {
  const backend = await installRegistrationBackend(page, { verificationStatus: 400 });
  await page.goto(`/verify-email#token=${fixtureToken}`);
  await expect(panel(page)).toHaveAttribute("data-verification", "refused");
  await expect(resend(page)).toHaveAttribute("data-resend", "asking");

  await askForAnother(page, "someone@example.com");
  await expect(resend(page)).toHaveAttribute("data-resend", "accepted");
  expect(requestsTo(backend, "POST", resendPath)).toHaveLength(1);
});

test("an accepted resend answers the same way for every address", async ({ page }) => {
  await installRegistrationBackend(page);
  const answers: string[] = [];
  for (const address of ["unknown@example.com", "already-there@example.com"]) {
    await page.goto("/verify-email");
    await expect(resend(page)).toHaveAttribute("data-resend", "asking");
    await askForAnother(page, address);
    await expect(resend(page)).toHaveAttribute("data-resend", "accepted");
    answers.push((await resend(page).innerText()).trim());
  }
  expect(answers[0]).toBe(answers[1]);
  expect(answers[0]).not.toContain("@");
});

const resendRefusals: [string, number, string][] = [
  ["a refused value", 400, "was not accepted"],
  ["an oversized value", 413, "too large"],
  ["a blocked request", 403, "was refused"],
  ["an unsupported type", 415, "was refused"],
  ["a server error", 500, "unavailable"],
];

for (const [name, status, wording] of resendRefusals) {
  test(`${name} is reported on the resend form`, async ({ page }) => {
    const backend = await installRegistrationBackend(page, { resendStatus: status });
    await page.goto("/verify-email");
    await askForAnother(page, "someone@example.com");
    await expect(resend(page).locator("[role=alert]")).toContainText(wording);
    await expect(resend(page)).toHaveAttribute("data-resend", "asking");
    expect(requestsTo(backend, "POST", resendPath)).toHaveLength(1);
  });
}

test("a network failure on the resend form is reported and retried by hand", async ({ page }) => {
  const backend = await installRegistrationBackend(page);
  await page.route(resendPath.replace("/api", "**/api"), (route) => route.abort("failed"), {
    times: 1,
  });
  await page.goto("/verify-email");
  await askForAnother(page, "someone@example.com");
  await expect(resend(page).locator("[role=alert]")).toContainText("unavailable");

  await askForAnother(page, "someone@example.com");
  await expect(resend(page)).toHaveAttribute("data-resend", "accepted");
  expect(requestsTo(backend, "POST", resendPath)).toHaveLength(1);
});

test("a rate-limited resend refuses a second submission until its deadline", async ({ page }) => {
  const backend = await installRegistrationBackend(page, {
    resendStatus: 429,
    resendRetryAfter: "2",
  });
  await page.goto("/verify-email");
  await askForAnother(page, "someone@example.com");
  await expect(resend(page).locator("[role=alert]")).toContainText("Too many attempts");
  const afterFirst = requestsTo(backend, "POST", resendPath).length;
  expect(afterFirst).toBe(1);

  const submit = page.getByRole("button", { name: "Ask for a message" });
  await expect(submit).toBeDisabled();
  await submit.click({ force: true });
  await resend(page).evaluate((form: HTMLFormElement) => form.requestSubmit());
  await page.waitForTimeout(300);
  expect(requestsTo(backend, "POST", resendPath)).toHaveLength(afterFirst);

  /* The hold releases on its own and submits nothing by itself. */
  await expect(submit).toBeEnabled({ timeout: 5_000 });
  expect(requestsTo(backend, "POST", resendPath)).toHaveLength(afterFirst);

  backend.resendStatus = 202;
  await page.getByRole("button", { name: "Ask for a message" }).click();
  await expect(resend(page)).toHaveAttribute("data-resend", "accepted");
  expect(requestsTo(backend, "POST", resendPath)).toHaveLength(afterFirst + 1);
});

/*
  Two submissions inside one task, before React has re-rendered anything: only a
  guard read in that same task can stop the second one.
*/
test("two registrations submitted in one task reach the network once", async ({ page }) => {
  const backend = await installRegistrationBackend(page, { holdRegistration: true });
  await page.goto("/register");
  await fillRegistration(page, "someone@example.com");
  await page.locator("form").evaluate((form: HTMLFormElement) => {
    form.requestSubmit();
    form.requestSubmit();
  });

  await expect.poll(() => backend.held.length).toBe(1);
  await page.waitForTimeout(300);
  expect(requestsTo(backend, "POST", registrationPath)).toHaveLength(1);
  await backend.held[0]?.release();
  await expect(page.getByRole("status")).toBeVisible();
});

test("two resends submitted in one task reach the network once", async ({ page }) => {
  const backend = await installRegistrationBackend(page, { holdResend: true });
  await page.goto("/verify-email");
  await resend(page).getByLabel("Email address", { exact: true }).fill("someone@example.com");
  await resend(page).evaluate((form: HTMLFormElement) => {
    form.requestSubmit();
    form.requestSubmit();
  });

  await expect.poll(() => backend.held.length).toBe(1);
  await page.waitForTimeout(300);
  expect(requestsTo(backend, "POST", resendPath)).toHaveLength(1);
});

test("two retries clicked in one task reach the network once", async ({ page }) => {
  const backend = await installRegistrationBackend(page, { verificationStatus: 500 });
  await page.goto(`/verify-email#token=${fixtureToken}`);
  await expect(panel(page)).toHaveAttribute("data-verification", "unavailable");
  const afterFirst = requestsTo(backend, "POST", verificationPath).length;
  expect(afterFirst).toBe(1);

  backend.holdVerification = true;
  await page.getByRole("button", { name: "Try again" }).evaluate((node: HTMLButtonElement) => {
    node.click();
    node.click();
  });

  await expect.poll(() => backend.held.length).toBe(1);
  await page.waitForTimeout(300);
  expect(requestsTo(backend, "POST", verificationPath)).toHaveLength(afterFirst + 1);
});

/*
  These three routes are public: the service reads no session on any of them,
  and sets none. No ambient credential may travel with them in either
  direction, which says nothing about the headers a browser adds of its own.
*/
const plantedCookie = "probe-session";

test("no public account request carries an ambient credential", async ({ page }) => {
  const backend = await installRegistrationBackend(page);
  await page
    .context()
    .addCookies([{ name: plantedCookie, value: "planted-by-the-test", url: serverOrigin }]);

  await page.goto("/register");
  await fillRegistration(page, "someone@example.com");
  await submitRegistration(page);
  await expect(resend(page)).toHaveAttribute("data-resend", "asking");
  await askForAnother(page, "someone@example.com");
  await expect(resend(page)).toHaveAttribute("data-resend", "accepted");

  await page.goto(`/verify-email#token=${fixtureToken}`);
  await expect(panel(page)).toHaveAttribute("data-verification", "verified");

  /* The cookie is there for this origin: the browser would send it if asked. */
  const planted = await page.context().cookies(serverOrigin);
  expect(planted.map((cookie) => cookie.name)).toContain(plantedCookie);

  for (const path of [registrationPath, resendPath, verificationPath]) {
    const sent = requestsTo(backend, "POST", path);
    expect(sent, path).toHaveLength(1);
    expect(sent[0]?.headers.cookie, path).toBeUndefined();
  }
});

test("an answer that tries to hand over a cookie is ignored", async ({ page }) => {
  await installRegistrationBackend(page, {
    answerSetsCookie: "planted-by-the-answer=1; Path=/",
  });

  await page.goto("/register");
  await fillRegistration(page, "someone@example.com");
  await submitRegistration(page);
  await expect(resend(page)).toHaveAttribute("data-resend", "asking");
  await askForAnother(page, "someone@example.com");
  await expect(resend(page)).toHaveAttribute("data-resend", "accepted");

  await page.goto(`/verify-email#token=${fixtureToken}`);
  await expect(panel(page)).toHaveAttribute("data-verification", "verified");

  const adopted = await page.context().cookies(serverOrigin);
  expect(adopted.map((cookie) => cookie.name)).not.toContain("planted-by-the-answer");
});

/* A 204 answers a first consumption and a coherent replay alike, so nothing
   here may go and read what the account is allowed to do now. */
test("a confirmed address is not followed by a look at the account", async ({ page }) => {
  const registration = await installRegistrationBackend(page);
  const session = await installSessionBackend(page);
  await page.goto(`/verify-email#token=${fixtureToken}`);
  await expect(panel(page)).toHaveAttribute("data-verification", "verified");
  await page.waitForTimeout(500);

  expect(session.requests).toEqual([]);
  expect(registration.requests.map((request) => request.method)).toEqual(["POST"]);
});

/*
  Clearing the address bar must not clear what the router keeps on that entry.
  A null state would leave the entry without it.
*/
test("clearing the address bar keeps the entry's state, and history still works", async ({
  page,
}) => {
  const backend = await installRegistrationBackend(page);
  await installSessionBackend(page);
  await page.goto(`/verify-email#token=${fixtureToken}`);
  await expect(panel(page)).toHaveAttribute("data-verification", "verified");

  const kept: unknown = await page.evaluate(() => window.history.state);
  expect(kept).not.toBeNull();
  expect(typeof kept).toBe("object");

  await page.getByRole("link", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/sign-in$/);

  /* Back to the confirmation route itself, not merely to its address. */
  await page.goBack();
  await expect(page).toHaveURL(/\/verify-email$/);
  await expect(page.getByRole("heading", { level: 1, name: "Confirm the address" })).toBeVisible();
  /* The address bar carries no link any more, so that is what it says: it does
     not report a refusal for a link this document already consumed. */
  await expect(panel(page)).toHaveAttribute("data-verification", "absent");
  await expect(resend(page)).toHaveAttribute("data-resend", "asking");
  expect(requestsTo(backend, "POST", verificationPath)).toHaveLength(1);

  await page.getByRole("link", { name: "Create an account" }).click();
  await expect(page).toHaveURL(/\/register$/);
  await expect(page.getByRole("heading", { name: "Create an account" })).toBeVisible();
});

test("an automated accessibility pass finds nothing on the account screens", async ({ page }) => {
  const backend: RegistrationBackend = await installRegistrationBackend(page);
  /* Including the two states that carry the resend form. */
  for (const path of ["/register", "/verify-email", `/verify-email#token=${fixtureToken}`]) {
    /* Two of these differ only by fragment, which alone would not reload. */
    await page.goto("about:blank");
    await page.goto(path);
    if (path.endsWith("/verify-email")) {
      await expect(resend(page)).toHaveAttribute("data-resend", "asking");
    }
    if (path.includes("#token=")) {
      await expect(panel(page)).toHaveAttribute("data-verification", "verified");
    }
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
      .analyze();
    expect(results.violations.map((v) => `${path} ${v.id}`)).toEqual([]);
  }
  /* And the accepted registration panel, which also carries it. */
  await page.goto("/register");
  await fillRegistration(page, "someone@example.com");
  await submitRegistration(page);
  await expect(resend(page)).toHaveAttribute("data-resend", "asking");
  const accepted = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(accepted.violations.map((v) => `accepted ${v.id}`)).toEqual([]);

  expect(backend.requests.length).toBeGreaterThan(0);
});
