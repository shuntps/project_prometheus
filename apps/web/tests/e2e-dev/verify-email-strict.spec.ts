import { expect, test } from "@playwright/test";

import { requestsTo } from "../support/recording";
import { fixtureToken, installRegistrationBackend } from "../support/registration-backend";

/*
  A development build runs every effect twice on mount, which is measured here
  and not assumed. The page reads the fragment once and clears it, so a second
  read would find nothing and refuse a link that is valid.
*/
test("the link is read once and sent once, however often the effect runs", async ({ page }) => {
  /* Every distinct value the panel ever displayed, not only the last one. */
  await page.addInitScript(() => {
    const seen: string[] = [];
    (window as unknown as { states: string[] }).states = seen;
    const note = () => {
      const value = document
        .querySelector("[data-verification]")
        ?.getAttribute("data-verification");
      if (value && seen[seen.length - 1] !== value) {
        seen.push(value);
      }
    };
    /* The document itself, because no element exists yet when this runs. */
    document.addEventListener("DOMContentLoaded", note);
    new MutationObserver(note).observe(document, {
      subtree: true,
      attributes: true,
      childList: true,
    });
  });

  const backend = await installRegistrationBackend(page);
  await page.goto(`/verify-email#token=${fixtureToken}`);

  await expect(page.locator("[data-verification]")).toHaveAttribute(
    "data-verification",
    "verified",
  );
  await page.waitForTimeout(1_000);

  const posted = requestsTo(backend, "POST", "/api/v1/auth/email-verification");
  expect(posted).toHaveLength(1);
  expect(JSON.parse(posted[0]?.body ?? "{}")).toEqual({ token: fixtureToken });

  /* A refusal in this list means a second read decided about a link the first
     one had already used and removed from the address bar. */
  const states = await page.evaluate(() => (window as unknown as { states: string[] }).states);
  expect(states).toEqual(["checking", "verified"]);
});
