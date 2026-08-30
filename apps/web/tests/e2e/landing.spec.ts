import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { fixtureSiteName, serverOrigin } from "../support/fixture";

test.beforeEach(async ({ page }) => {
  await page.goto("/");
});

test("the public name comes from configuration, not from a component", async ({ page }) => {
  await expect(page).toHaveTitle(fixtureSiteName);
  await expect(page.getByRole("banner").getByText(fixtureSiteName)).toBeVisible();
  await expect(page.getByRole("contentinfo").getByText(fixtureSiteName)).toBeVisible();
});

test("the landmarks and the heading hierarchy are sound", async ({ page }) => {
  await expect(page.getByRole("banner")).toBeVisible();
  await expect(page.getByRole("main")).toBeVisible();
  await expect(page.getByRole("contentinfo")).toBeVisible();
  await expect(page.getByRole("heading", { level: 1 })).toHaveCount(1);

  const levels = await page
    .locator("h1, h2, h3, h4, h5, h6")
    .evaluateAll((nodes) => nodes.map((node) => Number(node.tagName.slice(1))));
  expect(levels[0]).toBe(1);
  for (let index = 1; index < levels.length; index += 1) {
    expect((levels[index] ?? 0) - (levels[index - 1] ?? 0)).toBeLessThanOrEqual(1);
  }
});

test("the page never scrolls sideways", async ({ page }) => {
  const overflow = await page.evaluate(() => {
    const root = document.documentElement;
    return root.scrollWidth - root.clientWidth;
  });
  expect(overflow).toBeLessThanOrEqual(0);
});

test("the keyboard reaches the content and the focus is visibly ringed", async ({ page }) => {
  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: "Skip to content" });
  await expect(skip).toBeFocused();

  const ring = await skip.evaluate((node) => getComputedStyle(node).boxShadow);
  expect(ring).not.toBe("none");

  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(`${serverOrigin}/#main`);
});

test("every in-page navigation link points at a section that exists", async ({ page }) => {
  const targets = await page
    .getByRole("navigation")
    .getByRole("link")
    .evaluateAll((nodes) => nodes.map((node) => node.getAttribute("href") ?? ""));

  expect(targets.length).toBeGreaterThan(0);
  for (const target of targets) {
    expect(target.startsWith("#")).toBe(true);
    await expect(page.locator(target)).toHaveCount(1);
  }
});

test("the unavailable action is a disabled button, not a dead link", async ({ page }) => {
  const action = page.getByRole("button", { name: "Create an account" });
  await expect(action).toBeDisabled();

  const described = await action.getAttribute("aria-describedby");
  expect(described).toBeTruthy();
  await expect(page.locator(`#${described}`)).toBeVisible();
});

test("the page needs no request to another host", async ({ page }) => {
  const foreign: string[] = [];
  page.on("request", (request) => {
    if (!request.url().startsWith(serverOrigin) && !request.url().startsWith("data:")) {
      foreign.push(request.url());
    }
  });
  await page.reload({ waitUntil: "networkidle" });
  expect(foreign).toEqual([]);
});

/*
  An automated pass over the rules these tags select. It is not a conformance
  statement: a rule axe does not carry has not been assessed here.
*/
test("the automated accessibility pass returns no violation at all", async ({ page }) => {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();

  /* Every violation counts, whatever axe scores its impact as. */
  expect(results.violations.map((violation) => `${violation.id} (${violation.impact})`)).toEqual(
    [],
  );
});

/* The utility resolves the custom property; the computed value is what ships. */
test("the motion duration resolves to the configured value", async ({ page }) => {
  const measured = await page.evaluate(() => {
    const link = document.querySelector("header nav a");
    const button = document.querySelector("main button");
    return {
      link: link ? getComputedStyle(link).transitionDuration : null,
      button: button ? getComputedStyle(button).transitionDuration : null,
    };
  });

  expect(measured.link).toBe("0.18s");
  expect(measured.button).toBe("0.18s");
});

test("a reader who asks for less motion gets it", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.reload();

  const duration = await page.evaluate(() => {
    const link = document.querySelector("header nav a");
    return link ? getComputedStyle(link).transitionDuration : null;
  });

  /* Serialised as "1e-05s" here, so the number is compared, not the string. */
  expect(Number.parseFloat(duration ?? "")).toBeLessThan(0.001);
});
