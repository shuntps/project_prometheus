import { expect, test } from "vitest";

import { apiRewriteOriginFrom } from "../../src/config/api";
import { maxSiteNameCodePoints, siteNameFrom } from "../../src/config/site";

test("the configured public name is used as given, once trimmed", () => {
  expect(siteNameFrom({ SITE_NAME: "  A Name  " })).toBe("A Name");
});

test("a production build without a public name is refused", () => {
  expect(() => siteNameFrom({ NODE_ENV: "production" })).toThrow(/SITE_NAME/);
  expect(() => siteNameFrom({ NODE_ENV: "production", SITE_NAME: "   " })).toThrow(/SITE_NAME/);
});

test("development resolves a placeholder rather than refusing", () => {
  expect(siteNameFrom({ NODE_ENV: "development" })).toBeTruthy();
});

test("the bound is counted in code points, not in UTF-16 units", () => {
  /* Each astral character is one code point and two UTF-16 units. */
  const astral = "\u{1F600}".repeat(maxSiteNameCodePoints);
  expect([...astral]).toHaveLength(maxSiteNameCodePoints);
  expect(astral.length).toBe(maxSiteNameCodePoints * 2);
  expect(siteNameFrom({ SITE_NAME: astral })).toBe(astral);

  expect(() => siteNameFrom({ SITE_NAME: "\u{1F600}".repeat(maxSiteNameCodePoints + 1) })).toThrow(
    /code points/,
  );
});

test("a public name of exactly the bound is accepted and one more is refused", () => {
  expect(siteNameFrom({ SITE_NAME: "a".repeat(maxSiteNameCodePoints) })).toHaveLength(
    maxSiteNameCodePoints,
  );
  expect(() => siteNameFrom({ SITE_NAME: "a".repeat(maxSiteNameCodePoints + 1) })).toThrow(
    /code points/,
  );
});

/* Trimming used to run first, so a leading or trailing one was removed unseen. */
test("a control or format character is refused wherever it sits", () => {
  const cases = [
    "\nExample",
    "\tExample",
    "\u{FEFF}Example",
    "Exa\u{0000}mple",
    "Exa\u{202E}mple",
    "Example\n",
    "Example\u{200B}",
  ];
  for (const value of cases) {
    expect(() => siteNameFrom({ SITE_NAME: value }), value).toThrow(/control or format/);
  }
});

test("ordinary surrounding spaces are still trimmed", () => {
  expect(siteNameFrom({ SITE_NAME: "   Example Platform   " })).toBe("Example Platform");
});

test("no internal origin configured installs no rewrite and requires nothing", () => {
  expect(apiRewriteOriginFrom({})).toBeNull();
  expect(apiRewriteOriginFrom({ NODE_ENV: "production" })).toBeNull();
  expect(
    apiRewriteOriginFrom({ NODE_ENV: "production", CORE_API_INTERNAL_ORIGIN: "  " }),
  ).toBeNull();
});

test("a configured internal origin is kept as an origin", () => {
  expect(apiRewriteOriginFrom({ CORE_API_INTERNAL_ORIGIN: "http://10.0.0.4:8080" })).toBe(
    "http://10.0.0.4:8080",
  );
  expect(apiRewriteOriginFrom({ CORE_API_INTERNAL_ORIGIN: "https://core-api.internal" })).toBe(
    "https://core-api.internal",
  );
});

test("an internal origin that is not a plain credential-free origin is refused", () => {
  for (const value of [
    "not-a-url",
    "ftp://host",
    "http://host/api",
    "http://host/?a=1",
    "http://host/#f",
  ]) {
    expect(() => apiRewriteOriginFrom({ CORE_API_INTERNAL_ORIGIN: value })).toThrow();
  }
});

/* Reading .origin would drop these silently, so the refusal is explicit. */
test("an internal origin carrying credentials is refused, not normalised", () => {
  for (const value of [
    "http://user@host:8080",
    "http://user:secret@host:8080",
    "http://:secret@host:8080",
  ]) {
    expect(() => apiRewriteOriginFrom({ CORE_API_INTERNAL_ORIGIN: value })).toThrow(/credentials/);
  }
});

test("no public environment variable carries the internal API address", () => {
  expect(apiRewriteOriginFrom.toString()).not.toContain("NEXT_PUBLIC");
});
