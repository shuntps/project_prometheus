import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { expect, test } from "vitest";

const registrationDir = join("src", "features", "registration");

function filesUnder(directory: string): string[] {
  return readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry);
    return statSync(path).isDirectory() ? filesUnder(path) : [path];
  });
}

function sources(directory: string): { path: string; text: string }[] {
  return filesUnder(directory).map((path) => ({ path, text: readFileSync(path, "utf8") }));
}

/*
  Next refuses to build this module into the server graph, which is the real
  guarantee. This keeps the marker from being dropped by accident.
*/
test("the browser HTTP module declares itself client-only", () => {
  const text = readFileSync(join(registrationDir, "browser-api.ts"), "utf8");
  expect(text).toMatch(/^import "client-only";$/m);
});

test("the registration feature keeps nothing in the browser and logs nothing", () => {
  const forbidden = ["localStorage", "sessionStorage", "document.cookie", "console."];
  const offenders = sources(registrationDir)
    .flatMap(({ path, text }) =>
      forbidden.filter((needle) => text.includes(needle)).map((needle) => `${path}: ${needle}`),
    )
    .sort();
  expect(offenders).toEqual([]);
});

/* Two separate domains: registering opens no session and reads none. */
test("the registration feature never depends on the session feature", () => {
  const offenders = sources(registrationDir)
    .filter(({ text }) => text.includes("features/session") || text.includes("../session"))
    .map(({ path }) => path);
  expect(offenders).toEqual([]);
});

/* Same-origin relative paths only: no other host may be addressed. */
test("the registration feature calls no absolute URL", () => {
  const offenders = sources(registrationDir)
    .flatMap(({ path, text }) =>
      [...text.matchAll(/["'`](https?:\/\/[^"'`]*)["'`]/g)].map(
        (match) => `${path}: ${match[1] ?? ""}`,
      ),
    )
    .sort();
  expect(offenders).toEqual([]);
});

test("every registration request targets the authentication surface by a relative path", () => {
  const text = readFileSync(join(registrationDir, "browser-api.ts"), "utf8");
  const paths = [...text.matchAll(/["'](\/api\/[^"']*)["']/g)].map((match) => match[1]);
  expect(new Set(paths)).toEqual(
    new Set([
      "/api/v1/auth/registration",
      "/api/v1/auth/email-verification",
      "/api/v1/auth/email-verification/resend",
    ]),
  );
});

/*
  The token arrives in the fragment, which the browser does not send. Reading it
  from a query string, a path segment or the framework's parameters would put it
  in a request line instead, where it would reach access records and referrers.
  It is sent deliberately, once, in the body of the confirming request.
*/
test("the verification surface reads no request parameter", () => {
  const forbidden = [
    "useSearchParams",
    "searchParams",
    "location.search",
    "location.href",
    "useParams",
  ];
  const offenders = [
    ...sources(registrationDir),
    {
      path: join("src", "app", "verify-email", "page.tsx"),
      text: readFileSync(join("src", "app", "verify-email", "page.tsx"), "utf8"),
    },
  ]
    .flatMap(({ path, text }) =>
      forbidden.filter((needle) => text.includes(needle)).map((needle) => `${path}: ${needle}`),
    )
    .sort();
  expect(offenders).toEqual([]);
});

/*
  A 204 answers a first consumption and a coherent second presentation alike,
  and a suspension that arrived afterwards does not change it. This panel may
  say the address is confirmed and that no session was opened; it may not say
  what the account can do now, or that signing in will succeed.
*/
test("the confirmed panel claims nothing about the account's standing", () => {
  const text = readFileSync(join(registrationDir, "content.ts"), "utf8");
  const start = text.indexOf("verified: {");
  expect(start).toBeGreaterThan(0);
  const block = text.slice(start, text.indexOf("},", start)).toLowerCase();
  const claims = ["usable", "active", "enabled", "ready", "you can sign in", "will work"];
  expect(claims.filter((claim) => block.includes(claim))).toEqual([]);
});

/* A route is a shell: it composes, and decides nothing about a request. */
test("neither route holds business or transport logic", () => {
  for (const route of ["register", "verify-email"]) {
    const text = readFileSync(join("src", "app", route, "page.tsx"), "utf8");
    expect(text, route).not.toContain("fetch(");
    expect(text, route).not.toContain("use client");
    expect(text, route).not.toContain("useState");
  }
});
