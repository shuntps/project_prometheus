import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { expect, test } from "vitest";

const sessionDir = join("src", "features", "session");
const landingDir = join("src", "features", "landing");

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
  const text = readFileSync(join(sessionDir, "browser-api.ts"), "utf8");
  expect(text).toMatch(/^import "client-only";$/m);
});

test("the session feature keeps nothing in the browser and logs nothing", () => {
  const forbidden = ["localStorage", "sessionStorage", "document.cookie", "console."];
  const offenders = sources(sessionDir)
    .flatMap(({ path, text }) =>
      forbidden.filter((needle) => text.includes(needle)).map((needle) => `${path}: ${needle}`),
    )
    .sort();
  expect(offenders).toEqual([]);
});

test("the landing feature never depends on the session feature", () => {
  const offenders = sources(landingDir)
    .filter(({ text }) => text.includes("features/session") || text.includes("../session"))
    .map(({ path }) => path);
  expect(offenders).toEqual([]);
});

/* Same-origin relative paths only: no other host may be addressed. */
test("the session feature calls no absolute URL", () => {
  const offenders = sources(sessionDir)
    .flatMap(({ path, text }) =>
      [...text.matchAll(/["'`](https?:\/\/[^"'`]*)["'`]/g)].map(
        (match) => `${path}: ${match[1] ?? ""}`,
      ),
    )
    .sort();
  expect(offenders).toEqual([]);
});

test("every session request targets the authentication surface by a relative path", () => {
  const text = readFileSync(join(sessionDir, "browser-api.ts"), "utf8");
  const paths = [...text.matchAll(/["'](\/api\/[^"']*)["']/g)].map((match) => match[1]);
  expect(new Set(paths)).toEqual(
    new Set(["/api/v1/auth/session", "/api/v1/auth/session/activity"]),
  );
});
