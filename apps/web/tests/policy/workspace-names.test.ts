import { readFileSync } from "node:fs";
import { join } from "node:path";

import { expect, test } from "vitest";

const repositoryRoot = join(process.cwd(), "..", "..");

function read(...parts: string[]): string {
  return readFileSync(join(repositoryRoot, ...parts), "utf8");
}

const packageName = (JSON.parse(read("apps", "web", "package.json")) as { name: string }).name;

/*
  A filter that matches nothing used to succeed, so a wrong name looked green.
  Every place that names this package must name the one that exists.
*/
test("every workspace filter names the package that exists", () => {
  const sources = {
    "root package.json": read("package.json"),
    "web-ci.yml": read(".github", "workflows", "web-ci.yml"),
    Dockerfile: read("apps", "web", "Dockerfile"),
    "README.md": read("apps", "web", "README.md"),
  };

  for (const [origin, text] of Object.entries(sources)) {
    const filtered = [...text.matchAll(/--filter\s+([^\s"',]+)/g)].map((match) => match[1]);
    expect(filtered.length, `${origin} names no package`).toBeGreaterThan(0);
    for (const name of filtered) {
      expect(name, `${origin} names ${name}`).toBe(packageName);
    }
  }
});

/* Without this, a mistyped filter exits zero and reports nothing. */
test("the workspace refuses a filter that matches nothing", () => {
  expect(read("pnpm-workspace.yaml")).toMatch(/^failIfNoMatch:\s*true$/m);
});

/* Next 16.3 writes agent instruction files unless this is turned off. */
test("the framework does not write agent instructions of its own", () => {
  expect(read("apps", "web", "next.config.ts")).toMatch(/agentRules:\s*false/);
});

/* A variable the application reads must stay documented in the template. */
test("every configurable variable appears in the environment template", () => {
  const template = read("apps", "web", ".env.example");
  const configured = [
    ...read("apps", "web", "src", "config", "site.ts").matchAll(/environment\.([A-Z][A-Z0-9_]+)/g),
    ...read("apps", "web", "src", "config", "api.ts").matchAll(/environment\.([A-Z][A-Z0-9_]+)/g),
  ]
    .map((match) => match[1])
    .filter((name) => name !== "NODE_ENV");

  expect(configured.length).toBeGreaterThan(0);
  for (const name of new Set(configured)) {
    expect(template, `${name} is undocumented`).toContain(`${name}=`);
  }
});

/* A client environment variable would be inlined into the browser bundle. */
test("the template declares no client environment variable", () => {
  expect(read("apps", "web", ".env.example")).not.toContain("NEXT_PUBLIC");
});
