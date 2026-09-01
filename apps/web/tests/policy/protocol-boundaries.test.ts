import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { expect, test } from "vitest";

const protocolDir = join("src", "protocol");

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
  This package is a leaf: it describes what an HTTP answer means and nothing
  else. A dependency on React, a route or a domain would make it one more
  feature, and the surfaces that share it could no longer.
*/
test("the protocol package imports nothing at all", () => {
  const offenders = sources(protocolDir)
    .flatMap(({ path, text }) =>
      [...text.matchAll(/^\s*(?:import|export)\s[^\n]*\bfrom\s+["']([^"']+)["']/gm)].map(
        (match) => `${path}: ${match[1] ?? ""}`,
      ),
    )
    .sort();
  expect(offenders).toEqual([]);
});

test("the protocol package holds no component and no route", () => {
  const offenders = sources(protocolDir)
    .filter(({ path }) => !path.endsWith(".ts"))
    .map(({ path }) => path);
  expect(offenders).toEqual([]);
});

/* One definition, shared. A second copy would drift from the first in silence. */
test("the retry-after protocol is defined once and read where it is needed", () => {
  const definitions = sources(join("src"))
    .filter(({ text }) => text.includes("export function retryAfterDelayMs"))
    .map(({ path }) => path);
  expect(definitions).toEqual([join("src", "protocol", "http", "retry-after.ts")]);
});
