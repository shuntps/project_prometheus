import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { expect, test } from "vitest";

function filesUnder(directory: string): string[] {
  return readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry);
    return statSync(path).isDirectory() ? filesUnder(path) : [path];
  });
}

/*
  Typography is unresolved, so the build must not acquire a dependency on a font
  service. This checks the sources; the served page is checked at runtime.
*/
test("no source file reaches a font service", () => {
  const forbidden = ["fonts.googleapis.com", "fonts.gstatic.com", "next/font/google"];
  const offenders = filesUnder("src")
    .map((path) => ({ path, text: readFileSync(path, "utf8") }))
    .filter(({ text }) => forbidden.some((needle) => text.includes(needle)))
    .map(({ path }) => path);

  expect(offenders).toEqual([]);
});

test("every font family declared in the styles is a local stack", () => {
  const styles = readFileSync(join("src", "styles", "globals.css"), "utf8");
  const declarations = [...styles.matchAll(/--font-[a-z-]+:\s*([^;]+);/g)].map(
    (match) => match[1] ?? "",
  );

  expect(declarations.length).toBeGreaterThan(0);
  for (const declaration of declarations) {
    expect(declaration).not.toContain("url(");
    expect(declaration).not.toContain("http");
  }
});
