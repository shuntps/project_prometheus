import { renderToStaticMarkup } from "react-dom/server";
import { expect, test } from "vitest";

import { Badge } from "../../src/components/ui/badge";
import { Button } from "../../src/components/ui/button";
import { Container } from "../../src/components/ui/container";
import { Surface } from "../../src/components/ui/surface";

test("a button is not a submit control unless it is asked to be", () => {
  expect(renderToStaticMarkup(<Button>Go</Button>)).toContain('type="button"');
  expect(renderToStaticMarkup(<Button type="submit">Go</Button>)).toContain('type="submit"');
});

/* A caller's className adds to the variant; it must never replace it. */
test("a caller's classes never displace the ones the variant guarantees", () => {
  const plain = renderToStaticMarkup(<Button>Go</Button>);
  const extended = renderToStaticMarkup(<Button className="mt-8">Go</Button>);

  expect(plain).toContain("bg-primary");
  expect(extended).toContain("bg-primary");
  expect(extended).toContain("rounded-pill");
  expect(extended).toContain("mt-8");
});

test("the outline variant keeps its own guarantees alongside a caller's classes", () => {
  const markup = renderToStaticMarkup(
    <Button variant="outline" className="w-full">
      Go
    </Button>,
  );
  expect(markup).toContain("border-outline-strong");
  expect(markup).toContain("w-full");
});

test("the other primitives merge rather than replace as well", () => {
  expect(renderToStaticMarkup(<Badge className="mt-2">B</Badge>)).toContain("rounded-pill");
  expect(renderToStaticMarkup(<Badge className="mt-2">B</Badge>)).toContain("mt-2");

  const surface = renderToStaticMarkup(
    <Surface tone="highest" className="p-8">
      S
    </Surface>,
  );
  expect(surface).toContain("rounded-card");
  expect(surface).toContain("bg-surface-highest");
  expect(surface).toContain("p-8");

  const container = renderToStaticMarkup(<Container className="pb-4">C</Container>);
  expect(container).toContain("max-w-6xl");
  expect(container).toContain("pb-4");
});
