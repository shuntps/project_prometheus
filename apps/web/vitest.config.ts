import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

/* Node only: these suites never build or start the application. */
export default defineConfig({
  /* The same mapping the compiler and the bundler apply, so a module under test
     resolves its imports the way it will at runtime. */
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  test: {
    environment: "node",
    include: ["**/*.test.ts", "**/*.test.tsx"],
  },
});
