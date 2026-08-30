import { defineConfig } from "vitest/config";

/* Node only: these suites never build or start the application. */
export default defineConfig({
  test: {
    environment: "node",
    include: ["**/*.test.ts", "**/*.test.tsx"],
  },
});
