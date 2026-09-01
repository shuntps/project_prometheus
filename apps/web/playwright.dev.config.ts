import { defineConfig, devices } from "@playwright/test";

import { developmentOrigin, developmentPort, fixtureSiteName } from "./tests/support/fixture";

/*
  A second, deliberately small suite. It drives a development server because
  React's repeated effect on mount exists only there, and that repetition is
  what one property of the verification page has to survive. Everything else is
  proven against the standalone output the image runs.
*/
export default defineConfig({
  testDir: "./tests/e2e-dev",
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  timeout: 120_000,
  reporter: process.env.CI ? [["github"], ["list"]] : [["list"]],
  use: { baseURL: developmentOrigin, trace: "off" },
  projects: [{ name: "development", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `next dev --hostname 127.0.0.1 --port ${developmentPort}`,
    url: developmentOrigin,
    reuseExistingServer: false,
    timeout: 180_000,
    env: { SITE_NAME: fixtureSiteName },
  },
});
