import { defineConfig, devices } from "@playwright/test";

import { fixtureSiteName, serverOrigin, serverPort } from "./tests/support/fixture";

/*
  The page is prerendered, so the name has to be configured for the build as
  well as for the server; both read the same fixture value.
*/
const serverEnvironment = {
  SITE_NAME: fixtureSiteName,
  CORE_API_INTERNAL_ORIGIN: "http://127.0.0.1:8080",
  HOSTNAME: "127.0.0.1",
  PORT: String(serverPort),
};

export default defineConfig({
  testDir: "./tests/e2e",
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  reporter: process.env.CI ? [["github"], ["list"]] : [["list"]],
  use: {
    baseURL: serverOrigin,
    trace: "off",
  },
  projects: [
    {
      name: "desktop",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } },
    },
    {
      name: "mobile",
      use: { ...devices["Desktop Chrome"], viewport: { width: 390, height: 844 } },
    },
  ],
  webServer: {
    /* The standalone output is what the production image runs, so it is what
       the tests drive; its static assets sit outside the traced bundle. */
    command:
      "next build && cp -r .next/static .next/standalone/apps/web/.next/static && node .next/standalone/apps/web/server.js",
    url: serverOrigin,
    reuseExistingServer: false,
    timeout: 180_000,
    env: serverEnvironment,
  },
});
