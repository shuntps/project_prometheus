import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

/*
  Imports point one way: app → features → components/ui → config, and protocol
  is a leaf every layer may read. A layer never reaches back up, so a future
  domain cannot quietly couple itself to this one.
*/
const upward = (groups, message) => ({
  "no-restricted-imports": ["error", { patterns: [{ group: groups, message }] }],
});

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  globalIgnores([".next/**", "out/**", "build/**", "next-env.d.ts"]),
  {
    files: ["src/components/ui/**"],
    rules: upward(
      ["@/features/**", "@/app/**", "**/features/**", "**/app/**"],
      "A shared primitive may not depend on a feature or on a route.",
    ),
  },
  {
    files: ["src/features/**"],
    rules: upward(["@/app/**", "**/app/**"], "A feature may not depend on a route."),
  },
  {
    files: ["src/config/**"],
    rules: upward(
      [
        "@/components/**",
        "@/features/**",
        "@/app/**",
        "**/components/**",
        "**/features/**",
        "**/app/**",
        "react",
        "react-dom",
        "react-dom/**",
      ],
      "Configuration carries no user interface.",
    ),
  },
  {
    files: ["src/protocol/**"],
    rules: upward(
      [
        "@/components/**",
        "@/features/**",
        "@/app/**",
        "@/config/**",
        "**/components/**",
        "**/features/**",
        "**/app/**",
        "**/config/**",
        "react",
        "react-dom",
        "react-dom/**",
      ],
      "A protocol detail belongs to no feature, no route and no framework.",
    ),
  },
]);

export default eslintConfig;
