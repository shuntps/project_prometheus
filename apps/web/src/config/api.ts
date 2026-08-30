/*
  In production the edge routes /api. The rewrite below exists only for a local
  topology, so it is installed only when an internal origin is deliberately set:
  absent means no rewrite and nothing required.
*/
export function apiRewriteOriginFrom(
  environment: Readonly<Record<string, string | undefined>>,
): string | null {
  const configured = environment.CORE_API_INTERNAL_ORIGIN?.trim();
  if (!configured) {
    return null;
  }

  let parsed: URL;
  try {
    parsed = new URL(configured);
  } catch {
    throw new Error("CORE_API_INTERNAL_ORIGIN is not a URL.");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("CORE_API_INTERNAL_ORIGIN must use http or https.");
  }
  /* Refused rather than dropped: reading .origin would discard them in silence. */
  if (parsed.username !== "" || parsed.password !== "") {
    throw new Error("CORE_API_INTERNAL_ORIGIN must carry no credentials.");
  }
  if (parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== "") {
    throw new Error("CORE_API_INTERNAL_ORIGIN must be an origin, with no path, query or fragment.");
  }
  return parsed.origin;
}
