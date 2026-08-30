/*
  The public name is one configuration value. It is never written literally into
  a component, and it has no production default: an unnamed build fails closed.
*/
const developmentSiteName = "Example Platform";

/* A bound this implementation sets, measured in Unicode code points. */
export const maxSiteNameCodePoints = 64;

/* Controls and format characters cover newlines, byte-order marks and bidi. */
const forbiddenCharacters = /[\p{Cc}\p{Cf}]/u;

export function siteNameFrom(environment: Readonly<Record<string, string | undefined>>): string {
  const raw = environment.SITE_NAME;
  if (raw === undefined) {
    return withoutAName(environment);
  }
  /* Checked before trimming, so a leading or trailing one cannot slip away. */
  if (forbiddenCharacters.test(raw)) {
    throw new Error("SITE_NAME carries a control or format character.");
  }

  const configured = raw.trim();
  if (!configured) {
    return withoutAName(environment);
  }
  if ([...configured].length > maxSiteNameCodePoints) {
    throw new Error(`SITE_NAME is longer than ${maxSiteNameCodePoints} code points.`);
  }
  /* React escapes what it renders; nothing here re-implements that. */
  return configured;
}

function withoutAName(environment: Readonly<Record<string, string | undefined>>): string {
  if (environment.NODE_ENV === "production") {
    throw new Error("SITE_NAME is required: the public name has no production default.");
  }
  return developmentSiteName;
}

export const siteName = siteNameFrom(process.env);

export const siteDescription = "A platform where creators broadcast to their communities.";
