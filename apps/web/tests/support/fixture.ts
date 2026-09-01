/*
  A name no component could plausibly contain, so a page that still shows it
  proves the value travelled from configuration rather than from a literal.
*/
export const fixtureSiteName = "Landing Fixture 8f3a";

export const serverPort = 3100;
export const serverOrigin = `http://127.0.0.1:${serverPort}`;

/*
  React re-runs an effect on mount only in a development build, so the one
  property that depends on it is proven against a development server of its own.
*/
export const developmentPort = 3101;
export const developmentOrigin = `http://127.0.0.1:${developmentPort}`;
