/*
  Runs inside the web container, where Node is already present. Every assertion
  is exact: a wrong status or a missing field fails the check.
*/
const web = "http://127.0.0.1:3000";
const api = "http://core-api:8080";
const collector = "http://mailpit:8025";
const failures = [];
let passed = 0;

function check(name, condition, detail) {
  if (condition) {
    passed++;
    console.log(`ok   ${name}`);
  } else {
    failures.push(`${name}: ${detail}`);
    console.log(`FAIL ${name}: ${detail}`);
  }
}

async function fetched(url, init) {
  try {
    const response = await fetch(url, { redirect: "manual", ...init });
    return { response, body: await response.text() };
  } catch (error) {
    return { error: String(error) };
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/* The exact wording the API answers an unauthenticated read with. */
const authenticationRequired = "Authentication is required.";

function jsonOf(payload) {
  try {
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

const readiness = await fetched(`${api}/readyz`);
if (readiness.error) {
  check("core-api /readyz reachable", false, readiness.error);
} else {
  const type = readiness.response.headers.get("content-type") ?? "";
  const payload = jsonOf(readiness.body);
  check(
    "core-api /readyz is 200",
    readiness.response.status === 200,
    `status ${readiness.response.status}`,
  );
  check(
    "core-api /readyz answers json",
    type.includes("application/json"),
    `content-type ${type}`,
  );
  check(
    "core-api /readyz reports ready",
    payload !== null &&
      payload.status === "ready" &&
      Object.keys(payload).length === 1,
    `body ${readiness.body.slice(0, 120)}`,
  );
}

const home = await fetched(`${web}/`);
if (home.error) {
  check("web / reachable", false, home.error);
} else {
  check(
    "web / is 200",
    home.response.status === 200,
    `status ${home.response.status}`,
  );
  check(
    "web / serves html",
    (home.response.headers.get("content-type") ?? "").includes("text/html"),
    `content-type ${home.response.headers.get("content-type")}`,
  );
}

const rewritten = await fetched(`${web}/api/v1/auth/session`);
if (rewritten.error) {
  check("web /api rewrite reachable", false, rewritten.error);
} else {
  const headers = rewritten.response.headers;
  const type = headers.get("content-type") ?? "";
  const cacheControl = headers.get("cache-control") ?? "";
  const headerId = headers.get("x-request-id") ?? "";
  const error = jsonOf(rewritten.body)?.error;

  check(
    "web /api rewrite is 401",
    rewritten.response.status === 401,
    `status ${rewritten.response.status}`,
  );
  check(
    "web /api rewrite answers json",
    type.includes("application/json"),
    `content-type ${type}`,
  );
  check(
    "web /api rewrite forbids caching",
    cacheControl === "no-store",
    `cache-control ${cacheControl || "(absent)"}`,
  );
  check(
    "web /api rewrite refuses with the generic code",
    error?.code === "unauthorized",
    `code ${error?.code}`,
  );
  check(
    "web /api rewrite carries the generic message",
    error?.message === authenticationRequired,
    `message ${JSON.stringify(error?.message)}`,
  );
  check(
    "web /api rewrite carries a request id header",
    headerId.length > 0,
    "header absent",
  );
  check(
    "web /api rewrite carries a request id in the body",
    typeof error?.request_id === "string" && error.request_id.length > 0,
    `request_id ${JSON.stringify(error?.request_id)}`,
  );
  /* One identifier, reported twice: a mismatch means they came from two answers. */
  check(
    "web /api rewrite reports one identifier in both places",
    headerId.length > 0 && headerId === error?.request_id,
    `header ${headerId} body ${error?.request_id}`,
  );
}

/*
  The registration journey end to end, through the Next.js rewrite. The
  /verify-email page does not exist, so the token is read from the fragment here
  the way that page will have to.
*/
const registrant = `dev-check-${Date.now()}@example.invalid`;
const secret = "dev-check-correct-horse-battery-staple";
const browserHeaders = {
  "content-type": "application/json",
  origin: web.replace("127.0.0.1", "localhost"),
  "sec-fetch-site": "same-origin",
};

async function posted(path, body) {
  return fetched(`${web}${path}`, {
    method: "POST",
    headers: browserHeaders,
    body: JSON.stringify(body),
  });
}

const registration = await posted("/api/v1/auth/registration", {
  email: registrant,
  password: secret,
});
if (registration.error) {
  check("registration reachable", false, registration.error);
} else {
  check(
    "registration is accepted",
    registration.response.status === 202,
    `status ${registration.response.status} body ${registration.body.slice(0, 160)}`,
  );
  check(
    "registration answers no body",
    registration.body === "",
    `body ${JSON.stringify(registration.body.slice(0, 120))}`,
  );
}

let delivered = null;
for (let attempt = 0; attempt < 40 && delivered === null; attempt++) {
  const search = await fetched(
    `${collector}/api/v1/search?query=${encodeURIComponent("to:" + registrant)}`,
  );
  const found = search.error ? null : jsonOf(search.body)?.messages?.[0];
  if (found) {
    delivered = found;
    break;
  }
  await sleep(500);
}
check(
  "the verification message reaches the collector",
  delivered !== null,
  "no message was collected within 20s",
);

let token = null;
if (delivered !== null) {
  const message = await fetched(`${collector}/api/v1/message/${delivered.ID}`);
  const text = message.error ? "" : (jsonOf(message.body)?.Text ?? "");
  const link = text.match(/https?:\/\/\S+/)?.[0] ?? "";
  check(
    "the message carries no product name",
    !/prometheus/i.test(text),
    "the body names the internal codename",
  );
  check(
    "the link carries no token in a query",
    link.length > 0 && !link.includes("?"),
    `link ${link.replace(/#.*/, "#<fragment>")}`,
  );

  let parsed = null;
  try {
    parsed = new URL(link);
  } catch {
    parsed = null;
  }
  check(
    "the link points at the reserved verification path",
    parsed?.pathname === "/verify-email",
    `path ${parsed?.pathname}`,
  );
  check(
    "the request part of the link carries no token",
    parsed !== null && !`${parsed.pathname}${parsed.search}`.includes("token"),
    `path and query ${parsed?.pathname}${parsed?.search}`,
  );
  /* What the page will have to do: read the fragment, never the query. */
  token = new URLSearchParams((parsed?.hash ?? "").replace(/^#/, "")).get(
    "token",
  );
  check(
    "the fragment carries a token of the issued shape",
    typeof token === "string" && /^[A-Za-z0-9_-]{43}$/.test(token),
    `token ${JSON.stringify(token)}`,
  );
}

const before = await posted("/api/v1/auth/session", {
  email: registrant,
  password: secret,
});
check(
  "a pending account cannot sign in",
  !before.error && before.response.status === 401,
  `status ${before.response?.status} ${before.error ?? ""}`,
);

if (token !== null) {
  const verification = await posted("/api/v1/auth/email-verification", {
    token,
  });
  check(
    "the verification is accepted",
    !verification.error && verification.response.status === 204,
    `status ${verification.response?.status} body ${verification.body?.slice(0, 160)}`,
  );
  check(
    "the verification opens no session",
    verification.response?.headers.get("set-cookie") === null,
    `set-cookie ${verification.response?.headers.get("set-cookie")}`,
  );

  const replay = await posted("/api/v1/auth/email-verification", { token });
  check(
    "presenting the same token again answers alike",
    !replay.error && replay.response.status === 204,
    `status ${replay.response?.status}`,
  );
}

const after = await posted("/api/v1/auth/session", {
  email: registrant,
  password: secret,
});
const view = after.error ? null : jsonOf(after.body);
const cookie = after.response?.headers.get("set-cookie") ?? "";
check(
  "a verified account signs in",
  !after.error && after.response.status === 201,
  `status ${after.response?.status} body ${after.body?.slice(0, 160)}`,
);
check(
  "the sign-in sets the host-prefixed session cookie",
  cookie.includes("__Host-session="),
  `set-cookie ${cookie.slice(0, 80)}`,
);
check(
  "the account holds the viewer grant alone",
  Array.isArray(view?.roles) &&
    view.roles.length === 1 &&
    view.roles[0] === "viewer",
  `roles ${JSON.stringify(view?.roles)}`,
);

const watching = await fetched(`${web}/api/v1/auth/broadcast-access`, {
  headers: { ...browserHeaders, cookie: cookie.split(";")[0] },
});
check(
  "a verified viewer reaches no adult capability",
  !watching.error && watching.response.status === 403,
  `status ${watching.response?.status}`,
);

if (failures.length > 0) {
  console.error(`${failures.length} check(s) failed of ${passed + failures.length}`);
  process.exit(1);
}
console.log(`every check passed: ${passed} assertions`);
