/*
  Runs inside the web container, where Node is already present. Every assertion
  is exact: a wrong status or a missing field fails the check.
*/
const web = "http://127.0.0.1:3000";
const api = "http://core-api:8080";
const failures = [];

function check(name, condition, detail) {
  if (condition) {
    console.log(`ok   ${name}`);
  } else {
    failures.push(`${name}: ${detail}`);
    console.log(`FAIL ${name}: ${detail}`);
  }
}

async function fetched(url) {
  try {
    const response = await fetch(url, { redirect: "manual" });
    return { response, body: await response.text() };
  } catch (error) {
    return { error: String(error) };
  }
}

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

if (failures.length > 0) {
  console.error(`${failures.length} check(s) failed`);
  process.exit(1);
}
console.log("every check passed");
