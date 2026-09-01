import type { Request } from "@playwright/test";

/* What a stand-in keeps of a request, so a test can assert on what was sent. */
export type Recorded = {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
};

/* allHeaders, not headers: the set a test asserts on has to include the ones
   the browser itself would add, Cookie among them. */
export async function record(requests: Recorded[], request: Request): Promise<void> {
  requests.push({
    method: request.method(),
    url: request.url(),
    headers: await request.allHeaders(),
    body: request.postData() ?? "",
  });
}

export function requestsTo(
  source: { requests: Recorded[] },
  method: string,
  suffix: string,
): Recorded[] {
  return source.requests.filter((r) => r.method === method && r.url.endsWith(suffix));
}
