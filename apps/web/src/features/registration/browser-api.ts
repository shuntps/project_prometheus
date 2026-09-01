import "client-only";

import {
  classifySubmission,
  classifyVerification,
  type SubmissionOutcome,
  type VerificationOutcome,
} from "./contract";

/*
  Relative, same-origin paths only. No ambient credential travels with these
  three requests: the service reads no session on any of them and sets none, so
  credentials are omitted in both directions rather than merely unused.
*/
const registrationPath = "/api/v1/auth/registration";
const verificationPath = "/api/v1/auth/email-verification";
const resendPath = "/api/v1/auth/email-verification/resend";

const jsonHeaders = { "Content-Type": "application/json" } as const;

/* The password is sent exactly as it was typed: nothing here trims it, folds
   its case, truncates it or normalises it. */
export async function registerAccount(
  email: string,
  password: string,
  signal?: AbortSignal,
): Promise<SubmissionOutcome> {
  let response: Response;
  try {
    response = await fetch(registrationPath, {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: jsonHeaders,
      body: JSON.stringify({ email, password }),
      ...(signal ? { signal } : {}),
    });
  } catch {
    return { status: "unavailable" };
  }
  return classifySubmission(response.status, response.headers.get("Retry-After"));
}

/* A POST, never a GET: the token is sent deliberately, in the JSON body, and
   so enters no request line, referrer or history entry. Whatever reads request
   bodies between here and the service still reads it. */
export async function verifyEmail(
  token: string,
  signal?: AbortSignal,
): Promise<VerificationOutcome> {
  let response: Response;
  try {
    response = await fetch(verificationPath, {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: jsonHeaders,
      body: JSON.stringify({ token }),
      ...(signal ? { signal } : {}),
    });
  } catch {
    return { status: "unavailable" };
  }
  return classifyVerification(response.status, response.headers.get("Retry-After"));
}

/* Asks for another message. It carries the address alone: no password, no
   confirmation and no token, so nothing here can change or spend a credential. */
export async function resendVerification(
  email: string,
  signal?: AbortSignal,
): Promise<SubmissionOutcome> {
  let response: Response;
  try {
    response = await fetch(resendPath, {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: jsonHeaders,
      body: JSON.stringify({ email }),
      ...(signal ? { signal } : {}),
    });
  } catch {
    return { status: "unavailable" };
  }
  return classifySubmission(response.status, response.headers.get("Retry-After"));
}
