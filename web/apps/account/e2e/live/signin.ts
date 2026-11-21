// OP-153 m.3 (gg), OP-149 m.26 (b), TN-96, TN-132, TN-183, §10.2.2: the bootstrap test user signs
// in at the environment's hosted login through its JSON steps: identifier and password. It has no
// second step, and the environment asks for one only once the person adds one.
import { type APIRequestContext, expect } from "@playwright/test";

export const ENVIRONMENT = "/env/acme";
export const IDENTIFIER = process.env["ACCESS_LIVE_IDENTIFIER"] ?? "test@acme.example";
export const PASSWORD = process.env["ACCESS_LOCAL_TEST_PASSWORD"] ?? "";

async function post(
  request: APIRequestContext,
  origin: string,
  path: string,
  body?: unknown,
): Promise<Record<string, unknown>> {
  const r = await request.post(`${origin}${path}`, {
    headers: {
      origin,
      "sec-fetch-site": "same-origin",
      "content-type": "application/json",
      "idempotency-key": crypto.randomUUID(),
    },
    ...(body === undefined ? {} : { data: body }),
  });
  expect(r.status(), `${path}: ${await r.text()}`).toBeLessThan(300);
  return (await r.json()) as Record<string, unknown>;
}

/**
 * Signs `identifier` in on `request` with its password alone, whose cookie jar then holds the
 * session; an account the environment asks a second factor of fails here.
 */
export async function signInWithPassword(
  request: APIRequestContext,
  origin: string,
  identifier: string,
  password: string,
): Promise<void> {
  const done = await passwordStep(request, origin, identifier, password);
  expect(done["step"]).toBe("complete");
}

async function passwordStep(
  request: APIRequestContext,
  origin: string,
  identifier: string,
  password: string,
): Promise<Record<string, unknown>> {
  const started = await post(request, origin, `${ENVIRONMENT}/v1/login/flows`);
  const identified = await post(request, origin, `${ENVIRONMENT}${String(started["action"])}`, {
    method: "identifier",
    fields: { identifier },
  });
  expect(identified["step"]).toBe("authenticate");
  return post(request, origin, `${ENVIRONMENT}${String(identified["action"])}`, {
    method: "password",
    fields: { password },
  });
}

/** Signs the bootstrap test user in on `request`, whose cookie jar then holds the session. */
export async function signIn(request: APIRequestContext, origin: string): Promise<void> {
  await signInWithPassword(request, origin, IDENTIFIER, PASSWORD);
}
