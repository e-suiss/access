// OP-153 m.3 (gg), OP-149 m.26 (b), TN-96, TN-132, §10.2.2: the bootstrap test user signs in at
// the realm's hosted login through its JSON steps: identifier, password and, since the realm asks
// for a second factor once one is enrolled, a code of the authenticator app whose seed the
// bootstrap wrote.
import { expect, type APIRequestContext } from "@playwright/test";

import { nextStep, totp } from "./totp.js";

const IDENTIFIER = process.env["ACCESS_LIVE_IDENTIFIER"] ?? "test@acme.example";
export const PASSWORD = process.env["ACCESS_LOCAL_TEST_PASSWORD"] ?? "";
const SEED = process.env["ACCESS_LIVE_TEST_TOTP_SEED"] ?? "";

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

/** Signs the bootstrap test user in at `realm` on `request`, whose cookie jar then holds the
 * session. */
export async function signIn(
  request: APIRequestContext,
  origin: string,
  realm: string,
): Promise<void> {
  const step = SEED === "" ? 0 : await nextStep();
  const started = await post(request, origin, `${realm}/v1/login/flows`);
  const identified = await post(request, origin, `${realm}${String(started["action"])}`, {
    method: "identifier",
    fields: { identifier: IDENTIFIER },
  });
  expect(identified["step"]).toBe("authenticate");
  let done = await post(request, origin, `${realm}${String(identified["action"])}`, {
    method: "password",
    fields: { password: PASSWORD },
  });
  if (done["step"] === "second_factor") {
    expect(
      SEED,
      "ACCESS_LIVE_TEST_TOTP_SEED names the test user's authenticator app seed",
    ).not.toBe("");
    done = await post(request, origin, `${realm}${String(done["action"])}`, {
      method: "totp",
      fields: { totp_code: totp(SEED, step) },
    });
  }
  expect(done["step"]).toBe("complete");
}
