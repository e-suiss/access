import { readFileSync } from "node:fs";
import { join } from "node:path";

import { expect, test } from "./fixtures.js";
import { password, totp } from "./mock.js";

const neutral = "We couldn't sign you in with these details.";

/** The `ui-enumeration` phrases of the forbidden-claims catalog (B15). */
function enumerationClaims(): string[] {
  const catalog = readFileSync(
    join(import.meta.dirname, "../../../conformance/catalog/forbidden-claims.toml"),
    "utf8",
  );
  const block = catalog.split("[[claim]]").find((b) => b.includes('id = "ui-enumeration"')) ?? "";
  const phrases = /phrases = \[(.*)\]/.exec(block)?.[1] ?? "";
  return [...phrases.matchAll(/"([^"]+)"/g)].map((m) => (m[1] ?? "").toLowerCase());
}

// TN-96, §10.2.1, K06
test("identifier first, then password and MFA, then back to the client", async ({ page, mock }) => {
  await page.goto("/");
  const identifier = page.getByLabel("Email or username");
  await expect(identifier).toHaveAttribute("autocomplete", "username webauthn");
  await expect(page.getByRole("button", { name: "Sign in with a passkey" })).toBeVisible();
  await identifier.fill("ada@example.org");
  await page.getByRole("button", { name: "Continue" }).click();

  await expect(page.getByLabel("Password")).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign in with a passkey" })).toBeVisible();
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();

  await page.getByLabel("Code from your authenticator app").fill(totp);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible();

  expect(mock.submissions.map((s) => s.method)).toEqual(["identifier", "password", "totp"]);
  for (const s of mock.submissions) expect(s.idempotencyKey).toMatch(/^[0-9a-f-]{36}$/);
});

// CR-40, X34, X-L1, TN-82
test("a refused first factor shows one neutral message and the same screen for every identifier", async ({
  page,
}) => {
  const screen = async (who: string) => {
    await page.goto("/");
    await page.getByLabel("Email or username").fill(who);
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByLabel("Password").fill("not it");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page.getByRole("alert")).toHaveText(neutral);
    return (await page.locator("main").ariaSnapshot()).replaceAll(who, "<identifier>");
  };
  const known = await screen("ada@example.org");
  const unknown = await screen("nobody@example.org");
  expect(unknown).toBe(known);
  const claims = enumerationClaims();
  expect(claims.length).toBeGreaterThan(0);
  for (const phrase of claims) expect(known.toLowerCase()).not.toContain(phrase);
});

// TN-106
test("only the fields the step offered are submitted", async ({ page, mock }) => {
  await page.goto("/");
  await page.getByLabel("Email or username").fill("ada@example.org");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByLabel("Email or username")).toHaveValue("ada@example.org");
  await page.getByLabel("Password").fill("not it");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("alert")).toHaveText(neutral);
  expect(mock.submissions[1]).toMatchObject({ method: "password", fields: { password: "not it" } });
  expect(Object.keys(mock.submissions[1]?.fields ?? {})).toEqual(["password"]);
});

// TN-132
test("a different account restarts at the identifier", async ({ page, mock }) => {
  await page.goto("/");
  await page.getByLabel("Email or username").fill("ada@example.org");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: "Use a different account" }).click();
  await expect(page.getByLabel("Email or username")).toHaveValue("");
  expect(mock.submissions.at(-1)).toMatchObject({ method: "restart", fields: {} });
});

// TN-102
test("an expired flow starts again with a message", async ({ page, mock }) => {
  await page.goto("/?flow=lgf_gone");
  await expect(page.getByRole("alert")).toHaveText("This sign-in page has expired. Start again.");
  await expect(page.getByLabel("Email or username")).toBeVisible();
  expect(mock.requests).toEqual(["GET /v1/login/flows/lgf_gone", "POST /v1/login/flows"]);
  await expect(page).toHaveURL(/flow=lgf_example/);
});

// TN-44, RFC 9470, X-L3: the authorization request's step-up reason re-authenticates the live
// session in place; without one the page signs in afresh, and no reason asks for nothing
test("a step-up reason re-authenticates the live session", async ({ page, mock }) => {
  mock.session = true;
  await page.goto("/?reason=step_up&acr=http%3A%2F%2Fidmanagement.gov%2Fns%2Fassurance%2Faal%2F2");
  await expect(page.getByRole("button", { name: "Sign in with a passkey" })).toBeVisible();
  expect(mock.requests).toContain("POST /v1/login/step-up");
  expect(mock.requests).not.toContain("POST /v1/login/flows");
  expect(mock.stepUps).toEqual([{ max_age: 0, acr: "http://idmanagement.gov/ns/assurance/aal/2" }]);
});

test("a step-up without a session signs in afresh", async ({ page, mock }) => {
  await page.goto("/?reason=reauthenticate");
  await expect(page.getByLabel("Email or username")).toBeVisible();
  expect(mock.requests).toEqual(["POST /v1/login/step-up", "POST /v1/login/flows"]);
  expect(mock.stepUps).toEqual([{ max_age: 0 }]);
});

test("a plain sign-in never asks for a step-up", async ({ page, mock }) => {
  mock.session = true;
  await page.goto("/");
  await expect(page.getByLabel("Email or username")).toBeVisible();
  expect(mock.requests).not.toContain("POST /v1/login/step-up");
});
