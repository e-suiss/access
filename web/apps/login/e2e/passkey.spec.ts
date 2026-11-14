import { generateKeyPairSync } from "node:crypto";

import { addVirtualAuthenticator, expect, test } from "./fixtures.js";
import { example } from "./mock.js";

function pkcs8(): string {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
}

// OP-146 m.4 (g), §10.2.4, TN-96, TN-97, TN-99, CR-40
test("registers a passkey, then signs in with it from identifier autofill", async ({
  page,
  mock,
  webauthn,
}) => {
  const authenticator = await addVirtualAuthenticator(page);
  mock.flows.set("lgf_example", example("complete-passkey-offer"));

  await page.goto("/?flow=lgf_example");
  await page.getByRole("button", { name: "Create a passkey" }).click();
  await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible();

  const [stored] = await authenticator.credentials();
  expect(stored?.isResidentCredential).toBe(true);
  const registration = mock.submissions.at(-1);
  expect(registration?.method).toBe("passkey_register");
  const created = JSON.parse(registration?.fields.passkey_credential ?? "{}") as {
    id: string;
    type: string;
    response: { attestationObject?: string };
  };
  expect(created.type).toBe("public-key");
  expect(created.response.attestationObject).toBeTruthy();
  expect(mock.registered.has(created.id)).toBe(true);

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible();
  expect(webauthn.gets.at(-1)?.mediation).toBe("conditional");

  const assertion = JSON.parse(mock.submissions.at(-1)?.fields.passkey_credential ?? "{}") as {
    id: string;
    response: { userHandle?: string; signature?: string };
  };
  expect(assertion.id).toBe(created.id);
  expect(assertion.response.signature).toBeTruthy();
  expect(assertion.response.userHandle).toBeTruthy();
  expect(mock.submissions.some((s) => s.method === "identifier")).toBe(false);
});

// TN-96, TN-99, CR-40
test("signs in from the explicit passkey button where autofill is unavailable", async ({
  page,
  mock,
  webauthn,
}) => {
  await page.addInitScript(() => {
    PublicKeyCredential.isConditionalMediationAvailable = () => Promise.resolve(false);
  });
  const authenticator = await addVirtualAuthenticator(page);
  const raw = Buffer.from("known-credential-0001");
  await authenticator.cdp.send("WebAuthn.addCredential", {
    authenticatorId: authenticator.id,
    credential: {
      credentialId: raw.toString("base64"),
      isResidentCredential: true,
      rpId: "acme.localhost",
      privateKey: pkcs8(),
      userHandle: Buffer.from("user-handle-0001").toString("base64"),
      signCount: 0,
    },
  });
  mock.registered.add(raw.toString("base64url"));

  await page.goto("/");
  await expect(page.getByLabel("Email or username")).toBeVisible();
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible();
  expect(webauthn.gets.map((g) => g.mediation)).toEqual([null]);
  const assertion = JSON.parse(mock.submissions.at(-1)?.fields.passkey_credential ?? "{}") as {
    id: string;
    response: { userHandle?: string };
  };
  expect(assertion.id).toBe(raw.toString("base64url"));
  expect(assertion.response.userHandle).toBe(Buffer.from("user-handle-0001").toString("base64url"));
});

// TN-99, §10.2.4
test("offers passkeys in identifier autofill and aborts it for the explicit button", async ({
  page,
  mock,
  webauthn,
}) => {
  await addVirtualAuthenticator(page);
  await page.goto("/");
  await expect(page.getByLabel("Email or username")).toHaveAttribute(
    "autocomplete",
    "username webauthn",
  );
  await expect.poll(() => webauthn.gets.map((g) => g.mediation)).toEqual(["conditional"]);

  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect.poll(() => webauthn.gets.length).toBeGreaterThanOrEqual(2);
  await expect.poll(() => webauthn.gets[0]?.aborted).toBe(true);
  expect(webauthn.gets[1]?.mediation).toBeNull();
  expect(mock.submissions.filter((s) => s.method === "passkey")).toEqual([]);
});

// TN-97, §10.2.4, CR-40
test("tells the authenticator about an unknown credential after a failed passkey sign-in", async ({
  page,
  webauthn,
}) => {
  await page.addInitScript(() => {
    PublicKeyCredential.isConditionalMediationAvailable = () => Promise.resolve(false);
  });
  const authenticator = await addVirtualAuthenticator(page);
  const raw = Buffer.from("stale-credential-0001");
  await authenticator.cdp.send("WebAuthn.addCredential", {
    authenticatorId: authenticator.id,
    credential: {
      credentialId: raw.toString("base64"),
      isResidentCredential: true,
      rpId: "acme.localhost",
      privateKey: pkcs8(),
      userHandle: Buffer.from("user-handle-0001").toString("base64"),
      signCount: 0,
    },
  });

  await page.goto("/");
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(page.getByRole("alert")).toHaveText("We couldn't sign you in with these details.");
  await expect
    .poll(() => webauthn.signals)
    .toEqual([
      {
        name: "signalUnknownCredential",
        args: { rpId: "acme.localhost", credentialId: raw.toString("base64url") },
      },
    ]);
});

// TN-97, §10.2.4
test("after sign-in sends the full accepted list and user details, then tries conditional create", async ({
  page,
  mock,
  webauthn,
}) => {
  await addVirtualAuthenticator(page);
  const complete = example("complete");
  mock.flows.set("lgf_example", complete);
  await page.goto("/?flow=lgf_example");
  await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible();

  expect(webauthn.signals.map((s) => s.name).sort()).toEqual([
    "signalAllAcceptedCredentials",
    "signalCurrentUserDetails",
  ]);
  const all = webauthn.signals.find((s) => s.name === "signalAllAcceptedCredentials");
  const listed = complete.nodes.flatMap((n) =>
    n.type === "passkey_signal" && n.signal.kind === "all_accepted_credentials"
      ? n.signal.all_accepted_credential_ids
      : [],
  );
  expect(all?.args).toMatchObject({ rpId: "acme.localhost", allAcceptedCredentialIds: listed });
  const conditional = webauthn.creates.filter((c) => c.mediation === "conditional").length;
  const registered = mock.submissions.filter((s) => s.method === "passkey_register").length;
  expect(registered).toBeLessThanOrEqual(conditional);
});
