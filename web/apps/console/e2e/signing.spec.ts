// CR-41, CR-44, HL-27, OP-159 m.3 (g), (o), (r), (t)
import AxeBuilder from "@axe-core/playwright";

import { BASE, open } from "./data.js";
import { expect, test } from "./fixtures.js";

const PROFILE = 'section[aria-labelledby="signing-profile-title"]';

const VIEW = {
  signing_profile: null,
  algorithms: ["ES256"],
  kex_share: "optimistic",
  fips: false,
  fips_module: false,
  governing_domain: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  pq_reanchor: null,
};

test.beforeEach(async ({ context, bff }) => {
  await bff.signIn(context, BASE);
});

// CR-41, OP-159 m.3 (o), (t)
test("the signing screen turns the post-quantum profile on as one change", async ({
  page,
  bff,
}) => {
  bff.admin.set("realms/acme/signing", VIEW);
  await open(page, bff, "/console/admin/signing");
  await expect(page.getByRole("heading", { level: 2, name: "Signing" })).toBeVisible();
  await expect(page.locator("#signing-profile-title")).toHaveText("Classical signatures only");
  await expect(page.getByTestId("signing-algorithms")).toHaveText("ES256");
  await expect(page.getByTestId("signing-fips-module")).toHaveText("FIPS 140-3 module: not in use");
  await expect(page.getByTestId("signing-pq-anchor")).toHaveText("No post-quantum anchor yet");
  const panel = page.locator(PROFILE);
  await panel.getByLabel("ML-DSA-65").check();
  await panel.getByRole("button").click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(panel.getByRole("status")).toContainText("Recorded");
  expect(bff.writes.map((w) => [w.method, w.path, w.body["profile"]])).toEqual([
    ["PUT", "realms/acme/settings/signing-profile", "ml-dsa-65"],
  ]);
  const a11y = await new AxeBuilder({ page }).include("main").analyze();
  expect(a11y.violations).toEqual([]);
});

// CR-41, OP-159 m.3 (a), (g)
test("an open profile shows its algorithm and anchor and turns off as one change", async ({
  page,
  bff,
}) => {
  bff.admin.set("realms/acme/signing", {
    ...VIEW,
    signing_profile: "ml-dsa-65",
    algorithms: ["ES256", "ML-DSA-65"],
    kex_share: "advertise-only",
    pq_reanchor: { size: 42, time: 1_767_225_600_000, witnesses: ["witness.example"] },
  });
  await open(page, bff, "/console/admin/signing");
  await expect(page.locator("#signing-profile-title")).toHaveText(
    "Post-quantum signatures on (ML-DSA-65)",
  );
  await expect(page.getByTestId("signing-algorithms")).toHaveText("ES256, ML-DSA-65");
  await expect(page.getByTestId("signing-pq-anchor")).toContainText("log size 42");
  await page.getByTestId("signing-turn-off").click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(page.locator(PROFILE).getByRole("status")).toContainText("Recorded");
  expect(bff.writes.map((w) => [w.path, w.body])).toEqual([
    ["realms/acme/settings/signing-profile", expect.not.objectContaining({ profile: "" })],
  ]);
  expect(bff.writes[0]?.body["profile"]).toBeUndefined();
});

// CR-44, HL-27, OP-159 m.3 (r)
test("a FIPS realm cannot turn the post-quantum profile on", async ({ page, bff }) => {
  bff.admin.set("realms/acme/signing", { ...VIEW, fips: true });
  await open(page, bff, "/console/admin/signing");
  await expect(page.getByTestId("signing-fips-exclusive")).toHaveText(
    "FIPS and post-quantum profiles can't be combined",
  );
  await expect(page.locator(PROFILE).getByRole("radio")).toHaveCount(0);
  await expect(page.locator("main")).not.toContainText("validated");
});

// CR-18, TI-9, OP-159 m.3 (d)
test("without an HSM that holds post-quantum keys the refusal is said", async ({ page, bff }) => {
  bff.admin.set("realms/acme/signing", VIEW);
  bff.refuse.set("realms/acme/settings/signing-profile", [409, "pq-key-unavailable"]);
  await open(page, bff, "/console/admin/signing");
  const panel = page.locator(PROFILE);
  await panel.getByRole("button").click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(page.getByTestId("signing-refused")).toHaveText(
    "This HSM can't hold post-quantum keys, so post-quantum signatures can't be turned on.",
  );
  expect(bff.writes).toEqual([]);
});

// CR-12 m.3, OP-159 m.3 (t)
test("the key exchange share policy is one change", async ({ page, bff }) => {
  bff.admin.set("realms/acme/signing", VIEW);
  await open(page, bff, "/console/admin/signing");
  const kex = page.getByRole("region", { name: /Post-quantum key exchange/ });
  await kex.getByLabel("Send the classical key share first and offer post-quantum").check();
  await kex.getByRole("button").click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(kex.getByRole("status")).toContainText("Recorded");
  expect(bff.writes.map((w) => [w.path, w.body["mode"]])).toEqual([
    ["realms/acme/settings/kex-share", "advertise-only"],
  ]);
});
