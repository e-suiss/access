// OP-157 m.3 (v), m.6 (a), OP-153 m.3 (gg), §8.17.9.6: the offboarding routes against the
// running local deployment, through its real BFF on the management listener. Like every
// authority read they answer nothing without a session or this browser's device key, no commit
// reaches them unsigned, and the screen is not offered to a viewer who cannot exercise it.
import { expect, test } from "@playwright/test";

const PARTY = "AAAAAAAAAAAAAAAAAAAAAA";

test.describe("@live console offboarding", () => {
  test("@live the offboarding routes read and commit nothing without a session", async ({
    page,
  }) => {
    const preview = await page.request.get(
      `/console/api/proxy/admin/realms/acme/offboarding/${PARTY}/preview`,
    );
    expect([401, 403]).toContain(preview.status());
    const commit = await page.request.post(
      `/console/api/proxy/admin/realms/acme/offboarding/${PARTY}/commit`,
      {
        data: {
          choices: {
            grants: {},
            instances: {},
            holdings: {},
            self_anchor: "retire",
            reentry: "blocked",
          },
          operations: [],
        },
      },
    );
    expect([401, 403]).toContain(commit.status());
  });

  test("@live the offboarding screen is not offered without the viewer's eligibility", async ({
    page,
  }) => {
    const r = await page.goto("/console/admin/offboarding");
    expect(r?.status()).toBe(200);
    await expect(page.getByTestId("depart")).toHaveCount(0);
  });
});
