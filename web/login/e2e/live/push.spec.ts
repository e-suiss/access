// OP-156 m.3 (d), OP-153 m.3 (gg): push verification against the running local deployment, through
// its real router; nothing here is mocked. The waiting page itself needs a realm with push on and
// an approver, so here the routes answer as served and refuse what they must.
import { expect, test } from "@playwright/test";

const REALM = process.env["ACCESS_LIVE_REALM"] ?? "/realms/acme";

test.describe("@live push verification", () => {
  test("@live a push needs a flow at its second step and an answer needs an approver's signature", async ({
    page,
  }) => {
    const r = await page.goto(`${REALM}/login`);
    expect(r?.status()).toBe(200);
    const origin = new URL(page.url()).origin;
    const flow = await page.request.post(`${REALM}/v1/login/flows`, {
      headers: {
        origin,
        "content-type": "application/json",
        "idempotency-key": crypto.randomUUID(),
      },
    });
    expect(flow.status()).toBe(201);
    const handle = ((await flow.json()) as { flow: string }).flow;
    const push = await page.request.post(`${REALM}/v1/push/challenge`, {
      data: { flow: handle },
      headers: { origin, "idempotency-key": crypto.randomUUID() },
    });
    expect(push.status()).not.toBe(501);
    expect(push.status()).toBeGreaterThanOrEqual(400);
    const answer = await page.request.post(`${REALM}/v1/push/answer`, {
      data: { answer: "AA", signature: "AA" },
      headers: { origin },
    });
    expect(answer.status()).toBe(400);
    expect(((await answer.json()) as { code: string }).code).toBe("invalid-push-answer");
    const approvers = await page.request.get(`${REALM}/v1/approvers`);
    expect(approvers.status()).toBe(401);
  });
});
