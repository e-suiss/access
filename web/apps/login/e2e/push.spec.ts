import { expect, test } from "./fixtures.js";
import { example, password } from "./mock.js";

// OP-156 m.3 (d), TN-102: the page shows the number; the push never carries it
test("a push shows the number to type and signs in once the approver answers", async ({
  page,
  mock,
}) => {
  const sent = example("push-sent");
  mock.pushPolls = 1;
  mock.secondFactor = example("second-factor-push");
  mock.pushSent = sent;
  await page.goto("/");
  await page.getByLabel("Email or username").fill("ada@example.org");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByRole("button", { name: "Send a request to my approver" }).click();
  await expect(page.getByTestId("push-number")).toHaveText("42");
  await expect(page.getByTestId("push-wait")).toContainText("Ada's phone");
  await expect(page.getByRole("status").first()).toContainText("Waiting for your answer");
  await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible();
  expect(mock.submissions.map((s) => s.method)).toEqual(["identifier", "password", "push"]);
});

// OP-156 m.3 (d): "This wasn't me" stops the sign-in
test("a push answered with this wasn't me stops the sign-in", async ({ page, mock }) => {
  mock.pushPolls = 0;
  mock.secondFactor = example("second-factor-push");
  mock.pushSent = example("push-sent");
  mock.pushEnd = example("push-stopped");
  await page.goto("/");
  await page.getByLabel("Email or username").fill("ada@example.org");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByRole("button", { name: "Send a request to my approver" }).click();
  await expect(page.getByRole("alert")).toContainText("We stopped this sign-in");
  await expect(page.getByTestId("push-wait")).toHaveCount(0);
});
