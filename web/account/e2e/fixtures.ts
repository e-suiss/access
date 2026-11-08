import { test as base, expect } from "@playwright/test";

import { AccountMock } from "./mock.js";

// A refused call (401, 403, 409) is an answer the page handles; the browser still logs it.
const EXPECTED =
  /^Failed to load resource: (the server responded with a status of (401|403|409|503)|net::ERR_CONNECTION_RESET)/;

export const test = base.extend<{ pageErrors: string[]; bff: AccountMock }>({
  pageErrors: [
    async ({ page }, use) => {
      const errors: string[] = [];
      page.on("console", (message) => {
        if (message.type() === "error" && !EXPECTED.test(message.text())) {
          errors.push(message.text());
        }
      });
      page.on("pageerror", (error) => {
        errors.push(error.message);
      });
      await use(errors);
      expect(errors).toEqual([]);
    },
    { auto: true },
  ],
  bff: [
    async ({ context }, provide) => {
      const mock = new AccountMock();
      await mock.install(context);
      await provide(mock);
    },
    { auto: true },
  ],
});

export { expect };
