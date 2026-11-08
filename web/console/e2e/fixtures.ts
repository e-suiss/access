import { test as base, expect } from "@playwright/test";

import { ConsoleMock } from "./mock.js";

// A refused BFF call (401, 403, 422) is an expected answer the console handles; the browser still
// logs it as a failed resource, which is not a page error.
const EXPECTED =
  /^Failed to load resource: the server responded with a status of (401|403|409|422|503)/;

export const test = base.extend<{ pageErrors: string[]; bff: ConsoleMock }>({
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
      const mock = new ConsoleMock();
      await mock.install(context);
      await provide(mock);
    },
    { auto: true },
  ],
});

export { expect };
