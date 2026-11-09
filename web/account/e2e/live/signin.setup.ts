// OP-153 m.3 (gg): one sign-in for every @live test of this package, so the hosted login's rate
// limits see one person signing in once.
import { test as setup } from "@playwright/test";

import { SESSION } from "./session.js";
import { PASSWORD, signIn } from "./signin.js";

setup("the bootstrap test user signs in once", async ({ request, baseURL }) => {
  setup.skip(
    PASSWORD === "",
    "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user's password",
  );
  // TN-59: up to one TOTP step of waiting
  setup.setTimeout(90_000);
  await signIn(request, baseURL ?? "");
  await request.storageState({ path: SESSION });
});
