// OP-153 m.3 (gg): one sign-in for every @live test of this package, so the hosted login's rate
// limits see one person signing in once.
import { request as http, test as setup } from "@playwright/test";

import { OWN_DEVICE_SESSION, SESSION } from "./session.js";
import { PASSWORD, signIn } from "./signin.js";

setup("the bootstrap test user signs in once", async ({ request, baseURL }) => {
  setup.skip(
    PASSWORD === "",
    "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user's password",
  );
  // TN-59: up to one TOTP step of waiting for each of the two sign-ins
  setup.setTimeout(150_000);
  await signIn(request, baseURL ?? "");
  await request.storageState({ path: SESSION });
  // the realm accepts each TOTP step once: the second sign-in waits for the next one
  const own = await http.newContext({ baseURL: baseURL ?? "", ignoreHTTPSErrors: true });
  await signIn(own, baseURL ?? "");
  await own.storageState({ path: OWN_DEVICE_SESSION });
  await own.dispose();
});
