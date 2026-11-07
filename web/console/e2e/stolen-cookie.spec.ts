import { CSRF, COOKIE } from "./mock.js";
import { expect, test } from "./fixtures.js";

const BASE = "http://127.0.0.1:4173";

// TN-128, MD-14, OP-151 m.3 (e), (s): the console cookie copied into a browser without the
// IndexedDB key neither writes nor reads authority state; what it reads is Public only
test("a stolen cookie can neither write nor read authority state", async ({
  page,
  context,
  browser,
  bff,
}) => {
  await bff.signIn(context, BASE);
  bff.eligible.add("acc_ada");
  await page.goto("/console/");
  await page.getByRole("button", { name: "Register this browser" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(page.getByRole("link", { name: "Admin" })).toBeVisible();

  // the key is non-extractable: not even the page that made it can export it
  const exported = await page.evaluate(async () => {
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const r = indexedDB.open("access-console");
      r.onsuccess = () => {
        resolve(r.result);
      };
      r.onerror = () => {
        reject(new Error("idb"));
      };
    });
    const all = await new Promise<{ key: CryptoKey }[]>((resolve) => {
      const r = db.transaction("instances").objectStore("instances").getAll();
      r.onsuccess = () => {
        resolve(r.result as { key: CryptoKey }[]);
      };
    });
    const key = all[0]?.key;
    if (key === undefined) return "no key";
    try {
      await crypto.subtle.exportKey("pkcs8", key);
      return "exported";
    } catch {
      return `refused:${String(key.extractable)}`;
    }
  });
  expect(exported).toBe("refused:false");

  const stolen = (await context.cookies()).filter((c) => c.name === COOKIE || c.name === CSRF);
  const thief = await browser.newContext();
  await bff.install(thief);
  await thief.addCookies(stolen);
  const tp = await thief.newPage();
  await tp.goto(`${BASE}/console/`);
  await expect(tp.getByTestId("device-state")).toContainText("no device key");
  for (const name of ["Admin", "Developer", "Audit"]) {
    await expect(tp.getByRole("link", { name })).toHaveCount(0);
  }
  await expect(tp.getByRole("button", { name: "Register this browser" })).toHaveCount(0);

  const csrf = stolen.find((c) => c.name === CSRF)?.value ?? "";
  const answers = await tp.evaluate(async (token) => {
    const read = await fetch("/console/api/proxy/admin/realms/acme/clients");
    const write = await fetch("/console/api/proxy/admin/realms/acme/groups", {
      method: "POST",
      headers: { "content-type": "application/json", "x-csrf-token": token },
      body: "{}",
    });
    const forged = await fetch("/console/api/proxy/admin/realms/acme/clients", {
      headers: { "x-access-ais": "0oRDoQEmoFhAAAA" },
    });
    const search = await fetch("/console/api/proxy/adp/search/grants", {
      method: "POST",
      headers: { "content-type": "application/json", "x-csrf-token": token },
      body: JSON.stringify({ query: {} }),
    });
    return {
      read: read.status,
      write: write.status,
      forged: forged.status,
      search: (await search.json()) as { reader: string; results: { visibility: string }[] },
    };
  }, csrf);
  expect(answers.read).toBe(401);
  expect(answers.write).toBe(401);
  expect(answers.forged).toBe(403);
  expect(answers.search.reader).toBe("anonymous");
  expect(answers.search.results.every((r) => r.visibility === "public")).toBe(true);
  await thief.close();
});
