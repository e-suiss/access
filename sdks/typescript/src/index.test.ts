import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { loadKernel } from "./index.js";

describe("loadKernel", () => {
  it("returns the Kernel API version computed by the Wasm module", async () => {
    const bytes = await readFile(new URL("../wasm/access_kernel_wasm_bg.wasm", import.meta.url));
    const kernel = await loadKernel(bytes);
    expect(kernel.apiVersion()).toBe("0.0");
  });

  it("loads the module only once", async () => {
    const bytes = await readFile(new URL("../wasm/access_kernel_wasm_bg.wasm", import.meta.url));
    expect(await loadKernel(bytes)).toBe(await loadKernel());
  });
});
