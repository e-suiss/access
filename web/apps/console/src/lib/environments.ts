// OP-159 m.43 (b), TN-119, IA-5: the environments a platform viewer can go to, from the platform
// surface's metadata. Going there opens that environment's console; what it shows still comes from that
// environment's own probes.
import { adminGet } from "./admin.js";
import type { Instance } from "./instance.js";
import { isEnvironment } from "./paths.js";

interface Items<T> {
  readonly items: readonly T[];
}

/** The slugs of every tenant's environments the platform surface lists; none when it lists nothing. */
export async function platformEnvironments(instance: Instance): Promise<readonly string[]> {
  try {
    const tenants = await adminGet<Items<{ readonly tenant_id: string }>>(
      instance,
      "platform/tenants",
    );
    const lists = await Promise.all(
      tenants.items.map((x) =>
        adminGet<Items<{ readonly slug: string }>>(
          instance,
          `platform/tenants/${encodeURIComponent(x.tenant_id)}/envs`,
        ).then(
          (r) => r.items.map((m) => m.slug),
          () => [],
        ),
      ),
    );
    return [...new Set(lists.flat().filter(isEnvironment))].sort();
  } catch {
    return [];
  }
}
