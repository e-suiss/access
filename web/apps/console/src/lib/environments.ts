// OP-159 m.43 (b), TN-119, IA-5: the environments a platform viewer can go to, from the platform
// surface's metadata. Going there opens that environment's console; what it shows still comes from that
// environment's own probes.
import { queryOptions, skipToken } from "@tanstack/react-query";
import * as v from "valibot";

import { adminGet, items } from "./admin.js";
import type { Instance } from "./instance.js";
import { isEnvironment } from "./remember.js";

const Tenants = items(v.looseObject({ tenant_id: v.string() }));

const Slugs = items(v.looseObject({ slug: v.string() }));

/** The slugs of every tenant's environments the platform surface lists; none when it lists nothing. */
async function platformEnvironments(instance: Instance): Promise<readonly string[]> {
  try {
    const tenants = await adminGet(instance, "platform/tenants", Tenants);
    const lists = await Promise.all(
      tenants.items.map((x) =>
        adminGet(instance, `platform/tenants/${encodeURIComponent(x.tenant_id)}/envs`, Slugs).then(
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

// OP-159 m.46 (d)
/** The platform's environment list for the switcher, read again at most every few minutes. */
export function platformEnvironmentsQuery(instance: Instance | undefined, environment: string) {
  return queryOptions({
    queryKey: ["platform-environments", environment, instance?.id] as const,
    queryFn: instance === undefined ? skipToken : () => platformEnvironments(instance),
    staleTime: 300_000,
  });
}
