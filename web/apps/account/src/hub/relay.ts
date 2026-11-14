// §8.13 "Relay delayed", OP-156 m.11 (e), INV-24, E30: Access's public relay status. A delay is
// only a notice; authority never waits on delivery, so no row reads as pending because of it.

/** Relay's delivery as Access reports it. */
export interface RelayStatus {
  readonly delayed: boolean;
  readonly lagMs?: number;
}

/** `GET /access/v1/relay-status`, or `undefined` when Access does not answer it. */
export async function relayStatus(): Promise<RelayStatus | undefined> {
  try {
    const r = await fetch("/access/v1/relay-status", {
      headers: { accept: "application/json" },
      cache: "no-store",
      credentials: "omit",
    });
    if (!r.ok) return undefined;
    const v = (await r.json()) as { relay_lag_ms?: unknown; notifications_delayed?: unknown };
    if (typeof v.notifications_delayed !== "boolean") return undefined;
    return {
      delayed: v.notifications_delayed,
      ...(typeof v.relay_lag_ms === "number" ? { lagMs: v.relay_lag_ms } : {}),
    };
  } catch {
    return undefined;
  }
}
