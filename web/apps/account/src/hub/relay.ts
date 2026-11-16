// §8.13 "Relay delayed", OP-156 m.11 (e), INV-24, E30: Access's public relay status. A delay is
// only a notice; authority never waits on delivery, so no row reads as pending because of it.
import * as v from "valibot";

const Answer = v.object({
  notifications_delayed: v.boolean(),
  relay_lag_ms: v.fallback(v.optional(v.number()), undefined),
});

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
    const a = v.safeParse(Answer, await r.json());
    if (!a.success) return undefined;
    const { notifications_delayed: delayed, relay_lag_ms: lagMs } = a.output;
    return lagMs === undefined ? { delayed } : { delayed, lagMs };
  } catch {
    return undefined;
  }
}
