// TN-128, OP-159 m.42 (a), (b), m.46 (d): the console session as the BFF answers it. The read is kept
// for the page's life; signing in or out, or registering this browser, reads it again.
import { type QueryClient, queryOptions } from "@tanstack/react-query";
import * as v from "valibot";

import { call, Problem, problemOf, SessionInfo, send } from "./api.js";
import { clearSignInStarted, rememberEnvironment } from "./remember.js";

export type SessionState =
  | {
      readonly status: "signed-out";
      readonly reason: string | undefined;
      readonly signedOut: boolean;
    }
  | { readonly status: "unavailable" }
  | { readonly status: "signed-in"; readonly session: SessionInfo };

const KEY = ["session"] as const;

async function read(): Promise<SessionState> {
  try {
    const r = await call("/session");
    if (!r.ok) throw await problemOf(r);
    const session = v.parse(SessionInfo, await r.json());
    rememberEnvironment(session.environment);
    clearSignInStarted();
    return { status: "signed-in", session };
  } catch (e: unknown) {
    if (e instanceof Problem && e.status === 401) {
      return { status: "signed-out", reason: e.reason, signedOut: false };
    }
    return { status: "unavailable" };
  }
}

export const sessionQuery = queryOptions({
  queryKey: KEY,
  queryFn: read,
  staleTime: Number.POSITIVE_INFINITY,
});

/** Signs out; every read of the session ends with it, the probes' answers too. */
export async function signOut(client: QueryClient): Promise<void> {
  try {
    await send("/sign-out", { method: "POST" });
    client.removeQueries({ predicate: (q) => q.queryKey[0] !== KEY[0] });
    const out: SessionState = { status: "signed-out", reason: undefined, signedOut: true };
    client.setQueryData<SessionState>(KEY, out);
  } catch {
    client.setQueryData<SessionState>(KEY, { status: "unavailable" });
  }
}

/** Reads the session again, as after this browser registered its device Instance. */
export function reloadSession(client: QueryClient): Promise<void> {
  return client.invalidateQueries({ queryKey: KEY });
}
