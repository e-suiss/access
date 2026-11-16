// OP-159 m.42, TN-113
import { API } from "./api.js";

/** The console's own page, which names no realm. */
export const HOME = "/console";

const BASE = "/console/";

const SLUG = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;

// OP-159 m.42 (e)
const RESERVED: ReadonlySet<string> = new Set(["api", "assets"]);

const LAST_REALM = "access-console-realm";

// OP-159 m.43 (b)
const KNOWN_REALMS = "access-console-realms";

/** How many realms this browser signed in to the console keeps. */
const MAX_KNOWN = 12;

const SIGN_IN_STARTED = "access-console-sign-in";

/** How long a started sign-in keeps the console from starting another on its own. */
const SIGN_IN_GRACE_MS = 60_000;

/** Whether `s` can name a realm in a console address. */
export function isRealm(s: string): boolean {
  return SLUG.test(s) && !RESERVED.has(s);
}

/** The address of `route` (`""`, `admin`, `admin/roles`, …) in `realm`'s console. */
export function consoleHref(realm: string, route = ""): string {
  const base = `${BASE}${encodeURIComponent(realm)}`;
  return route === "" ? base : `${base}/${route}`;
}

/** A realm's console address as people share it, on this origin. */
export function consoleLink(realm: string): string {
  return `${location.origin}${consoleHref(realm)}`;
}

/** The realm `path` names and the rest after it; `undefined` when it names none. */
export function splitPath(path: string): {
  readonly realm: string | undefined;
  readonly rest: string;
} {
  if (!path.startsWith(BASE)) return { realm: undefined, rest: "" };
  const [head = "", ...rest] = path.slice(BASE.length).split("/");
  if (!isRealm(head)) return { realm: undefined, rest: "" };
  return { realm: head, rest: rest.join("/") };
}

/** The realm this browser last signed in to, if it remembers one (OP-159 m.42 (b)). */
export function lastRealm(): string | undefined {
  try {
    const r = localStorage.getItem(LAST_REALM);
    return r !== null && isRealm(r) ? r : undefined;
  } catch {
    return undefined;
  }
}

/** The realms this browser signed in to, the latest first (OP-159 m.43 (b)). */
export function knownRealms(): readonly string[] {
  try {
    const v: unknown = JSON.parse(localStorage.getItem(KNOWN_REALMS) ?? "[]");
    if (!Array.isArray(v)) return [];
    const out: string[] = [];
    for (const r of v) {
      if (typeof r === "string" && isRealm(r) && !out.includes(r)) out.push(r);
    }
    return out.slice(0, MAX_KNOWN);
  } catch {
    return [];
  }
}

/** Remembers `realm` as the one this browser last signed in to, and among those it signed in to. */
export function rememberRealm(realm: string): void {
  try {
    localStorage.setItem(LAST_REALM, realm);
  } catch {
    // OP-159 m.42 (b)
  }
  try {
    const known = [realm, ...knownRealms().filter((r) => r !== realm)].slice(0, MAX_KNOWN);
    localStorage.setItem(KNOWN_REALMS, JSON.stringify(known));
  } catch {
    // OP-159 m.43 (b)
  }
}

/** Notes that the console started a sign-in now. */
export function noteSignInStarted(): void {
  try {
    sessionStorage.setItem(SIGN_IN_STARTED, String(Date.now()));
  } catch {
    // OP-159 m.42 (a)
  }
}

/** Forgets a started sign-in. */
export function clearSignInStarted(): void {
  try {
    sessionStorage.removeItem(SIGN_IN_STARTED);
  } catch {
    // OP-159 m.42 (a)
  }
}

/** Whether the console started a sign-in a moment ago that did not end signed in. */
export function signInJustStarted(): boolean {
  try {
    const at = Number(sessionStorage.getItem(SIGN_IN_STARTED));
    return Number.isFinite(at) && at > 0 && Date.now() - at < SIGN_IN_GRACE_MS;
  } catch {
    return false;
  }
}

// TN-128, OP-159 m.29: a navigation, not a form submission, since `form-action 'self'` also
// governs the redirect to the realm's hosted login on another origin
/** Starts the sign-in of `realm` at its hosted login. */
export function startSignIn(realm: string): void {
  noteSignInStarted();
  window.location.assign(`${API}/sign-in?realm=${encodeURIComponent(realm)}`);
}
