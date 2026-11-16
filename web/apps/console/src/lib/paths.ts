// OP-159 m.42, TN-113
import { API } from "./api.js";

/** The console's own page, which names no environment. */
export const HOME = "/console";

const BASE = "/console/";

const SLUG = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;

// OP-159 m.42 (e)
const RESERVED: ReadonlySet<string> = new Set(["api", "assets"]);

const LAST_ENVIRONMENT = "access-console-environment";

// OP-159 m.43 (b)
const KNOWN_ENVIRONMENTS = "access-console-environments";

/** How many environments this browser signed in to the console keeps. */
const MAX_KNOWN = 12;

const SIGN_IN_STARTED = "access-console-sign-in";

/** How long a started sign-in keeps the console from starting another on its own. */
const SIGN_IN_GRACE_MS = 60_000;

/** Whether `s` can name an environment in a console address. */
export function isEnvironment(s: string): boolean {
  return SLUG.test(s) && !RESERVED.has(s);
}

/** The address of `route` (`""`, `admin`, `admin/roles`, …) in `environment`'s console. */
export function consoleHref(environment: string, route = ""): string {
  const base = `${BASE}${encodeURIComponent(environment)}`;
  return route === "" ? base : `${base}/${route}`;
}

/** An environment's console address as people share it, on this origin. */
export function consoleLink(environment: string): string {
  return `${location.origin}${consoleHref(environment)}`;
}

/** The environment `path` names and the rest after it; `undefined` when it names none. */
export function splitPath(path: string): {
  readonly environment: string | undefined;
  readonly rest: string;
} {
  if (!path.startsWith(BASE)) return { environment: undefined, rest: "" };
  const [head = "", ...rest] = path.slice(BASE.length).split("/");
  if (!isEnvironment(head)) return { environment: undefined, rest: "" };
  return { environment: head, rest: rest.join("/") };
}

/** The environment this browser last signed in to, if it remembers one (OP-159 m.42 (b)). */
export function lastEnvironment(): string | undefined {
  try {
    const r = localStorage.getItem(LAST_ENVIRONMENT);
    return r !== null && isEnvironment(r) ? r : undefined;
  } catch {
    return undefined;
  }
}

/** The environments this browser signed in to, the latest first (OP-159 m.43 (b)). */
export function knownEnvironments(): readonly string[] {
  try {
    const v: unknown = JSON.parse(localStorage.getItem(KNOWN_ENVIRONMENTS) ?? "[]");
    if (!Array.isArray(v)) return [];
    const out: string[] = [];
    for (const r of v) {
      if (typeof r === "string" && isEnvironment(r) && !out.includes(r)) out.push(r);
    }
    return out.slice(0, MAX_KNOWN);
  } catch {
    return [];
  }
}

/** Remembers `environment` as the one this browser last signed in to, and among those it signed in to. */
export function rememberEnvironment(environment: string): void {
  try {
    localStorage.setItem(LAST_ENVIRONMENT, environment);
  } catch {
    // OP-159 m.42 (b)
  }
  try {
    const known = [environment, ...knownEnvironments().filter((r) => r !== environment)].slice(
      0,
      MAX_KNOWN,
    );
    localStorage.setItem(KNOWN_ENVIRONMENTS, JSON.stringify(known));
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
// governs the redirect to the environment's hosted login on another origin
/** Starts the sign-in of `environment` at its hosted login. */
export function startSignIn(environment: string): void {
  noteSignInStarted();
  window.location.assign(`${API}/sign-in?environment=${encodeURIComponent(environment)}`);
}
