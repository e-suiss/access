// §17.9.6, TN-133: a realm is reached by its own host or under `/realms/{slug}`; the pages and
// every Frontend API call they make stay under the same prefix.

const SLUG = /^\/realms\/([a-z0-9-]+)\/(?:login|device)(?:\/|$)/.exec(
  window.location.pathname,
)?.[1];

/** The realm prefix: empty at a host issuer, `/realms/{slug}` at a path one. */
export const REALM = SLUG === undefined ? "" : `/realms/${SLUG}`;

/** The hosted pages' root. */
export const LOGIN = `${REALM}/login`;

/** A realm path (`/v1/...`, `/login/...`) under the realm's prefix. */
export function under(path: string): string {
  return `${REALM}${path}`;
}
