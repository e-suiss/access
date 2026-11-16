// §17.9.6, TN-133: an environment is reached by its own host or under `/env/{slug}`; the pages and
// every Frontend API call they make stay under the same prefix.

const SLUG = /^\/env\/([a-z0-9-]+)\/(?:login|device)(?:\/|$)/.exec(window.location.pathname)?.[1];

/** The environment prefix: empty at a host issuer, `/env/{slug}` at a path one. */
export const ENVIRONMENT = SLUG === undefined ? "" : `/env/${SLUG}`;

/** The hosted pages' root. */
export const LOGIN = `${ENVIRONMENT}/login`;

/** An environment path (`/v1/...`, `/login/...`) under the environment's prefix. */
export function under(path: string): string {
  return `${ENVIRONMENT}${path}`;
}
