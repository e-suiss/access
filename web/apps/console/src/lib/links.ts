// OP-159 m.42 (d), TN-113: an environment's console address as people share it.

/** The console's base path; no address ends in `/`. */
export const BASE = "/console";

/** An environment's console address on this origin. */
export function consoleLink(environment: string): string {
  return `${location.origin}${BASE}/${encodeURIComponent(environment)}`;
}
