// OP-158 m.3 (e), (t), XI-20, X14, §6.4, §7.9.14, §8.7, §8.13
/** Who answers for a failure, as `conformance/catalog/failure-ownership.toml` names them. */
export type Owner =
  "access" | "operator" | "domain" | "idp" | "relay" | "executor" | "provider" | "verifier";

/** A failure the surface is in, with what is not known and what holds until it is. */
export interface Degraded {
  /** The failure row, `FO-n`. */
  readonly id: string;
  readonly owner: Owner;
  /** What is not available yet, in the viewer's words. */
  readonly missing: string;
  /** The fail-closed default that holds until it is known, in the viewer's words. */
  readonly safeDefault: string;
}

/** A recorded change and how far its acknowledgement got (SEC23, CL-2). */
export interface Recorded {
  /** Its position in the domain's log, as a decimal string. */
  readonly pos: string;
  /** `ack` of the answer, when the domain acknowledges this class. */
  readonly ack?: "pending" | "witnessed" | undefined;
  /** `witnessed_through` of the latest answer read, as a decimal string. */
  readonly witnessedThrough?: string | undefined;
}

function position(text: string | undefined): bigint | null {
  return text !== undefined && /^[0-9]{1,20}$/.test(text) ? BigInt(text) : null;
}

/** CL-2: confirmed only once a cosign covers the record; an unreadable position is not. */
export function witnessed(r: Recorded): boolean {
  if (r.ack === "pending") return false;
  const pos = position(r.pos);
  const through = position(r.witnessedThrough);
  if (pos === null) return false;
  if (through !== null) return through >= pos;
  return r.ack === "witnessed";
}
