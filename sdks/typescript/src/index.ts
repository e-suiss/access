// OP-8, OP-116
import init, {
  aisProtected,
  aisStatement,
  apiVersion,
  checkValidity,
  childWithinParent,
  coseKeyP256,
  coseSign1,
  coseToBeSigned,
  describeIntent,
  describeStatement,
  evaluate,
  exerciseBasis,
  intentDigest,
  operationalKey,
  receiptPosition,
  statusLookup,
  verifyCheckpoint,
  verifyConsistency,
  verifyCoseSign1,
  verifyInclusion,
  verifyJwsCompact,
  verifyMetadata,
  verifyPap,
  verifyReceipt,
  verifyReport,
  verifySdJwt,
  thumbprintP256,
} from "../wasm/access_kernel_wasm.js";

export type KernelSource = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

const kernel = {
  apiVersion,
  evaluate,
  childWithinParent,
  intentDigest,
  verifyCoseSign1,
  verifyMetadata,
  operationalKey,
  verifyJwsCompact,
  verifySdJwt,
  checkValidity,
  verifyInclusion,
  verifyConsistency,
  verifyPap,
  verifyReceipt,
  // §9.5.2 k.6: the verified receipt names this nonce's Exercise
  receiptPosition,
  verifyReport,
  statusLookup,
  verifyCheckpoint,
  // OP-151 m.3 (e): what a browser needs to sign an AIS with its own key
  aisStatement,
  exerciseBasis,
  aisProtected,
  coseToBeSigned,
  coseSign1,
  coseKeyP256,
  thumbprintP256,
  describeStatement,
  describeIntent,
};

/** Kernel functions over canonical CBOR bytes; a failure throws an `Error` whose message is the stable name. */
export type Kernel = Readonly<typeof kernel>;

let loading: Promise<Kernel> | undefined;

export function loadKernel(source?: KernelSource): Promise<Kernel> {
  loading ??= (source === undefined ? init() : init({ module_or_path: source })).then(
    (): Kernel => kernel,
    (error: unknown) => {
      loading = undefined;
      throw error;
    },
  );
  return loading;
}

/** Largest inflated status list, in bytes, as the Rust verifier SDK (OP-150 m.6 (d)). */
export const MAX_STATUS_LIST_BYTES = 4 * 1024 * 1024;

/**
 * Inflates the ZLIB `lst` of a Token Status List (RFC 1950) for `statusLookup`. A list larger
 * than `MAX_STATUS_LIST_BYTES` or that is not ZLIB data throws `status-compression`.
 */
export async function inflateStatusList(lst: Uint8Array): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    const stream = new Blob([Uint8Array.from(lst)])
      .stream()
      .pipeThrough(new DecompressionStream("deflate"));
    for await (const chunk of stream) {
      size += chunk.length;
      if (size > MAX_STATUS_LIST_BYTES) throw new RangeError("too large");
      chunks.push(chunk);
    }
  } catch {
    throw new Error("status-compression");
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

// CMP-17, T41: `auth` (identity) and `authorize` (PEP), kept apart in code
export * as auth from "./auth.js";
export * as authorize from "./authorize.js";
export * as reason from "./reason.js";
export type * as AccessApi from "./generated/access-v1.js";
export type * as AdminApi from "./generated/admin-v1.js";
export type * as FrontendApi from "./generated/frontend.js";
export type * as LoginApi from "./generated/login.js";
export type * as ExperienceApi from "./generated/experience-v1.js";
