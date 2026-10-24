// OP-8, OP-116
import init, {
  apiVersion,
  checkValidity,
  childWithinParent,
  evaluate,
  intentDigest,
  operationalKey,
  verifyConsistency,
  verifyCoseSign1,
  verifyInclusion,
  verifyJwsCompact,
  verifyMetadata,
  verifySdJwt,
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
