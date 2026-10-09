// OP-8
import init, { apiVersion } from "../wasm/access_kernel_wasm.js";

export type KernelSource = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface Kernel {
  readonly apiVersion: () => string;
}

let loading: Promise<Kernel> | undefined;

export function loadKernel(source?: KernelSource): Promise<Kernel> {
  loading ??= (source === undefined ? init() : init({ module_or_path: source })).then(
    (): Kernel => ({ apiVersion }),
    (error: unknown) => {
      loading = undefined;
      throw error;
    },
  );
  return loading;
}
