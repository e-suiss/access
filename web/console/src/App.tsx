import { loadKernel } from "@suiss/access";
import { useEffect, useState } from "react";

type KernelState =
  | { readonly status: "loading" }
  | { readonly status: "ready"; readonly apiVersion: string }
  | { readonly status: "failed" };

export function App() {
  const [kernel, setKernel] = useState<KernelState>({ status: "loading" });

  useEffect(() => {
    let active = true;
    loadKernel().then(
      (loaded) => {
        if (active) setKernel({ status: "ready", apiVersion: loaded.apiVersion() });
      },
      () => {
        if (active) setKernel({ status: "failed" });
      },
    );
    return () => {
      active = false;
    };
  }, []);

  return (
    <>
      <header>
        <p className="brand">Access</p>
      </header>
      <main>
        <h1>Console</h1>
        <dl aria-live="polite" aria-busy={kernel.status === "loading"}>
          <dt>Kernel API version</dt>
          <dd data-testid="kernel-api-version">
            {kernel.status === "ready"
              ? kernel.apiVersion
              : kernel.status === "loading"
                ? "Loading…"
                : "Unavailable"}
          </dd>
        </dl>
      </main>
    </>
  );
}
