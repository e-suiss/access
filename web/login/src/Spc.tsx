// §9.4 G, §9.4.1, OP-156 m.3 (g): Secure Payment Confirmation on the Approval Surface. The page
// opens the pushed request, shows the payee and total the decision point's canonical render
// produced, and asks the browser for a `payment.get` assertion over H(AAS) with exactly those
// values; the server refuses any other bytes. Without SPC in the browser or the request, it is a
// passkey assertion over the same statement.
import { useEffect, useRef, useState } from "react";

import { under } from "./base.js";
import { follow } from "./http.js";
import { t } from "./i18n.js";

/** What `POST /v1/approve/flows` answers. */
export interface SpcStarted {
  readonly flow: string;
  readonly options: {
    readonly challenge: string;
    readonly rpId: string;
    readonly timeout?: number;
    readonly allowCredentials: readonly { readonly id: string }[];
  };
  readonly spc?: {
    readonly payeeName: string;
    readonly payeeOrigin?: string;
    readonly total: { readonly currency: string; readonly value: string };
    readonly instrument: { readonly displayName: string; readonly icon: string };
  };
}

type State =
  | { readonly phase: "loading" }
  | { readonly phase: "ready"; readonly started: SpcStarted }
  | { readonly phase: "mismatch" }
  | { readonly phase: "failed" };

function bytes(b64url: string): Uint8Array<ArrayBuffer> {
  const s = atob(b64url.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

async function call(path: string, body: unknown): Promise<Response> {
  return fetch(under(path), {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      "idempotency-key": crypto.randomUUID(),
    },
    body: JSON.stringify(body),
  });
}

/** The `secure-payment-confirmation` request of a started flow. */
export function paymentRequest(started: SpcStarted): PaymentRequest | null {
  const spc = started.spc;
  if (spc === undefined || typeof PaymentRequest === "undefined") return null;
  const data = {
    rpId: started.options.rpId,
    challenge: bytes(started.options.challenge),
    credentialIds: started.options.allowCredentials.map((c) => bytes(c.id)),
    payeeName: spc.payeeName,
    ...(spc.payeeOrigin === undefined ? {} : { payeeOrigin: spc.payeeOrigin }),
    instrument: { ...spc.instrument, iconMustBeShown: false },
    timeout: started.options.timeout ?? 300000,
  };
  return new PaymentRequest([{ supportedMethods: "secure-payment-confirmation", data }], {
    total: { label: "Total", amount: spc.total },
  });
}

async function assertion(started: SpcStarted): Promise<PublicKeyCredential | null> {
  const request = paymentRequest(started);
  if (request !== null) {
    const response = await request.show().catch(() => null);
    if (response === null) return null;
    await response.complete("success").catch(() => undefined);
    return response.details as PublicKeyCredential;
  }
  const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(
    started.options as unknown as PublicKeyCredentialRequestOptionsJSON,
  );
  return (await navigator.credentials
    .get({ publicKey })
    .catch(() => null)) as PublicKeyCredential | null;
}

export function Spc() {
  const q = new URLSearchParams(window.location.search);
  const call_ = {
    request: q.get("request") ?? "",
    redirect_uri: q.get("redirect_uri") ?? "",
    state: q.get("state") ?? "",
  };
  const [state, setState] = useState<State>({ phase: "loading" });
  const [busy, setBusy] = useState(false);
  const title = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    void call("/v1/approve/flows", call_).then(async (r) => {
      // OP-157 m.3 (l)
      if (r.status === 201) setState({ phase: "ready", started: (await r.json()) as SpcStarted });
      else setState({ phase: "failed" });
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (state.phase !== "loading") title.current?.focus();
  }, [state.phase]);

  const confirm = async (started: SpcStarted) => {
    setBusy(true);
    const cred = await assertion(started);
    if (cred === null) {
      setBusy(false);
      return;
    }
    const r = await call(`/v1/approve/flows/${encodeURIComponent(started.flow)}`, {
      credential: cred.toJSON(),
      redirect_uri: call_.redirect_uri,
      state: call_.state,
    });
    const out = (await r.json().catch(() => ({}))) as { redirect?: string; code?: string };
    setBusy(false);
    if (r.ok && out.redirect !== undefined) follow(out.redirect);
    else setState({ phase: out.code === "spc-mismatch" ? "mismatch" : "failed" });
  };

  if (state.phase === "loading") return <p role="status">…</p>;
  if (state.phase !== "ready") {
    return (
      <section>
        <h1 ref={title} tabIndex={-1}>
          {t("spc.title")}
        </h1>
        <p role="alert" data-testid="spc-refused">
          {state.phase === "mismatch" ? t("spc.mismatch") : t("error.access_owner")}
        </p>
      </section>
    );
  }
  const spc = state.started.spc;
  return (
    <section>
      <h1 ref={title} tabIndex={-1}>
        {t("spc.title")}
      </h1>
      {spc !== undefined && (
        <dl data-testid="spc-details">
          <dt>{spc.payeeName}</dt>
          <dd>{`${spc.total.value} ${spc.total.currency}`}</dd>
        </dl>
      )}
      <button
        type="button"
        disabled={busy}
        onClick={() => {
          void confirm(state.started);
        }}
      >
        {t("spc.title")}
      </button>
    </section>
  );
}
