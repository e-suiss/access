// §9.4 G, §9.4.1, OP-156 m.3 (g): Secure Payment Confirmation on the Approval Surface. The page
// opens the pushed request, shows the payee and total the decision point's canonical render
// produced, and asks the browser for a `payment.get` assertion over H(AAS) with exactly those
// values; the server refuses any other bytes. Without SPC in the browser or the request, it is a
// passkey assertion over the same statement.
import { useEffect, useRef, useState } from "react";

import { Button } from "@suiss/access-ui/components/ui/button";

import { under } from "./base.js";
import { follow } from "./http.js";
import { t } from "./i18n.js";
import { note, Panel, primary, problem, stack, Title } from "./Layout.js";

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

  if (state.phase === "loading") {
    return (
      <Panel>
        <p role="status" className={note}>
          …
        </p>
      </Panel>
    );
  }
  if (state.phase !== "ready") {
    return (
      <Panel>
        <section className={stack}>
          <Title ref={title}>{t("spc.title")}</Title>
          <p role="alert" className={problem} data-testid="spc-refused">
            {state.phase === "mismatch" ? t("spc.mismatch") : t("error.access_owner")}
          </p>
        </section>
      </Panel>
    );
  }
  const spc = state.started.spc;
  return (
    <Panel>
      <section className={stack}>
        <Title ref={title}>{t("spc.title")}</Title>
        {spc !== undefined && (
          <dl
            data-testid="spc-details"
            className="flex flex-col gap-1 rounded-lg bg-muted px-4 py-3"
          >
            <dt className="font-medium">{spc.payeeName}</dt>
            <dd className="text-2xl font-semibold tabular-nums">{`${spc.total.value} ${spc.total.currency}`}</dd>
          </dl>
        )}
        <Button
          {...primary}
          disabled={busy}
          onPress={() => {
            void confirm(state.started);
          }}
        >
          {t("spc.title")}
        </Button>
      </section>
    </Panel>
  );
}
