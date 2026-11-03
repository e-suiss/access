import { useEffect, useRef, useState, type SyntheticEvent } from "react";

import type {
  FieldName,
  InputNode,
  LoginUi,
  Method,
  PasskeyCreateNode,
  SubmitNode,
  Submission,
  UiNode,
} from "./contract.js";
import {
  conditionalCreateAvailable,
  conditionalGetAvailable,
  createPasskey,
  getPasskey,
  sendSignal,
} from "./passkey.js";

interface Props {
  readonly ui: LoginUi;
  readonly busy: boolean;
  readonly onSubmit: (submission: Submission) => void;
}

const htmlType = { text: "text", password: "password", code: "text" } as const;

function methodsInOrder(nodes: readonly UiNode[]): Method[] {
  const seen: Method[] = [];
  for (const node of nodes) {
    if ((node.type === "input" || node.type === "submit") && !seen.includes(node.method)) {
      seen.push(node.method);
    }
  }
  return seen;
}

function Field({ node }: { readonly node: InputNode }) {
  const id = `field-${node.name}-${node.method}`;
  return (
    <div className="field">
      <label htmlFor={id}>{node.label.text}</label>
      <input
        id={id}
        name={node.name}
        type={htmlType[node.kind]}
        autoComplete={node.autocomplete}
        required={node.required}
        maxLength={node.max_length}
        readOnly={node.read_only === true}
        defaultValue={node.value}
        {...(node.kind === "code" ? { inputMode: "numeric" as const } : {})}
        spellCheck={false}
        autoCapitalize="none"
      />
    </div>
  );
}

function MethodForm(props: {
  readonly method: Method;
  readonly nodes: readonly UiNode[];
  readonly busy: boolean;
  readonly onSubmit: (submission: Submission) => void;
}) {
  const inputs = props.nodes.filter(
    (n): n is InputNode => n.type === "input" && n.method === props.method,
  );
  const buttons = props.nodes.filter(
    (n): n is SubmitNode => n.type === "submit" && n.method === props.method,
  );
  const handle = (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const fields: Partial<Record<FieldName, string>> = {};
    for (const input of inputs) {
      if (input.read_only === true) continue;
      const value = data.get(input.name);
      if (typeof value === "string") fields[input.name] = value;
    }
    props.onSubmit({ method: props.method, fields });
  };
  return (
    <form className={`method method-${props.method}`} onSubmit={handle} noValidate={false}>
      {inputs.map((node) => (
        <Field key={node.name} node={node} />
      ))}
      {buttons.map((node) => (
        <button
          key={node.label.id}
          type="submit"
          className={
            props.method === "restart" || props.method === "skip" ? "secondary" : "primary"
          }
          disabled={props.busy}
        >
          {node.label.text}
        </button>
      ))}
    </form>
  );
}

/** Conditional create is opportunistic; it never holds the user back for longer than this. */
const conditionalCreateWaitMs = 2000;

/** Credentials the server called unknown; autofill does not resubmit them (TN-97). */
const refused = new Set<string>();

function credentialId(json: string): string {
  const parsed = JSON.parse(json) as { id?: unknown };
  return typeof parsed.id === "string" ? parsed.id : "";
}

function follow(target: string) {
  const url = new URL(target, window.location.origin);
  if (url.protocol === "https:" || url.protocol === "http:") window.location.assign(url.href);
}

export function StepView({ ui, busy, onSubmit }: Props) {
  const autofill = ui.nodes.find((n) => n.type === "passkey_autofill");
  const passkeyButton = ui.nodes.find((n) => n.type === "passkey_get");
  const create = ui.nodes.find((n): n is PasskeyCreateNode => n.type === "passkey_create");
  const conditional = useRef<AbortController | null>(null);
  const [round, setRound] = useState(0);

  // TN-97
  useEffect(() => {
    const signals = ui.nodes.flatMap((n) => (n.type === "passkey_signal" ? [n.signal] : []));
    for (const s of signals) if (s.kind === "unknown_credential") refused.add(s.credential_id);
    void Promise.all(signals.map(sendSignal)).then(async () => {
      if (ui.step !== "complete" || ui.redirect_to === undefined) return;
      if (create?.mediation === "explicit") return;
      // §10.2.4
      if (create?.mediation === "conditional" && (await conditionalCreateAvailable())) {
        const credential = await createPasskey(
          create.options,
          "conditional",
          AbortSignal.timeout(conditionalCreateWaitMs),
        );
        if (credential !== null) {
          onSubmit({ method: "passkey_register", fields: { passkey_credential: credential } });
          return;
        }
      }
      follow(ui.redirect_to);
    });
  }, [ui, create, onSubmit]);

  // TN-99
  useEffect(() => {
    if (autofill === undefined) return;
    const controller = new AbortController();
    conditional.current = controller;
    void conditionalGetAvailable().then(async (available) => {
      if (!available || controller.signal.aborted) return;
      const credential = await getPasskey(autofill.options, "conditional", controller.signal);
      if (credential !== null && !refused.has(credentialId(credential))) {
        onSubmit({ method: "passkey", fields: { passkey_credential: credential } });
      }
    });
    return () => {
      controller.abort();
    };
  }, [autofill, onSubmit, round]);

  const signInWithPasskey = async () => {
    if (passkeyButton === undefined) return;
    conditional.current?.abort();
    const credential = await getPasskey(
      passkeyButton.options,
      undefined,
      new AbortController().signal,
    );
    if (credential === null) {
      setRound((r) => r + 1);
      return;
    }
    onSubmit({ method: "passkey", fields: { passkey_credential: credential } });
  };

  const registerPasskey = async () => {
    if (create === undefined) return;
    const credential = await createPasskey(create.options, undefined, new AbortController().signal);
    if (credential !== null) {
      onSubmit({ method: "passkey_register", fields: { passkey_credential: credential } });
    }
  };

  const errors = ui.messages.filter((m) => m.severity === "error");
  const infos = ui.messages.filter((m) => m.severity === "info");
  const heading = ui.step === "complete" ? "Signing you in" : "Sign in";

  return (
    <section aria-labelledby="step-heading" data-step={ui.step}>
      <h1 id="step-heading">{heading}</h1>
      <div role="alert" className="messages" data-testid="errors">
        {errors.map((m) => (
          <p key={m.id} data-message-id={m.id}>
            {m.text}
          </p>
        ))}
      </div>
      {infos.map((m) => (
        <p key={m.id} className="info" data-message-id={m.id}>
          {m.text}
        </p>
      ))}
      {methodsInOrder(ui.nodes)
        .filter((m) => m !== "restart" && m !== "skip")
        .map((method) => (
          <MethodForm
            key={method}
            method={method}
            nodes={ui.nodes}
            busy={busy}
            onSubmit={onSubmit}
          />
        ))}
      {passkeyButton !== undefined && (
        <button
          type="button"
          className="passkey"
          disabled={busy}
          onClick={() => void signInWithPasskey()}
        >
          {passkeyButton.label.text}
        </button>
      )}
      {create?.mediation === "explicit" && (
        <button
          type="button"
          className="passkey"
          disabled={busy}
          onClick={() => void registerPasskey()}
        >
          {create.label.text}
        </button>
      )}
      {methodsInOrder(ui.nodes)
        .filter((m) => m === "restart" || m === "skip")
        .map((method) => (
          <MethodForm
            key={method}
            method={method}
            nodes={ui.nodes}
            busy={busy}
            onSubmit={onSubmit}
          />
        ))}
    </section>
  );
}
