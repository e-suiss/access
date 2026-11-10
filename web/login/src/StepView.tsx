import { useEffect, useRef, useState, type SyntheticEvent } from "react";

import type {
  FieldName,
  InputNode,
  LoginUi,
  Method,
  OptionName,
  OptionNode,
  PasskeyCreateNode,
  ProviderNode,
  SubmitNode,
  Submission,
  UiNode,
} from "./contract.js";
import { LOGIN, under } from "./base.js";
import { pushOf, PushWait } from "./PushWait.js";
import { follow, returnTo } from "./http.js";
import { t, text } from "./i18n.js";
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

type Fields = Partial<Record<FieldName, string>>;

const htmlType = { text: "text", password: "password", code: "text" } as const;

/** Codes that are digits only get the numeric keyboard; recovery codes are not (TN-107). */
const numeric = new Set<FieldName>(["totp_code", "email_code"]);

function methodsInOrder(nodes: readonly UiNode[]): Method[] {
  const seen: Method[] = [];
  for (const node of nodes) {
    if ((node.type === "input" || node.type === "submit") && !seen.includes(node.method)) {
      seen.push(node.method);
    }
  }
  return seen;
}

// TN-107: paste and autofill are never blocked; one pasteable field per code
function Field({ node }: { readonly node: InputNode }) {
  if (node.kind === "hidden") return null;
  const id = `field-${node.name}-${node.method}`;
  return (
    <div className="field">
      <label htmlFor={id}>{text(node.label)}</label>
      <input
        id={id}
        name={node.name}
        type={htmlType[node.kind]}
        autoComplete={node.autocomplete}
        required={node.required}
        maxLength={node.max_length}
        readOnly={node.read_only === true}
        defaultValue={node.value}
        {...(numeric.has(node.name) ? { inputMode: "numeric" as const } : {})}
        spellCheck={false}
        autoCapitalize="none"
        dir="auto"
      />
    </div>
  );
}

function MethodForm(props: {
  readonly method: Method;
  readonly nodes: readonly UiNode[];
  readonly busy: boolean;
  readonly options: Fields;
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
    const fields: Fields = {};
    for (const input of inputs) {
      if (input.read_only === true || input.kind === "hidden") continue;
      const value = data.get(input.name);
      if (typeof value === "string") fields[input.name] = value;
    }
    props.onSubmit({ method: props.method, fields: { ...fields, ...props.options } });
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
          {text(node.label)}
        </button>
      ))}
    </form>
  );
}

function Option(props: {
  readonly node: OptionNode;
  readonly checked: boolean;
  readonly onChange: (name: OptionName, checked: boolean) => void;
}) {
  const id = `option-${props.node.name}`;
  return (
    <div className="option">
      <input
        id={id}
        type="checkbox"
        name={props.node.name}
        checked={props.checked}
        onChange={(e) => {
          props.onChange(props.node.name, e.currentTarget.checked);
        }}
      />
      <label htmlFor={id}>{text(props.node.label)}</label>
    </div>
  );
}

// OP-153 m.3 (l): a full-page navigation; the provider redirect is the server's
function Provider({ node }: { readonly node: ProviderNode }) {
  return (
    <a className="provider" href={under(node.href)} data-provider={node.provider}>
      {text(node.label)}
    </a>
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

function heading(ui: LoginUi): string {
  if (ui.kind === "registration") return t("registration.title");
  return ui.step === "complete" ? t("page.signing_in") : t("page.sign_in");
}

function initialOptions(nodes: readonly UiNode[]): Fields {
  const out: Fields = {};
  for (const n of nodes) if (n.type === "option" && n.checked) out[n.name] = "true";
  return out;
}

export function StepView({ ui, busy, onSubmit }: Props) {
  const autofill = ui.nodes.find((n) => n.type === "passkey_autofill");
  const passkeyButton = ui.nodes.find((n) => n.type === "passkey_get");
  const create = ui.nodes.find((n): n is PasskeyCreateNode => n.type === "passkey_create");
  const optionNodes = ui.nodes.filter((n): n is OptionNode => n.type === "option");
  const providers = ui.nodes.filter((n): n is ProviderNode => n.type === "provider");
  const push = pushOf(ui);
  const conditional = useRef<AbortController | null>(null);
  const title = useRef<HTMLHeadingElement>(null);
  const first = useRef(true);
  const [round, setRound] = useState(0);
  const [options, setOptions] = useState<Fields>(() => initialOptions(ui.nodes));
  const [shown, setShown] = useState(ui);

  // X33, TN-36: the choices belong to the step they were offered on
  if (shown !== ui) {
    setShown(ui);
    setOptions(initialOptions(ui.nodes));
  }

  // TN-107: a new step is announced by moving focus to its heading
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    title.current?.focus();
  }, [ui.flow, ui.step]);

  // TN-97
  useEffect(() => {
    const signals = ui.nodes.flatMap((n) => (n.type === "passkey_signal" ? [n.signal] : []));
    for (const s of signals) if (s.kind === "unknown_credential") refused.add(s.credential_id);
    void Promise.all(signals.map(sendSignal)).then(async () => {
      const target = ui.step === "complete" ? (returnTo() ?? ui.redirect_to) : undefined;
      if (target === undefined) return;
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
      follow(target);
    });
  }, [ui, create, onSubmit]);

  const optionsRef = useRef(options);
  useEffect(() => {
    optionsRef.current = options;
  }, [options]);

  // TN-99
  useEffect(() => {
    if (autofill === undefined) return;
    const controller = new AbortController();
    conditional.current = controller;
    void conditionalGetAvailable().then(async (available) => {
      if (!available || controller.signal.aborted) return;
      const credential = await getPasskey(autofill.options, "conditional", controller.signal);
      if (credential !== null && !refused.has(credentialId(credential))) {
        onSubmit({
          method: "passkey",
          fields: { passkey_credential: credential, ...optionsRef.current },
        });
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
    onSubmit({ method: "passkey", fields: { passkey_credential: credential, ...options } });
  };

  const registerPasskey = async () => {
    if (create === undefined) return;
    const credential = await createPasskey(create.options, undefined, new AbortController().signal);
    if (credential !== null) {
      onSubmit({ method: "passkey_register", fields: { passkey_credential: credential } });
    }
  };

  const setOption = (name: OptionName, checked: boolean) => {
    setOptions((o) => {
      const rest = Object.fromEntries(Object.entries(o).filter(([k]) => k !== name)) as Fields;
      return checked ? { ...rest, [name]: "true" } : rest;
    });
  };

  const errors = ui.messages.filter((m) => m.severity === "error");
  const infos = ui.messages.filter((m) => m.severity === "info");
  const login = ui.kind === undefined || ui.kind === "login";

  return (
    <section aria-labelledby="step-heading" data-step={ui.step} data-kind={ui.kind ?? "login"}>
      <h1 id="step-heading" ref={title} tabIndex={-1}>
        {heading(ui)}
      </h1>
      <div role="alert" className="messages" data-testid="errors">
        {errors.map((m) => (
          <p key={m.id} data-message-id={m.id}>
            {text(m)}
          </p>
        ))}
      </div>
      <div role="status" className="infos">
        {infos.map((m) => (
          <p key={m.id} className="info" data-message-id={m.id}>
            {text(m)}
          </p>
        ))}
      </div>
      {push !== undefined && <PushWait node={push} />}
      {optionNodes.length > 0 && (
        <fieldset className="options">
          <legend className="visually-hidden">{t("page.options")}</legend>
          {optionNodes.map((node) => (
            <Option
              key={node.name}
              node={node}
              checked={options[node.name] === "true"}
              onChange={setOption}
            />
          ))}
        </fieldset>
      )}
      {methodsInOrder(ui.nodes)
        .filter((m) => m !== "restart" && m !== "skip")
        .map((method) => (
          <MethodForm
            key={method}
            method={method}
            nodes={ui.nodes}
            busy={busy}
            options={options}
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
          {text(passkeyButton.label)}
        </button>
      )}
      {create?.mediation === "explicit" && (
        <button
          type="button"
          className="passkey"
          disabled={busy}
          onClick={() => void registerPasskey()}
        >
          {text(create.label)}
        </button>
      )}
      {providers.length > 0 && (
        <nav className="providers" aria-label={t("page.providers")}>
          {providers.map((node) => (
            <Provider key={node.provider} node={node} />
          ))}
        </nav>
      )}
      {methodsInOrder(ui.nodes)
        .filter((m) => m === "restart" || m === "skip")
        .map((method) => (
          <MethodForm
            key={method}
            method={method}
            nodes={ui.nodes}
            busy={busy}
            options={{}}
            onSubmit={onSubmit}
          />
        ))}
      {login && (ui.step === "identifier" || ui.step === "authenticate") && (
        <p className="links">
          <a href={`${LOGIN}/recovery`}>{t("page.recover")}</a>{" "}
          <a href={`${LOGIN}?reason=create`}>{t("page.create_account")}</a>
        </p>
      )}
      {ui.kind === "registration" && ui.step !== "complete" && (
        <p className="links">
          <a href={LOGIN}>{t("action.have_account")}</a>
        </p>
      )}
    </section>
  );
}
