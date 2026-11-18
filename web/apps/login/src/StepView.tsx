import { Button } from "@access/ui/components/button";
import { Checkbox } from "@access/ui/components/checkbox";
import { Field as FieldBox, FieldLabel, FieldLegend, FieldSet } from "@access/ui/components/field";
import { Input } from "@access/ui/components/input";
import { QrCode } from "@access/ui/components/qr-code";
import { type SyntheticEvent, useEffect, useRef, useState } from "react";
import * as v from "valibot";

import { LOGIN, under } from "./base.js";
import type {
  FieldName,
  InputNode,
  LoginUi,
  Method,
  OptionName,
  OptionNode,
  PasskeyCreateNode,
  ProviderNode,
  RecoveryCodesNode,
  Submission,
  SubmitNode,
  TotpSetupNode,
  UiNode,
} from "./contract.js";
import { Empty, follow, postJson, returnTo } from "./http.js";
import { t, text } from "./i18n.js";
import {
  link,
  note,
  other,
  otherLink,
  pressable,
  primary,
  problem,
  quiet,
  stack,
  Title,
} from "./Layout.js";
import { PushWait, pushOf } from "./PushWait.js";
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

const htmlType = { text: "text", password: "password", code: "text", tel: "tel" } as const;

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
    <FieldBox className="gap-2">
      <FieldLabel htmlFor={id} className="text-sm">
        {text(node.label)}
      </FieldLabel>
      <Input
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
        {...(node.kind === "code" ? { className: "font-mono tracking-widest" } : {})}
      />
    </FieldBox>
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
    <form className={stack} onSubmit={handle} noValidate={false}>
      {inputs.map((node) => (
        <Field key={node.name} node={node} />
      ))}
      {buttons.map((node) => (
        <Button
          key={node.label.id}
          type="submit"
          {...(props.method === "restart" || props.method === "skip" ? quiet : primary)}
          disabled={props.busy}
        >
          {text(node.label)}
        </Button>
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
    <FieldBox orientation="horizontal">
      <Checkbox
        className={pressable}
        id={id}
        name={props.node.name}
        aria-labelledby={`${id}-label`}
        checked={props.checked}
        onCheckedChange={(checked) => {
          props.onChange(props.node.name, checked);
        }}
      />
      <FieldLabel id={`${id}-label`} htmlFor={id} className="min-h-6 text-sm font-normal">
        {text(props.node.label)}
      </FieldLabel>
    </FieldBox>
  );
}

// OP-153 m.3 (l): a full-page navigation; the provider redirect is the server's
function Provider({ node }: { readonly node: ProviderNode }) {
  return (
    <a className={otherLink} href={under(node.href)} data-provider={node.provider}>
      {text(node.label)}
    </a>
  );
}

// OP-159 m.48 (a): the key of a TOTP set up at sign-in; the code that proves it is the step's input
function TotpSetup({ node }: { readonly node: TotpSetupNode }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex flex-col gap-2" data-testid="totp-setup">
      <p className="text-sm">{text(node.label)}</p>
      {/* TN-155 */}
      <QrCode value={node.uri} label={t("page.totp_qr")} className="self-center" />
      <p className="text-sm text-muted-foreground">{t("page.totp_scan")}</p>
      <p
        className="break-all rounded-lg bg-muted px-3 py-2 font-mono text-base tracking-widest"
        data-testid="totp-secret"
      >
        {node.secret}
      </p>
      <p className="flex flex-wrap gap-3">
        <Button
          type="button"
          {...quiet}
          onClick={() => {
            void navigator.clipboard.writeText(node.secret).then(
              () => {
                setCopied(true);
              },
              () => undefined,
            );
          }}
        >
          {copied ? t("page.totp_copied") : t("page.totp_copy")}
        </Button>
        <a className={link} href={node.uri} data-testid="totp-uri">
          {t("page.totp_open")}
        </a>
      </p>
    </div>
  );
}

// OP-159 m.48 (a), §10.2.2: shown once; the sign-in continues only after the person says they saved them
function RecoveryCodes(props: {
  readonly node: RecoveryCodesNode;
  readonly target: string | undefined;
}) {
  const [busy, setBusy] = useState(false);
  const proceed = async () => {
    setBusy(true);
    await postJson("/v1/account/recovery-codes/acknowledgement", {}, Empty);
    if (props.target !== undefined) follow(props.target);
  };
  return (
    <div className="flex flex-col gap-3" data-testid="recovery-codes">
      <p className="text-sm">{text(props.node.label)}</p>
      <ul className="grid grid-cols-2 gap-2 rounded-lg bg-muted px-3 py-2 font-mono text-sm">
        {props.node.codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
      <Button {...primary} disabled={busy} onClick={() => void proceed()}>
        {t("page.codes_saved")}
      </Button>
    </div>
  );
}

/** Conditional create is opportunistic; it never holds the user back for longer than this. */
const conditionalCreateWaitMs = 2000;

/** Credentials the server called unknown; autofill does not resubmit them (TN-97). */
const refused = new Set<string>();

// OP-159 m.46 (f)
const Credential = v.looseObject({ id: v.string() });

function credentialId(json: string): string {
  const parsed = v.safeParse(Credential, JSON.parse(json));
  return parsed.success ? parsed.output.id : "";
}

function heading(ui: LoginUi): string {
  if (ui.kind === "registration") return t("registration.title");
  if (ui.step === "complete") return t("page.signing_in");
  return t("page.sign_in");
}

/**
 * OP-159 m.47 (b), TN-138: a second step is required and nothing on the step can give one: the
 * account has none yet and the step offers no way to add one.
 */
function noSecondStep(ui: LoginUi): boolean {
  if (ui.step !== "second_factor") return false;
  const missing = ui.requirements.some(
    (r) => r.requirement === "second_factor" && r.state === "missing",
  );
  const offered = ui.nodes.some(
    (n) =>
      n.type === "passkey_get" ||
      n.type === "passkey_create" ||
      n.type === "push_number" ||
      n.type === "totp_setup" ||
      ((n.type === "input" || n.type === "submit") &&
        n.method !== "restart" &&
        n.method !== "skip"),
  );
  return missing && !offered;
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
  const totpSetup = ui.nodes.find((n): n is TotpSetupNode => n.type === "totp_setup");
  const recoveryCodes = ui.nodes.find((n): n is RecoveryCodesNode => n.type === "recovery_codes");
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
      // OP-159 m.48 (a): the recovery codes are read first
      if (recoveryCodes !== undefined) return;
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
  }, [ui, create, recoveryCodes, onSubmit]);

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
    <section
      aria-labelledby="step-heading"
      data-step={ui.step}
      data-kind={ui.kind ?? "login"}
      className={stack}
    >
      <Title id="step-heading" ref={title}>
        {heading(ui)}
      </Title>
      <div role="alert" className="flex flex-col gap-2 empty:-mb-4" data-testid="errors">
        {errors.map((m) => (
          <p key={m.id} className={problem} data-message-id={m.id}>
            {text(m)}
          </p>
        ))}
      </div>
      <div role="status" className="flex flex-col gap-2 empty:-mb-4">
        {infos.map((m) => (
          <p key={m.id} className={note} data-message-id={m.id}>
            {text(m)}
          </p>
        ))}
      </div>
      {push !== undefined && <PushWait node={push} />}
      {totpSetup !== undefined && <TotpSetup node={totpSetup} />}
      {recoveryCodes !== undefined && (
        <RecoveryCodes
          node={recoveryCodes}
          target={ui.step === "complete" ? (returnTo() ?? ui.redirect_to) : undefined}
        />
      )}
      {noSecondStep(ui) && (
        <p className={problem} data-testid="second-step-missing">
          {t("page.second_step_missing")}
        </p>
      )}
      {optionNodes.length > 0 && (
        <FieldSet className="gap-3">
          <FieldLegend className="sr-only">{t("page.options")}</FieldLegend>
          {optionNodes.map((node) => (
            <Option
              key={node.name}
              node={node}
              checked={options[node.name] === "true"}
              onChange={setOption}
            />
          ))}
        </FieldSet>
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
        <Button {...other} disabled={busy} onClick={() => void signInWithPasskey()}>
          {text(passkeyButton.label)}
        </Button>
      )}
      {create?.mediation === "explicit" && (
        <Button {...other} disabled={busy} onClick={() => void registerPasskey()}>
          {text(create.label)}
        </Button>
      )}
      {providers.length > 0 && (
        <nav className="flex flex-col gap-2" aria-label={t("page.providers")}>
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
        <p className="flex flex-wrap justify-between gap-2">
          <a className={link} href={`${LOGIN}/recovery`}>
            {t("page.recover")}
          </a>{" "}
          <a className={link} href={`${LOGIN}?reason=create`}>
            {t("page.create_account")}
          </a>
        </p>
      )}
      {ui.kind === "registration" && ui.step !== "complete" && (
        <p>
          <a className={link} href={LOGIN}>
            {t("action.have_account")}
          </a>
        </p>
      )}
    </section>
  );
}
