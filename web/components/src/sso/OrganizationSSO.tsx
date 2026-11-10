// TN-133, TN-134, OP-155 m.3 (i): the organization SSO setup portal as one embeddable component.
// It renders what a one-use setup link opens and hands each step back through `onSubmit`; the
// host calls the realm's setup API (the hosted page and a tenant's page use the same one). It
// keeps no copy and decides nothing: what it submits is a connection draft, and only an owner's
// signed change puts a connection into effect.
import { useState, type SyntheticEvent } from "react";

import { text } from "../texts.js";

export type Protocol = "saml" | "oidc";

export interface SetupWizardStep {
  readonly protocol?: Protocol;
  readonly action: "open" | "copy" | "paste";
  readonly place?: string;
  readonly value?: string;
  readonly input?: string;
  readonly field?: string;
}

export interface SetupWizard {
  readonly provider: string;
  readonly name: string;
  readonly protocols: readonly Protocol[];
  readonly scim: boolean;
  readonly steps: readonly SetupWizardStep[];
}

/** What the setup link opens, as `GET /v1/sso-setup/{link}` answers. */
export interface OrganizationSetup {
  readonly organization: { readonly id: string; readonly display_name: string };
  readonly values: Readonly<Record<string, string>>;
  readonly wizards: readonly SetupWizard[];
  readonly domains: readonly {
    readonly domain: string;
    readonly verified: boolean;
    readonly txt_name: string;
  }[];
  readonly drafts: readonly unknown[];
  readonly test: "ready" | "after_enactment";
}

export type OrganizationSetupStep =
  | {
      readonly step: "connection";
      readonly provider: string;
      readonly protocol: Protocol;
      readonly [input: string]: string;
    }
  | { readonly step: "test" }
  | { readonly step: "finish" };

export interface OrganizationSSOProps {
  readonly setup: OrganizationSetup;
  /** Hands one step to the host, which submits it. */
  readonly onSubmit: (step: OrganizationSetupStep) => void;
  /** The host's catalogue of the login texts; English otherwise. */
  readonly catalogue?: Readonly<Record<string, string>>;
  /** The host's own formatter (its Fluent catalogs), tried first. */
  readonly format?: (key: string, args: Readonly<Record<string, string>>) => string | undefined;
}

interface Texts {
  readonly catalogue: OrganizationSSOProps["catalogue"] | undefined;
  readonly format: OrganizationSSOProps["format"] | undefined;
}

function say(key: string, texts: Texts, args: Readonly<Record<string, string>> = {}): string {
  const own = texts.format?.(key, args);
  if (own !== undefined) return own;
  let out = text(key, texts.catalogue);
  for (const [name, value] of Object.entries(args)) out = out.replaceAll(`{ $${name} }`, value);
  return out;
}

/** The steps of `wizard` that apply to `protocol`. */
export function stepsOf(wizard: SetupWizard, protocol: Protocol): readonly SetupWizardStep[] {
  return wizard.steps.filter((s) => s.protocol === undefined || s.protocol === protocol);
}

export function OrganizationSSO({ setup, onSubmit, catalogue, format }: OrganizationSSOProps) {
  const texts: Texts = { catalogue, format };
  const [provider, setProvider] = useState(setup.wizards[0]?.provider ?? "");
  const wizard = setup.wizards.find((w) => w.provider === provider);
  const [protocol, setProtocol] = useState<Protocol>(wizard?.protocols[0] ?? "saml");
  const [inputs, setInputs] = useState<Readonly<Record<string, string>>>({});
  const chosen: Protocol = wizard?.protocols.includes(protocol)
    ? protocol
    : (wizard?.protocols[0] ?? "saml");
  const steps = wizard === undefined ? [] : stepsOf(wizard, chosen);
  const org = setup.organization.display_name;

  function save(e: SyntheticEvent) {
    e.preventDefault();
    if (wizard === undefined) return;
    const pasted = Object.fromEntries(
      steps.flatMap((s) =>
        s.action === "paste" && s.input !== undefined ? [[s.input, inputs[s.input] ?? ""]] : [],
      ),
    );
    onSubmit({ step: "connection", provider: wizard.provider, protocol: chosen, ...pasted });
  }

  return (
    <section className="access-organization-sso" aria-labelledby="access-sso-title">
      <h2 id="access-sso-title">{say("sso_setup.title", texts, { organization: org })}</h2>
      <form onSubmit={save}>
        <label>
          {say("sso_setup.choose_provider", texts)}
          <select
            name="provider"
            value={provider}
            onChange={(e) => {
              setProvider(e.target.value);
              setInputs({});
            }}
          >
            {setup.wizards.map((w) => (
              <option key={w.provider} value={w.provider}>
                {w.name}
              </option>
            ))}
          </select>
        </label>
        {wizard !== undefined && wizard.protocols.length > 1 ? (
          <fieldset>
            <legend>Protocol</legend>
            {wizard.protocols.map((p) => (
              <label key={p}>
                <input
                  type="radio"
                  name="protocol"
                  value={p}
                  checked={chosen === p}
                  onChange={() => {
                    setProtocol(p);
                  }}
                />
                {p === "saml" ? "SAML 2.0" : "OpenID Connect"}
              </label>
            ))}
          </fieldset>
        ) : null}
        {wizard !== undefined ? (
          <p>{say("sso_setup.configure", texts, { provider: wizard.name })}</p>
        ) : null}
        <ol className="access-sso-steps">
          {steps.map((s, i) => (
            <li key={`${s.action}:${String(i)}`} data-action={s.action}>
              {s.action === "open" ? <span>{s.place}</span> : null}
              {s.action === "copy" && s.value !== undefined ? (
                <label>
                  {s.field}
                  <input readOnly value={setup.values[s.value] ?? ""} data-value={s.value} />
                </label>
              ) : null}
              {s.action === "paste" && s.input !== undefined ? (
                <label>
                  {s.field}
                  <input
                    name={s.input}
                    required
                    value={inputs[s.input] ?? ""}
                    onChange={(e) => {
                      const key = s.input ?? "";
                      setInputs({ ...inputs, [key]: e.target.value });
                    }}
                  />
                </label>
              ) : null}
            </li>
          ))}
        </ol>
        <button type="submit">{say("sso_setup.save", texts)}</button>
      </form>
      <h3>{say("sso_setup.domains", texts)}</h3>
      <ul className="access-sso-domains">
        {setup.domains.map((d) => (
          <li key={d.domain} data-verified={d.verified}>
            {d.domain} — <code>{d.txt_name}</code>
          </li>
        ))}
      </ul>
      {wizard?.scim === true ? (
        <p>
          {say("sso_setup.scim", texts)} <code>{setup.values["scim_base_url"]}</code>
        </p>
      ) : null}
      <p>{say("sso_setup.test", texts)}</p>
      <button
        type="button"
        disabled={setup.test !== "ready"}
        onClick={() => {
          onSubmit({ step: "test" });
        }}
      >
        {say("sso_setup.test", texts)}
      </button>
      <button
        type="button"
        onClick={() => {
          onSubmit({ step: "finish" });
        }}
      >
        {say("sso_setup.finish", texts)}
      </button>
    </section>
  );
}
