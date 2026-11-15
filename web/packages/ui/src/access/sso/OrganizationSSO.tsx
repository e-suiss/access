// TN-133, TN-134, OP-155 m.3 (i): the organization SSO setup portal as one embeddable component.
// It renders what a one-use setup link opens and hands each step back through `onSubmit`; the
// host calls the realm's setup API (the hosted page and a tenant's page use the same one). It
// keeps no copy and decides nothing: what it submits is a connection draft, and only an owner's
// signed change puts a connection into effect.
import { Button } from "@access/ui/components/button";
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
  FieldLegend,
  FieldSet,
} from "@access/ui/components/field";
import { Input } from "@access/ui/components/input";
import { Item } from "@access/ui/components/item";
import { NativeSelect, NativeSelectOption } from "@access/ui/components/native-select";
import { Separator } from "@access/ui/components/separator";
import { useId, useState, type SyntheticEvent } from "react";

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
  const id = useId();

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
    <section
      className="access-organization-sso flex flex-col gap-6"
      aria-labelledby="access-sso-title"
    >
      <h2 id="access-sso-title" className="text-2xl font-semibold tracking-tight">
        {say("sso_setup.title", texts, { organization: org })}
      </h2>
      <form onSubmit={save} className="flex flex-col gap-6">
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor={`${id}-provider`}>
              {say("sso_setup.choose_provider", texts)}
            </FieldLabel>
            <NativeSelect
              id={`${id}-provider`}
              name="provider"
              className="w-full"
              value={provider}
              onChange={(e) => {
                setProvider(e.target.value);
                setInputs({});
              }}
            >
              {setup.wizards.map((w) => (
                <NativeSelectOption key={w.provider} value={w.provider}>
                  {w.name}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </Field>
          {wizard !== undefined && wizard.protocols.length > 1 ? (
            <FieldSet className="gap-3">
              <FieldLegend variant="label" className="mb-0">
                Protocol
              </FieldLegend>
              {wizard.protocols.map((p) => (
                <FieldLabel key={p} className="font-normal">
                  <input
                    type="radio"
                    name="protocol"
                    value={p}
                    className="size-5 accent-primary outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
                    checked={chosen === p}
                    onChange={() => {
                      setProtocol(p);
                    }}
                  />
                  {p === "saml" ? "SAML 2.0" : "OpenID Connect"}
                </FieldLabel>
              ))}
            </FieldSet>
          ) : null}
          {wizard !== undefined ? (
            <FieldDescription>
              {say("sso_setup.configure", texts, { provider: wizard.name })}
            </FieldDescription>
          ) : null}
          <ol className="access-sso-steps flex list-decimal flex-col gap-4 ps-5">
            {steps.map((s, i) => (
              <li
                key={`${s.action}:${String(i)}`}
                data-action={s.action}
                className="ps-1 marker:text-muted-foreground"
              >
                {s.action === "open" ? <span className="text-base">{s.place}</span> : null}
                {s.action === "copy" && s.value !== undefined ? (
                  <Field>
                    <FieldLabel htmlFor={`${id}-step-${String(i)}`}>{s.field}</FieldLabel>
                    <Input
                      id={`${id}-step-${String(i)}`}
                      readOnly
                      className="font-mono text-sm"
                      value={setup.values[s.value] ?? ""}
                      data-value={s.value}
                    />
                  </Field>
                ) : null}
                {s.action === "paste" && s.input !== undefined ? (
                  <Field>
                    <FieldLabel htmlFor={`${id}-step-${String(i)}`}>{s.field}</FieldLabel>
                    <Input
                      id={`${id}-step-${String(i)}`}
                      name={s.input}
                      required
                      value={inputs[s.input] ?? ""}
                      onChange={(e) => {
                        const key = s.input ?? "";
                        setInputs({ ...inputs, [key]: e.target.value });
                      }}
                    />
                  </Field>
                ) : null}
              </li>
            ))}
          </ol>
        </FieldGroup>
        <Button type="submit" size="lg" block>
          {say("sso_setup.save", texts)}
        </Button>
      </form>
      <Separator />
      <div className="flex flex-col gap-3">
        <h3 className="text-lg font-semibold">{say("sso_setup.domains", texts)}</h3>
        <ul className="access-sso-domains flex flex-col gap-2">
          {setup.domains.map((d) => (
            <Item
              key={d.domain}
              render={<li />}
              variant="outline"
              size="sm"
              data-verified={d.verified}
              className="block wrap-anywhere"
            >
              {d.domain} — <code className="font-mono text-sm">{d.txt_name}</code>
            </Item>
          ))}
        </ul>
      </div>
      {wizard?.scim === true ? (
        <p className="text-sm text-muted-foreground">
          {say("sso_setup.scim", texts)}{" "}
          <code className="font-mono text-foreground wrap-anywhere">
            {setup.values["scim_base_url"]}
          </code>
        </p>
      ) : null}
      <div className="flex flex-col gap-3">
        <p className="text-sm text-muted-foreground">{say("sso_setup.test", texts)}</p>
        <Button
          type="button"
          variant="secondary"
          size="lg"
          block
          disabled={setup.test !== "ready"}
          onClick={() => {
            onSubmit({ step: "test" });
          }}
        >
          {say("sso_setup.test", texts)}
        </Button>
        <Button
          type="button"
          size="lg"
          block
          onClick={() => {
            onSubmit({ step: "finish" });
          }}
        >
          {say("sso_setup.finish", texts)}
        </Button>
      </div>
    </section>
  );
}
