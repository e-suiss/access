// S11 (§8.5, §8.8; TN-99, TN-64, TN-68, TN-107, OP-148): the ways this person signs in, on the
// session cookie alone. Passkeys are created, seen and removed here (the first FIDO pattern; the
// sign-in fallback stays on the hosted login). The authenticator app's key is shown as text with
// a copy button, so a QR code is never the only path; its code is one pasteable field. Removing
// a method is confirmed first and named in the confirmation; removing the last way to sign in is
// refused by the server and said plainly (TN-148).
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@access/ui/components/alert-dialog";
import { Button, buttonVariants } from "@access/ui/components/button";
import { Field, FieldLabel } from "@access/ui/components/field";
import { Input } from "@access/ui/components/input";
import { ItemActions, ItemContent } from "@access/ui/components/item";
import { PasswordInput } from "@access/ui/components/password-input";
import { QrCode } from "@access/ui/components/qr-code";
import { cn } from "@access/ui/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ReactElement, type SyntheticEvent, useEffect, useRef, useState } from "react";
import * as v from "valibot";

import { FRONTEND, frontend, json, Problem } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { Actions, Loading, Meta, MONO, Panel, Part, RowItem, Rows } from "../lib/ui.js";
import { useAnnouncer, when } from "./common.js";

/** What `GET /v1/account/methods` answers. */
export const Methods = v.object({
  password: v.object({
    set: v.boolean(),
    kind: v.optional(v.picklist(["password", "pin"]), "password"),
  }),
  passkeys: v.array(
    v.object({
      id: v.string(),
      name: v.nullable(v.string()),
      created_at: v.string(),
      synced: v.boolean(),
    }),
  ),
  totp: v.array(v.object({ id: v.string(), created_at: v.string() })),
  recovery_codes: v.object({ set: v.boolean(), acknowledged: v.boolean() }),
  phone: v.optional(
    v.nullable(v.object({ set: v.boolean(), ends_with: v.nullable(v.string()) })),
    null,
  ),
  identity: v.optional(
    v.nullable(
      v.object({
        national_id: v.nullable(v.string()),
        national_id_scheme: v.nullable(v.string()),
        birthdate: v.nullable(v.string()),
      }),
    ),
    null,
  ),
});

const PhoneChange = v.object({ change: v.string() });
export type Methods = v.InferOutput<typeof Methods>;

const Enrollment = v.object({
  enrollment: v.string(),
  secret: v.string(),
  uri: v.string(),
  proof: v.optional(v.boolean(), false),
});
type Enrollment = v.InferOutput<typeof Enrollment>;

const Registration = v.object({
  registration: v.string(),
  options: v.record(v.string(), v.unknown()),
  proof: v.optional(v.boolean(), false),
});
type Registration = v.InferOutput<typeof Registration>;

// TN-147
const PROOF_CODES = {
  "code-not-accepted": "methods.proof_failed",
  "proof-unavailable": "methods.proof_unavailable",
} as const;

async function prove(flow: string, code: string): Promise<void> {
  await json(
    frontend(`/v1/account/method-proof/${encodeURIComponent(flow)}`, {
      method: "POST",
      body: { code },
    }),
  );
}

/** TN-147: the code sent to the account's address before a first strong method is added. */
function Proof(props: {
  readonly id: string;
  readonly busy: boolean;
  readonly onCode: (code: string) => void;
  readonly onCancel: () => void;
}): ReactElement {
  const field = useRef<HTMLInputElement>(null);
  useEffect(() => {
    field.current?.focus();
  }, []);
  const submit = (e: SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    const code = v.safeParse(Code, new FormData(e.currentTarget).get("code"));
    if (code.success && code.output !== "") props.onCode(code.output);
  };
  return (
    <form
      onSubmit={submit}
      className="flex flex-col gap-3 rounded-xl border p-4"
      data-testid="method-proof"
    >
      <p className="text-sm">{t("methods.proof_sent")}</p>
      <Field>
        <FieldLabel htmlFor={props.id}>{t("label.proof_code")}</FieldLabel>
        <Input
          id={props.id}
          ref={field}
          size="md"
          name="code"
          autoComplete="one-time-code"
          inputMode="numeric"
          maxLength={16}
          spellCheck={false}
          required
        />
      </Field>
      <Actions>
        <Button type="submit" disabled={props.busy}>
          {t("action.verify")}
        </Button>
        <Button variant="outline" onClick={props.onCancel}>
          {t("action.cancel")}
        </Button>
      </Actions>
    </form>
  );
}

const Codes = v.object({ recovery_codes: v.array(v.string()) });
const Enrolled = v.object({ recovery_codes: v.optional(v.array(v.string())) });

const NewPassword = v.pipe(v.string(), v.nonEmpty());
const Code = v.pipe(
  v.string(),
  v.transform((c) => c.replace(/\s+/g, "")),
);

const KEY = ["account", "methods"] as const;

const REMOVE_CODES = { "last-sign-in-method": "methods.last_method" } as const;

async function createPasskey(options: Readonly<Record<string, unknown>>): Promise<unknown> {
  const inner = options["publicKey"];
  const shape = (typeof inner === "object" && inner !== null ? inner : options) as unknown;
  const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(
    shape as PublicKeyCredentialCreationOptionsJSON,
  );
  const credential = (await navigator.credentials.create({
    publicKey,
  })) as PublicKeyCredential | null;
  if (credential === null) throw new Error("cancelled");
  return credential.toJSON();
}

function Passkeys(props: {
  readonly methods: Methods;
  readonly reload: () => void;
  readonly say: (text: string, alert?: boolean) => void;
  readonly fail: (e: unknown, codes?: Readonly<Record<string, string>>) => void;
  readonly remove: (id: string, label: string) => void;
}): ReactElement {
  const [name, setName] = useState("");
  const [waiting, setWaiting] = useState<Registration | null>(null);
  const finish = async (reg: Registration): Promise<boolean> => {
    let credential: unknown;
    try {
      credential = await createPasskey(reg.options);
    } catch {
      return false;
    }
    await json(
      frontend(`/v1/account/passkeys/${encodeURIComponent(reg.registration)}`, {
        method: "POST",
        body: { credential },
      }),
    );
    return true;
  };
  const done = (created: boolean | null) => {
    if (created === null) return;
    setWaiting(null);
    if (!created) {
      props.say(t("methods.passkey_failed"), true);
      return;
    }
    setName("");
    props.say(t("methods.added"));
    props.reload();
  };
  const refused = (err: unknown) => {
    // OP-159 m.3 (ll), TN-147
    props.fail(err, {
      "attestation-format": t("passkey.attestation_refused"),
      "attestation-revocation-unknown": t("passkey.attestation_unknown"),
      ...PROOF_CODES,
    });
  };
  const create = useMutation({
    mutationFn: async (label: string): Promise<boolean | null> => {
      const reg = await json(
        frontend("/v1/account/passkeys", { method: "POST", body: { name: label } }),
        Registration,
      );
      if (reg.proof) {
        setWaiting(reg);
        return null;
      }
      return finish(reg);
    },
    onSuccess: done,
    onError: refused,
  });
  const proved = useMutation({
    mutationFn: async ({ reg, code }: { readonly reg: Registration; readonly code: string }) => {
      await prove(reg.registration, code);
      return finish(reg);
    },
    onSuccess: done,
    onError: refused,
  });
  const add = (e: SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    create.mutate(name.trim() === "" ? t("methods.passkey_unnamed") : name.trim());
  };
  return (
    <Part aria-labelledby="passkeys-heading" data-testid="passkeys">
      <h4 id="passkeys-heading" className="font-semibold">
        {t("methods.passkeys")}
      </h4>
      {/* HL-19 */}
      {props.methods.passkeys.length === 0 && (
        // TN-156
        <p className="text-sm font-medium" data-testid="passkey-suggest">
          {t("methods.passkey_suggest")}
        </p>
      )}
      <Meta data-testid="passkey-no-pqc">{t("security.passkey_no_pqc")}</Meta>
      {props.methods.passkeys.length > 0 && (
        <Rows>
          {props.methods.passkeys.map((p) => (
            <RowItem key={p.id} data-testid="passkey-row">
              <ItemContent>
                <strong>{p.name ?? t("methods.passkey_unnamed")}</strong>
                <Meta>
                  {p.synced ? t("methods.passkey_synced") : t("methods.passkey_this_device")}
                  {" · "}
                  {t("methods.added_on", { date: when(p.created_at) })}
                </Meta>
              </ItemContent>
              <ItemActions>
                <Button
                  variant="outline"
                  size="sm"
                  aria-label={`${t("action.remove")}: ${p.name ?? t("methods.passkey_unnamed")}`}
                  onClick={() => {
                    props.remove(p.id, p.name ?? t("methods.passkey_unnamed"));
                  }}
                >
                  {t("action.remove")}
                </Button>
              </ItemActions>
            </RowItem>
          ))}
        </Rows>
      )}
      {waiting !== null && (
        <Proof
          id="passkey-proof"
          busy={proved.isPending}
          onCode={(code) => {
            proved.mutate({ reg: waiting, code });
          }}
          onCancel={() => {
            setWaiting(null);
          }}
        />
      )}
      <form onSubmit={add} className="flex flex-col gap-2 sm:flex-row sm:items-end">
        <Field className="flex-1">
          <FieldLabel htmlFor="passkey-name">{t("methods.passkey_name")}</FieldLabel>
          <Input
            id="passkey-name"
            size="md"
            value={name}
            maxLength={64}
            autoComplete="off"
            onChange={(e) => {
              setName(e.target.value);
            }}
          />
        </Field>
        <Button type="submit" disabled={create.isPending}>
          {t("action.passkey_create")}
        </Button>
      </form>
    </Part>
  );
}

function Password(props: {
  readonly set: boolean;
  readonly pin: boolean;
  readonly reload: () => void;
  readonly say: (text: string, alert?: boolean) => void;
  readonly fail: (e: unknown, codes?: Readonly<Record<string, string>>) => void;
}): ReactElement {
  const [open, setOpen] = useState(false);
  const field = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (open) field.current?.focus();
  }, [open]);
  const change = useMutation({
    mutationFn: (value: string) =>
      json(frontend("/v1/account/password", { method: "PUT", body: { new_password: value } })),
    onSuccess: () => {
      setOpen(false);
      props.say(t("methods.password_saved"));
      props.reload();
    },
    onError: (err) => {
      props.fail(err, {
        "password-rejected": props.pin ? "methods.pin_rejected" : "methods.password_rejected",
      });
    },
  });
  const save = (e: SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    const value = v.safeParse(NewPassword, new FormData(e.currentTarget).get("new_password"));
    if (value.success) change.mutate(value.output);
  };
  return (
    <Part aria-labelledby="password-heading" data-testid="password">
      <h4 id="password-heading" className="font-semibold">
        {props.pin ? t("methods.pin") : t("methods.password")}
      </h4>
      <Meta>
        {props.pin
          ? props.set
            ? t("methods.pin_set")
            : t("methods.pin_none")
          : props.set
            ? t("methods.password_set")
            : t("methods.password_none")}
      </Meta>
      {open ? (
        <form onSubmit={save} className="flex flex-col gap-3">
          <Field>
            <FieldLabel htmlFor="new-password">
              {props.pin ? t("label.new_pin") : t("label.new_password")}
            </FieldLabel>
            <PasswordInput
              id="new-password"
              ref={field}
              name="new_password"
              autoComplete="new-password"
              maxLength={props.pin ? 6 : 128}
              {...(props.pin ? { inputMode: "numeric" as const } : {})}
              required
              compact
              words={{
                show: t(props.pin ? "methods.show_pin" : "methods.show_password"),
                hide: t(props.pin ? "methods.hide_pin" : "methods.hide_password"),
                capsLock: t("methods.caps_lock"),
              }}
            />
          </Field>
          <Actions>
            <Button type="submit">{t("action.save")}</Button>
            <Button
              variant="outline"
              onClick={() => {
                setOpen(false);
              }}
            >
              {t("action.cancel")}
            </Button>
          </Actions>
        </form>
      ) : (
        <Actions>
          <Button
            variant="outline"
            onClick={() => {
              setOpen(true);
            }}
          >
            {props.pin
              ? props.set
                ? t("action.change_pin")
                : t("action.set_pin")
              : props.set
                ? t("action.change_password")
                : t("action.set_password")}
          </Button>
        </Actions>
      )}
    </Part>
  );
}

// TN-156: a phone number is added or changed with a text message code to the new number; the old
// number is told and every sign-in ends, this one too
// TN-158: what the environment asked for at sign-up; changed only through support
function Identity(props: {
  readonly identity: {
    readonly national_id: string | null;
    readonly national_id_scheme: string | null;
    readonly birthdate: string | null;
  };
}): ReactElement {
  const id = props.identity;
  return (
    <Part aria-labelledby="identity-heading" data-testid="identity">
      <h4 id="identity-heading" className="font-semibold">
        {t("methods.identity")}
      </h4>
      {id.national_id !== null && (
        <Meta>{t("methods.identity_number", { number: id.national_id })}</Meta>
      )}
      {id.birthdate !== null && (
        <Meta>{t("methods.identity_birthdate", { date: id.birthdate })}</Meta>
      )}
      {id.national_id === null && id.birthdate === null && (
        <Meta>{t("methods.identity_none")}</Meta>
      )}
      <Meta>{t("methods.identity_support")}</Meta>
    </Part>
  );
}

function Phone(props: {
  readonly phone: { readonly set: boolean; readonly ends_with: string | null };
  readonly say: (text: string, alert?: boolean) => void;
  readonly fail: (e: unknown, codes?: Readonly<Record<string, string>>) => void;
}): ReactElement {
  const [step, setStep] = useState<"idle" | "number" | { readonly change: string }>("idle");
  const start = useMutation({
    mutationFn: (phone: string) =>
      json(frontend("/v1/account/phone", { method: "POST", body: { phone } }), PhoneChange),
    onSuccess: (c) => {
      setStep({ change: c.change });
      props.say(t("methods.phone_code_sent"));
    },
    onError: (err) => {
      props.fail(err, { "invalid-phone": "methods.phone_invalid" });
    },
  });
  const confirm = useMutation({
    mutationFn: ({ change, code }: { readonly change: string; readonly code: string }) =>
      json(
        frontend(`/v1/account/phone/${encodeURIComponent(change)}`, {
          method: "POST",
          body: { code },
        }),
      ),
    onSuccess: () => {
      props.say(t("methods.phone_changed"));
      location.assign(`${FRONTEND}/login`);
    },
    onError: (err) => {
      props.fail(err, { "code-not-accepted": "methods.proof_failed" });
    },
  });
  return (
    <Part aria-labelledby="phone-heading" data-testid="phone">
      <h4 id="phone-heading" className="font-semibold">
        {t("methods.phone")}
      </h4>
      <Meta>
        {props.phone.set && props.phone.ends_with !== null
          ? t("methods.phone_ends", { digits: props.phone.ends_with })
          : t("methods.phone_none")}
      </Meta>
      {step === "idle" && (
        <Actions>
          <Button
            variant="outline"
            onClick={() => {
              setStep("number");
            }}
          >
            {props.phone.set ? t("action.change_phone") : t("action.add_phone")}
          </Button>
        </Actions>
      )}
      {step === "number" && (
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            start.mutate(String(new FormData(e.currentTarget).get("phone") ?? ""));
          }}
        >
          <Field>
            <FieldLabel htmlFor="new-phone">{t("label.new_phone")}</FieldLabel>
            <Input
              id="new-phone"
              size="md"
              name="phone"
              type="tel"
              autoComplete="tel"
              maxLength={32}
              required
            />
          </Field>
          <Actions>
            <Button type="submit" disabled={start.isPending}>
              {t("action.continue")}
            </Button>
            <Button
              variant="outline"
              onClick={() => {
                setStep("idle");
              }}
            >
              {t("action.cancel")}
            </Button>
          </Actions>
        </form>
      )}
      {typeof step === "object" && (
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            const code = String(new FormData(e.currentTarget).get("code") ?? "").replace(
              /\s+/g,
              "",
            );
            confirm.mutate({ change: step.change, code });
          }}
        >
          <Field>
            <FieldLabel htmlFor="phone-code">{t("label.sms_code")}</FieldLabel>
            <Input
              id="phone-code"
              size="md"
              name="code"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={16}
              required
            />
          </Field>
          <Actions>
            <Button type="submit" disabled={confirm.isPending}>
              {t("action.verify")}
            </Button>
          </Actions>
        </form>
      )}
    </Part>
  );
}

function Authenticator(props: {
  readonly methods: Methods;
  readonly reload: () => void;
  readonly say: (text: string, alert?: boolean) => void;
  readonly fail: (e: unknown, codes?: Readonly<Record<string, string>>) => void;
  readonly remove: (id: string, label: string) => void;
  readonly onCodes: (codes: readonly string[]) => void;
}): ReactElement {
  const [pending, setPending] = useState<Enrollment | null>(null);
  const code = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (pending !== null && !pending.proof) code.current?.focus();
  }, [pending]);
  const proved = useMutation({
    mutationFn: async ({ e, code }: { readonly e: Enrollment; readonly code: string }) => {
      await prove(e.enrollment, code);
      return e;
    },
    onSuccess: (e) => {
      setPending({ ...e, proof: false });
    },
    onError: (err) => {
      props.fail(err, PROOF_CODES);
    },
  });
  const start = useMutation({
    mutationFn: () =>
      json(
        frontend("/v1/account/totp", { method: "POST", body: { label: "account" } }),
        Enrollment,
      ),
    onSuccess: (e) => {
      setPending(e);
    },
    onError: (err) => {
      props.fail(err, PROOF_CODES);
    },
  });
  const verify = useMutation({
    mutationFn: ({ enrollment, code }: { readonly enrollment: string; readonly code: string }) =>
      json(
        frontend(`/v1/account/totp/${encodeURIComponent(enrollment)}`, {
          method: "POST",
          body: { code },
        }),
        Enrolled,
      ),
    onSuccess: (done) => {
      setPending(null);
      props.say(t("methods.authenticator_added"));
      if (done.recovery_codes !== undefined) props.onCodes(done.recovery_codes);
      props.reload();
    },
    onError: (err) => {
      props.fail(err, {
        "code-invalid": "methods.code_failed",
        "totp-invalid": "methods.code_failed",
        "second-factor-failed": "methods.code_failed",
        "invalid-code": "methods.code_failed",
        "code-not-accepted": "methods.code_failed",
      });
    },
  });
  const begin = () => {
    start.mutate();
  };
  const confirm = (e: SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (pending === null) return;
    const code = v.safeParse(Code, new FormData(e.currentTarget).get("code"));
    if (code.success) verify.mutate({ enrollment: pending.enrollment, code: code.output });
  };
  return (
    <Part aria-labelledby="totp-heading" data-testid="authenticator">
      <h4 id="totp-heading" className="font-semibold">
        {t("methods.authenticator")}
      </h4>
      {props.methods.totp.length === 0 && pending === null && (
        <Meta>{t("methods.authenticator_none")}</Meta>
      )}
      {props.methods.totp.length > 0 && (
        <Rows>
          {props.methods.totp.map((m) => (
            <RowItem key={m.id} data-testid="totp-row">
              <ItemContent>{t("methods.added_on", { date: when(m.created_at) })}</ItemContent>
              <ItemActions>
                <Button
                  variant="outline"
                  size="sm"
                  aria-label={`${t("action.remove")}: ${t("methods.authenticator")}`}
                  onClick={() => {
                    props.remove(m.id, t("methods.authenticator"));
                  }}
                >
                  {t("action.remove")}
                </Button>
              </ItemActions>
            </RowItem>
          ))}
        </Rows>
      )}
      {pending === null ? (
        <Actions>
          <Button variant="outline" onClick={begin}>
            {props.methods.totp.length > 0
              ? t("action.replace_authenticator")
              : t("action.add_authenticator")}
          </Button>
        </Actions>
      ) : pending.proof ? (
        <Proof
          id="totp-proof"
          busy={proved.isPending}
          onCode={(code) => {
            proved.mutate({ e: pending, code });
          }}
          onCancel={() => {
            setPending(null);
          }}
        />
      ) : (
        <form
          onSubmit={confirm}
          className="flex flex-col gap-3 rounded-xl border p-4"
          data-testid="totp-enrollment"
        >
          {/* TN-155 */}
          {props.methods.totp.length > 0 && (
            <p className="text-sm font-medium" data-testid="totp-replaces">
              {t("methods.authenticator_replaces")}
            </p>
          )}
          <QrCode value={pending.uri} label={t("methods.authenticator_qr")} />
          <p className="text-sm">{t("methods.authenticator_scan")}</p>
          <p className="text-sm">{t("methods.authenticator_key")}</p>
          <p
            className={cn(MONO, "rounded-lg bg-muted px-3 py-2 text-base")}
            data-testid="totp-secret"
          >
            {pending.secret}
          </p>
          <Actions>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                void navigator.clipboard.writeText(pending.secret).then(
                  () => {
                    props.say(t("methods.key_copied"));
                  },
                  () => undefined,
                );
              }}
            >
              {t("action.copy_key")}
            </Button>
            <a
              href={pending.uri}
              className={buttonVariants({
                variant: "link",
                size: "sm",
                className: "h-auto min-h-8 px-0 whitespace-normal",
              })}
            >
              {t("methods.authenticator_link")}
            </a>
          </Actions>
          <Field>
            <FieldLabel htmlFor="totp-code">{t("label.totp_code")}</FieldLabel>
            <Input
              id="totp-code"
              ref={code}
              size="md"
              name="code"
              autoComplete="one-time-code"
              inputMode="numeric"
              maxLength={10}
              spellCheck={false}
              required
            />
          </Field>
          <Actions>
            <Button type="submit">{t("action.verify")}</Button>
          </Actions>
        </form>
      )}
    </Part>
  );
}

function RecoveryCodes(props: {
  readonly methods: Methods;
  readonly reload: () => void;
  readonly say: (text: string, alert?: boolean) => void;
  readonly fail: (e: unknown, codes?: Readonly<Record<string, string>>) => void;
  readonly codes: readonly string[] | null;
  readonly setCodes: (codes: readonly string[] | null) => void;
}): ReactElement {
  const { codes, setCodes } = props;
  const list = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (codes !== null) list.current?.focus();
  }, [codes]);
  const state = props.methods.recovery_codes;
  const renew = useMutation({
    mutationFn: () => json(frontend("/v1/account/recovery-codes", { method: "POST" }), Codes),
    onSuccess: (r) => {
      setCodes(r.recovery_codes);
    },
    onError: (err) => {
      props.fail(err);
    },
  });
  const acknowledge = useMutation({
    mutationFn: () =>
      json(frontend("/v1/account/recovery-codes/acknowledgement", { method: "POST" })),
    onSuccess: () => {
      setCodes(null);
      props.say(t("methods.codes_saved"));
      props.reload();
    },
    onError: (err) => {
      props.fail(err);
    },
  });
  return (
    <Part aria-labelledby="codes-heading" data-testid="recovery-codes">
      <h4 id="codes-heading" className="font-semibold">
        {t("recovery_codes.title")}
      </h4>
      {codes === null ? (
        <>
          <Meta>
            {!state.set
              ? t("methods.recovery_codes_none")
              : state.acknowledged
                ? t("methods.recovery_codes_set")
                : t("methods.recovery_codes_unsaved")}
          </Meta>
          {state.set && <Meta>{t("methods.recovery_codes_replace")}</Meta>}
          <Actions>
            <Button
              variant="outline"
              onClick={() => {
                renew.mutate();
              }}
            >
              {t("action.new_recovery_codes")}
            </Button>
          </Actions>
        </>
      ) : (
        <div className="flex flex-col gap-3 rounded-xl bg-muted p-4">
          <h5
            tabIndex={-1}
            ref={list}
            className="rounded-sm text-sm font-semibold outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
          >
            {t("recovery_codes.save")}
          </h5>
          <ul className={cn(MONO, "grid gap-1 sm:grid-cols-2")} data-testid="code-list">
            {codes.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
          <Actions>
            <Button
              onClick={() => {
                acknowledge.mutate();
              }}
            >
              {t("action.codes_saved")}
            </Button>
          </Actions>
        </div>
      )}
    </Part>
  );
}

/** The sign-in methods section of S11. */
export function SignInMethods(): ReactElement {
  const queries = useQueryClient();
  const [codes, setCodes] = useState<readonly string[] | null>(null);
  const { data: methods, error } = useQuery({
    queryKey: KEY,
    queryFn: () => json(frontend("/v1/account/methods"), Methods),
  });
  const { say, fail: announce, region } = useAnnouncer(error);
  // TN-151: an account without an address gives one at a fresh sign-in, then adds the method
  const [noAddress, setNoAddress] = useState(false);
  const fail = (e: unknown, codes?: Readonly<Record<string, string>>) => {
    if (e instanceof Problem && e.code === "proof-unavailable") setNoAddress(true);
    announce(e, codes);
  };
  const reload = () => {
    void queries.invalidateQueries({ queryKey: KEY });
  };
  const removal = useMutation({
    mutationFn: (id: string) =>
      json(frontend(`/v1/account/methods/${encodeURIComponent(id)}`, { method: "DELETE" })),
    onSuccess: () => {
      say(t("methods.removed"));
      reload();
    },
    onError: (e) => {
      fail(e, REMOVE_CODES);
    },
  });
  const [confirming, setConfirming] = useState<{ id: string; label: string } | null>(null);
  const remove = (id: string, label: string) => {
    setConfirming({ id, label });
  };
  return (
    <Panel
      aria-labelledby="methods-heading"
      data-testid="sign-in-methods"
      title={t("settings.sign_in_methods")}
      titleId="methods-heading"
    >
      {region}
      {noAddress && (
        <Actions>
          <a
            className={buttonVariants({ variant: "outline" })}
            data-testid="add-address"
            href={`${FRONTEND}/login`}
          >
            {t("methods.add_address")}
          </a>
        </Actions>
      )}
      <AlertDialog
        open={confirming !== null}
        onOpenChange={(open) => {
          if (!open) setConfirming(null);
        }}
      >
        <AlertDialogContent data-testid="remove-method-dialog">
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("methods.remove_title", { method: confirming?.label ?? "" })}
            </AlertDialogTitle>
            <AlertDialogDescription>{t("methods.remove_body")}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("action.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={() => {
                if (confirming !== null) removal.mutate(confirming.id);
              }}
            >
              {t("action.remove")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      {methods === undefined ? (
        <Loading rows={4} />
      ) : (
        <>
          <Passkeys methods={methods} reload={reload} say={say} fail={fail} remove={remove} />
          <Password
            set={methods.password.set}
            pin={methods.password.kind === "pin"}
            reload={reload}
            say={say}
            fail={fail}
          />
          {methods.phone !== null && <Phone phone={methods.phone} say={say} fail={fail} />}
          {methods.identity !== null && <Identity identity={methods.identity} />}
          <Authenticator
            methods={methods}
            reload={reload}
            say={say}
            fail={fail}
            remove={remove}
            onCodes={setCodes}
          />
          <RecoveryCodes
            methods={methods}
            reload={reload}
            say={say}
            fail={fail}
            codes={codes}
            setCodes={setCodes}
          />
        </>
      )}
    </Panel>
  );
}
