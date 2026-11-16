// S11 (§8.5, §8.8; TN-99, TN-64, TN-68, TN-107, OP-148): the ways this person signs in, on the
// session cookie alone. Passkeys are created, seen and removed here (the first FIDO pattern; the
// sign-in fallback stays on the hosted login). The authenticator app's key is shown as text with
// a copy button, so a QR code is never the only path; its code is one pasteable field. Removing
// the last way to sign in is refused by the server and said plainly.
import { Button, buttonVariants } from "@access/ui/components/button";
import { Field, FieldLabel } from "@access/ui/components/field";
import { Input } from "@access/ui/components/input";
import { ItemActions, ItemContent } from "@access/ui/components/item";
import { cn } from "@access/ui/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ReactElement, type SyntheticEvent, useEffect, useRef, useState } from "react";
import * as v from "valibot";

import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { Actions, Loading, Meta, MONO, Panel, Part, RowItem, Rows } from "../lib/ui.js";
import { useAnnouncer, when } from "./common.js";

/** What `GET /v1/account/methods` answers. */
export const Methods = v.object({
  password: v.object({ set: v.boolean() }),
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
});
export type Methods = v.InferOutput<typeof Methods>;

const Enrollment = v.object({ enrollment: v.string(), secret: v.string(), uri: v.string() });
type Enrollment = v.InferOutput<typeof Enrollment>;

const Registration = v.object({
  registration: v.string(),
  options: v.record(v.string(), v.unknown()),
});

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
  readonly remove: (id: string) => void;
}): ReactElement {
  const [name, setName] = useState("");
  const create = useMutation({
    mutationFn: async (label: string): Promise<boolean> => {
      const reg = await json(
        frontend("/v1/account/passkeys", { method: "POST", body: { name: label } }),
        Registration,
      );
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
    },
    onSuccess: (created) => {
      if (!created) {
        props.say(t("methods.passkey_failed"), true);
        return;
      }
      setName("");
      props.say(t("methods.added"));
      props.reload();
    },
    onError: (err) => {
      // OP-159 m.3 (ll)
      props.fail(err, {
        "attestation-format": t("passkey.attestation_refused"),
        "attestation-revocation-unknown": t("passkey.attestation_unknown"),
      });
    },
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
                    props.remove(p.id);
                  }}
                >
                  {t("action.remove")}
                </Button>
              </ItemActions>
            </RowItem>
          ))}
        </Rows>
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
      props.fail(err, { "password-rejected": "methods.password_rejected" });
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
        {t("methods.password")}
      </h4>
      <Meta>{props.set ? t("methods.password_set") : t("methods.password_none")}</Meta>
      {open ? (
        <form onSubmit={save} className="flex flex-col gap-3">
          <Field>
            <FieldLabel htmlFor="new-password">{t("label.new_password")}</FieldLabel>
            <Input
              id="new-password"
              ref={field}
              size="md"
              name="new_password"
              type="password"
              autoComplete="new-password"
              maxLength={128}
              required
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
            {props.set ? t("action.change_password") : t("action.set_password")}
          </Button>
        </Actions>
      )}
    </Part>
  );
}

function Authenticator(props: {
  readonly methods: Methods;
  readonly reload: () => void;
  readonly say: (text: string, alert?: boolean) => void;
  readonly fail: (e: unknown, codes?: Readonly<Record<string, string>>) => void;
  readonly remove: (id: string) => void;
  readonly onCodes: (codes: readonly string[]) => void;
}): ReactElement {
  const [pending, setPending] = useState<Enrollment | null>(null);
  const code = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (pending !== null) code.current?.focus();
  }, [pending]);
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
      props.fail(err);
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
                    props.remove(m.id);
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
            {t("action.add_authenticator")}
          </Button>
        </Actions>
      ) : (
        <form
          onSubmit={confirm}
          className="flex flex-col gap-3 rounded-xl border p-4"
          data-testid="totp-enrollment"
        >
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
  const { say, fail, region } = useAnnouncer(error);
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
  const remove = (id: string) => {
    removal.mutate(id);
  };
  return (
    <Panel
      aria-labelledby="methods-heading"
      data-testid="sign-in-methods"
      title={t("settings.sign_in_methods")}
      titleId="methods-heading"
    >
      {region}
      {methods === undefined ? (
        <Loading rows={4} />
      ) : (
        <>
          <Passkeys methods={methods} reload={reload} say={say} fail={fail} remove={remove} />
          <Password set={methods.password.set} reload={reload} say={say} fail={fail} />
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
