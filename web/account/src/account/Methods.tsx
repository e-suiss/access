// S11 (§8.5, §8.8; TN-99, TN-64, TN-68, TN-107, OP-148): the ways this person signs in, on the
// session cookie alone. Passkeys are created, seen and removed here (the first FIDO pattern; the
// sign-in fallback stays on the hosted login). The authenticator app's key is shown as text with
// a copy button, so a QR code is never the only path; its code is one pasteable field. Removing
// the last way to sign in is refused by the server and said plainly.
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactElement,
  type SyntheticEvent,
} from "react";

import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { useAnnouncer, when } from "./common.js";

/** What `GET /v1/account/methods` answers. */
export interface Methods {
  readonly password: { readonly set: boolean };
  readonly passkeys: readonly {
    readonly id: string;
    readonly name: string | null;
    readonly created_at: string;
    readonly synced: boolean;
  }[];
  readonly totp: readonly { readonly id: string; readonly created_at: string }[];
  readonly recovery_codes: { readonly set: boolean; readonly acknowledged: boolean };
}

interface Enrollment {
  readonly enrollment: string;
  readonly secret: string;
  readonly uri: string;
}

interface Registration {
  readonly registration: string;
  readonly options: Readonly<Record<string, unknown>>;
}

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
  const [busy, setBusy] = useState(false);
  const add = (e: SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    setBusy(true);
    const label = name.trim() === "" ? t("methods.passkey_unnamed") : name.trim();
    void json<Registration>(
      frontend("/v1/account/passkeys", { method: "POST", body: { name: label } }),
    )
      .then(async (reg) => {
        let credential: unknown;
        try {
          credential = await createPasskey(reg.options);
        } catch {
          props.say(t("methods.passkey_failed"), true);
          return;
        }
        await json(
          frontend(`/v1/account/passkeys/${encodeURIComponent(reg.registration)}`, {
            method: "POST",
            body: { credential },
          }),
        );
        setName("");
        props.say(t("methods.added"));
        props.reload();
      })
      .catch((err: unknown) => {
        props.fail(err);
      })
      .finally(() => {
        setBusy(false);
      });
  };
  return (
    <section aria-labelledby="passkeys-heading" data-testid="passkeys">
      <h4 id="passkeys-heading">{t("methods.passkeys")}</h4>
      <ul className="rows">
        {props.methods.passkeys.map((p) => (
          <li key={p.id} className="row" data-testid="passkey-row">
            <strong>{p.name ?? t("methods.passkey_unnamed")}</strong>
            <span className="meta">
              {" · "}
              {p.synced ? t("methods.passkey_synced") : t("methods.passkey_this_device")}
              {" · "}
              {t("methods.added_on", { date: when(p.created_at) })}
            </span>
            <div className="actions">
              <button
                type="button"
                className="secondary"
                aria-label={`${t("action.remove")}: ${p.name ?? t("methods.passkey_unnamed")}`}
                onClick={() => {
                  props.remove(p.id);
                }}
              >
                {t("action.remove")}
              </button>
            </div>
          </li>
        ))}
      </ul>
      <form onSubmit={add} className="actions">
        <label htmlFor="passkey-name">{t("methods.passkey_name")}</label>
        <input
          id="passkey-name"
          value={name}
          maxLength={64}
          autoComplete="off"
          onChange={(e) => {
            setName(e.target.value);
          }}
        />
        <button type="submit" disabled={busy}>
          {t("action.passkey_create")}
        </button>
      </form>
    </section>
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
  const save = (e: SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    const value = new FormData(e.currentTarget).get("new_password");
    if (typeof value !== "string" || value === "") return;
    void json(frontend("/v1/account/password", { method: "PUT", body: { new_password: value } }))
      .then(() => {
        setOpen(false);
        props.say(t("methods.password_saved"));
        props.reload();
      })
      .catch((err: unknown) => {
        props.fail(err, { "password-rejected": "methods.password_rejected" });
      });
  };
  return (
    <section aria-labelledby="password-heading" data-testid="password">
      <h4 id="password-heading">{t("methods.password")}</h4>
      <p>{props.set ? t("methods.password_set") : t("methods.password_none")}</p>
      {open ? (
        <form onSubmit={save}>
          <label htmlFor="new-password">{t("label.new_password")}</label>
          <input
            id="new-password"
            ref={field}
            name="new_password"
            type="password"
            autoComplete="new-password"
            maxLength={128}
            required
          />
          <div className="actions">
            <button type="submit">{t("action.save")}</button>
            <button
              type="button"
              className="secondary"
              onClick={() => {
                setOpen(false);
              }}
            >
              {t("action.cancel")}
            </button>
          </div>
        </form>
      ) : (
        <button
          type="button"
          onClick={() => {
            setOpen(true);
          }}
        >
          {props.set ? t("action.change_password") : t("action.set_password")}
        </button>
      )}
    </section>
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
  const begin = () => {
    void json<Enrollment>(
      frontend("/v1/account/totp", { method: "POST", body: { label: "account" } }),
    )
      .then(setPending)
      .catch((err: unknown) => {
        props.fail(err);
      });
  };
  const confirm = (e: SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (pending === null) return;
    const value = new FormData(e.currentTarget).get("code");
    if (typeof value !== "string") return;
    void json<{ recovery_codes?: string[] }>(
      frontend(`/v1/account/totp/${encodeURIComponent(pending.enrollment)}`, {
        method: "POST",
        body: { code: value.replace(/\s+/g, "") },
      }),
    )
      .then((done) => {
        setPending(null);
        props.say(t("methods.authenticator_added"));
        if (done.recovery_codes !== undefined) props.onCodes(done.recovery_codes);
        props.reload();
      })
      .catch((err: unknown) => {
        props.fail(err, {
          "code-invalid": "methods.code_failed",
          "totp-invalid": "methods.code_failed",
          "second-factor-failed": "methods.code_failed",
          "invalid-code": "methods.code_failed",
        });
      });
  };
  return (
    <section aria-labelledby="totp-heading" data-testid="authenticator">
      <h4 id="totp-heading">{t("methods.authenticator")}</h4>
      {props.methods.totp.length === 0 && pending === null && (
        <p>{t("methods.authenticator_none")}</p>
      )}
      <ul className="rows">
        {props.methods.totp.map((m) => (
          <li key={m.id} className="row" data-testid="totp-row">
            {t("methods.added_on", { date: when(m.created_at) })}
            <div className="actions">
              <button
                type="button"
                className="secondary"
                aria-label={`${t("action.remove")}: ${t("methods.authenticator")}`}
                onClick={() => {
                  props.remove(m.id);
                }}
              >
                {t("action.remove")}
              </button>
            </div>
          </li>
        ))}
      </ul>
      {pending === null ? (
        <button type="button" onClick={begin}>
          {t("action.add_authenticator")}
        </button>
      ) : (
        <form onSubmit={confirm} className="panel" data-testid="totp-enrollment">
          <p id="totp-key-label">{t("methods.authenticator_key")}</p>
          <p className="mono" aria-labelledby="totp-key-label" data-testid="totp-secret">
            {pending.secret}
          </p>
          <div className="actions">
            <button
              type="button"
              className="secondary"
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
            </button>
            <a href={pending.uri}>{t("methods.authenticator_link")}</a>
          </div>
          <label htmlFor="totp-code">{t("label.totp_code")}</label>
          <input
            id="totp-code"
            ref={code}
            name="code"
            autoComplete="one-time-code"
            inputMode="numeric"
            maxLength={10}
            spellCheck={false}
            required
          />
          <button type="submit">{t("action.verify")}</button>
        </form>
      )}
    </section>
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
  return (
    <section aria-labelledby="codes-heading" data-testid="recovery-codes">
      <h4 id="codes-heading">{t("recovery_codes.title")}</h4>
      {codes === null ? (
        <>
          <p>
            {!state.set
              ? t("methods.recovery_codes_none")
              : state.acknowledged
                ? t("methods.recovery_codes_set")
                : t("methods.recovery_codes_unsaved")}
          </p>
          {state.set && <p className="notice">{t("methods.recovery_codes_replace")}</p>}
          <button
            type="button"
            onClick={() => {
              void json<{ recovery_codes: string[] }>(
                frontend("/v1/account/recovery-codes", { method: "POST" }),
              )
                .then((r) => {
                  setCodes(r.recovery_codes);
                })
                .catch((err: unknown) => {
                  props.fail(err);
                });
            }}
          >
            {t("action.new_recovery_codes")}
          </button>
        </>
      ) : (
        <div className="panel">
          <h5 tabIndex={-1} ref={list}>
            {t("recovery_codes.save")}
          </h5>
          <ul className="mono" data-testid="code-list">
            {codes.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
          <button
            type="button"
            onClick={() => {
              void json(frontend("/v1/account/recovery-codes/acknowledgement", { method: "POST" }))
                .then(() => {
                  setCodes(null);
                  props.say(t("methods.codes_saved"));
                  props.reload();
                })
                .catch((err: unknown) => {
                  props.fail(err);
                });
            }}
          >
            {t("action.codes_saved")}
          </button>
        </div>
      )}
    </section>
  );
}

/** The sign-in methods section of S11. */
export function SignInMethods(): ReactElement {
  const [methods, setMethods] = useState<Methods | null>(null);
  const [codes, setCodes] = useState<readonly string[] | null>(null);
  const { say, fail, region } = useAnnouncer();
  const reload = useCallback(() => {
    json<Methods>(frontend("/v1/account/methods"))
      .then(setMethods)
      .catch((e: unknown) => {
        fail(e);
      });
  }, [fail]);
  useEffect(reload, [reload]);
  const remove = (id: string) => {
    void json(frontend(`/v1/account/methods/${encodeURIComponent(id)}`, { method: "DELETE" }))
      .then(() => {
        say(t("methods.removed"));
        reload();
      })
      .catch((e: unknown) => {
        fail(e, REMOVE_CODES);
      });
  };
  return (
    <section aria-labelledby="methods-heading" data-testid="sign-in-methods">
      <h3 id="methods-heading">{t("settings.sign_in_methods")}</h3>
      {region}
      {methods === null ? (
        <p>{t("shell.loading")}</p>
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
    </section>
  );
}
