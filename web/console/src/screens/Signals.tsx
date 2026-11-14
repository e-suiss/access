// OP-156 m.3 (r), E38, §8.10, §8.13: the realm's signal sources. A KYC provider, an MDM, a risk
// service or a DLP system is registered as the issuer whose Claims it sends; registering it gives
// them no effect, which comes only from the domain's own Acceptance and policies. A posture is
// the provider's statement ("Compliant per Acme MDM (statement)"), never Access's own, and a
// delayed source is stated, never hidden. Each change is one signed Exercise.
import { useState, type ReactElement } from "react";

import { Button } from "@suiss/access-ui/components/ui/button";
import { Field as FieldRoot, FieldLabel } from "@suiss/access-ui/components/ui/field";
import { NativeSelect, NativeSelectOption } from "@suiss/access-ui/components/ui/native-select";

import { t } from "../i18n/index.js";
import { adminGet, change, type WriteResult } from "../lib/admin.js";
import { ACTIONS, FORM, H4, HINT, MONO, Notice, ROW, ROWLIST } from "../ui.js";
import { type Ctx, Field, Panel, Show, useLoad, useRun } from "./parts.js";

interface Source {
  readonly name: string;
  readonly kind: "kyc" | "mdm" | "risk" | "dlp";
  readonly class: string;
  readonly provider: string;
  readonly issuer: string;
  readonly format: string;
  readonly transmitter?: string | null;
  readonly status: string;
}

const KIND = {
  kyc: "signalKindKyc",
  mdm: "signalKindMdm",
  risk: "signalKindRisk",
  dlp: "signalKindDlp",
} as const;

/** The signal sources panel of the realm's sign-in settings. */
export function Signals({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const realm = encodeURIComponent(ctx.session.realm);
  const list = useLoad(() =>
    adminGet<{ readonly items: readonly Source[] }>(ctx.instance, `realms/${realm}/signal-sources`),
  );
  const [name, setName] = useState("");
  const [kind, setKind] = useState<Source["kind"]>("mdm");
  const [provider, setProvider] = useState("");
  const [issuer, setIssuer] = useState("");
  const [w, write] = useRun<WriteResult>();
  const send = (operation: string, path: string, body: Record<string, unknown>, key?: string) => {
    write(() =>
      change(ctx.instance, ctx.confirm, ctx.session.realm, {
        operation,
        ...(key === undefined ? {} : { key }),
        method: "POST",
        path,
        body,
      }),
    );
  };
  return (
    <Panel id="signal-sources" title={t("signalSourcesTitle")}>
      <p>{t("signalSourcesIntro")}</p>
      <p className={HINT} data-testid="signal-posture-note">
        {t("signalPostureNote", { provider: "Acme MDM" })}
      </p>
      <Show l={list}>
        {(p) =>
          p.items.length === 0 ? (
            <p className={HINT}>{t("none")}</p>
          ) : (
            <ul data-testid="signal-sources" className={ROWLIST}>
              {p.items.map((s) => (
                <li key={s.name} className={ROW}>
                  <span className={MONO}>{s.name}</span> · {s.provider} · {t(KIND[s.kind])} ·{" "}
                  <span className={MONO}>{s.class}</span> ·{" "}
                  {s.status === "live" ? t("signalSourceLive") : t("signalSourceRetired")}
                  {s.status === "live" && (
                    <>
                      {" "}
                      <Button
                        variant="outline"
                        size="sm"
                        className="ms-auto"
                        onPress={() => {
                          send(
                            "retireSignalSource",
                            `signal-sources/${encodeURIComponent(s.name)}/retire`,
                            {},
                            s.name,
                          );
                        }}
                      >
                        {t("signalSourceRetire", { name: s.name })}
                      </Button>
                    </>
                  )}
                </li>
              ))}
            </ul>
          )
        }
      </Show>
      <form
        className={FORM}
        onSubmit={(e) => {
          e.preventDefault();
          send("registerSignalSource", "signal-sources", { name, kind, provider, issuer });
        }}
      >
        <h4 className={H4}>{t("signalSourceRegister")}</h4>
        <Field
          id="signal-name"
          label={t("signalSourceName")}
          value={name}
          onChange={setName}
          hint={t("sshGroupNameHint")}
        />
        <FieldRoot className="max-w-xl gap-2">
          <FieldLabel htmlFor="signal-kind" className="text-sm">
            {t("signalSourceKind")}
          </FieldLabel>
          <NativeSelect
            id="signal-kind"
            size="sm"
            value={kind}
            onChange={(e) => {
              setKind(e.target.value as Source["kind"]);
            }}
          >
            {(Object.keys(KIND) as Source["kind"][]).map((k) => (
              <NativeSelectOption key={k} value={k}>
                {t(KIND[k])}
              </NativeSelectOption>
            ))}
          </NativeSelect>
        </FieldRoot>
        <Field
          id="signal-provider"
          label={t("signalSourceProvider")}
          value={provider}
          onChange={setProvider}
        />
        <Field
          id="signal-issuer"
          label={t("signalSourceIssuer")}
          value={issuer}
          onChange={setIssuer}
          hint={t("signalSourceIssuerHint")}
        />
        <div className={ACTIONS}>
          <Button type="submit">{t("signalSourceRegisterSend")}</Button>
        </div>
      </form>
      <Show l={w}>
        {(r) => <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>}
      </Show>
    </Panel>
  );
}
