// CR-41, CR-44, HL-27, OP-159 m.3 (g), (o), (r), (t)
import { useState, type ReactElement } from "react";

import { Button } from "@suiss/access-ui/components/ui/button";

import { t } from "../i18n/index.js";
import { adminGet, change, type WriteResult } from "../lib/admin.js";
import { Problem } from "../lib/api.js";
import { CHOICE, CHOICE_LABEL, FORM, MONO, Notice } from "../ui.js";
import { at, type Ctx, Panel, Show, useLoad, useRun } from "./parts.js";

type Profile = "ml-dsa-65" | "ml-dsa-44" | "ml-dsa-87";
type KexShare = "optimistic" | "advertise-only";

interface SigningView {
  readonly signing_profile: Profile | null;
  readonly algorithms: readonly string[];
  readonly kex_share: KexShare;
  readonly fips: boolean;
  readonly fips_module: boolean;
  readonly governing_domain: string;
  readonly pq_reanchor: {
    readonly size: number;
    readonly time: number;
    readonly witnesses: readonly string[];
  } | null;
}

const PROFILES: readonly Profile[] = ["ml-dsa-65", "ml-dsa-44", "ml-dsa-87"];

const ALG: Record<Profile, string> = {
  "ml-dsa-65": "ML-DSA-65",
  "ml-dsa-44": "ML-DSA-44",
  "ml-dsa-87": "ML-DSA-87",
};

/** The refusal a profile change can meet, in words. */
function refusal(e: unknown): string | undefined {
  if (!(e instanceof Problem)) return undefined;
  if (e.code === "fips-pq-exclusive") return t("signingFipsPqExclusive");
  if (e.code === "pq-key-unavailable") return t("signingKeyUnavailable");
  return undefined;
}

function ProfilePanel({ ctx, v }: { readonly ctx: Ctx; readonly v: SigningView }): ReactElement {
  const [profile, setProfile] = useState<Profile>(v.signing_profile ?? "ml-dsa-65");
  const [w, write] = useRun<WriteResult>();
  const [refused, setRefused] = useState<string>();
  const submit = (body: Record<string, string>) => {
    setRefused(undefined);
    write(async () => {
      try {
        return await change(ctx.instance, ctx.confirm, ctx.session.realm, {
          operation: "putSigningProfile",
          method: "PUT",
          path: "settings/signing-profile",
          body,
        });
      } catch (e) {
        setRefused(refusal(e));
        throw e;
      }
    });
  };
  return (
    <Panel
      id="signing-profile"
      title={
        v.signing_profile === null
          ? t("signingPqOff")
          : t("signingPqOn", { alg: ALG[v.signing_profile] })
      }
    >
      <p data-testid="signing-algorithms" className={`${MONO} text-sm`}>
        {v.algorithms.join(", ")}
      </p>
      {v.fips ? (
        <Notice role="note" data-testid="signing-fips-exclusive">
          {t("signingFipsPqExclusive")}
        </Notice>
      ) : v.signing_profile === null ? (
        <form
          className={FORM}
          onSubmit={(e) => {
            e.preventDefault();
            submit({ profile });
          }}
        >
          {PROFILES.map((p) => (
            <label key={p} className={CHOICE_LABEL}>
              <input
                className={CHOICE}
                type="radio"
                name="signing-profile"
                value={p}
                checked={profile === p}
                onChange={() => {
                  setProfile(p);
                }}
              />
              {ALG[p]}
            </label>
          ))}
          <Button type="submit" className="self-start">
            {t("settingsSave")}
          </Button>
        </form>
      ) : (
        <Button
          variant="destructive"
          className="self-start"
          data-testid="signing-turn-off"
          onPress={() => {
            submit({});
          }}
        >
          {t("signingPqTurnOff")}
        </Button>
      )}
      {refused !== undefined && (
        <Notice tone="danger" role="alert" data-testid="signing-refused">
          {refused}
        </Notice>
      )}
      <Show l={w}>
        {(r) => <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>}
      </Show>
    </Panel>
  );
}

function KexPanel({ ctx, v }: { readonly ctx: Ctx; readonly v: SigningView }): ReactElement {
  const [mode, setMode] = useState<KexShare>(v.kex_share);
  const [w, write] = useRun<WriteResult>();
  const label = (m: KexShare) =>
    m === "optimistic" ? t("signingKexOptimistic") : t("signingKexAdvertise");
  return (
    <Panel id="signing-kex" title={t("signingKexShare", { mode: label(v.kex_share) })}>
      <form
        className={FORM}
        onSubmit={(e) => {
          e.preventDefault();
          write(() =>
            change(ctx.instance, ctx.confirm, ctx.session.realm, {
              operation: "putKexShare",
              method: "PUT",
              path: "settings/kex-share",
              body: { mode },
            }),
          );
        }}
      >
        {(["optimistic", "advertise-only"] as const).map((m) => (
          <label key={m} className={CHOICE_LABEL}>
            <input
              className={CHOICE}
              type="radio"
              name="kex-share"
              value={m}
              checked={mode === m}
              onChange={() => {
                setMode(m);
              }}
            />
            {label(m)}
          </label>
        ))}
        <Button type="submit" className="self-start" isDisabled={mode === v.kex_share}>
          {t("settingsSave")}
        </Button>
      </form>
      <Show l={w}>
        {(r) => <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>}
      </Show>
    </Panel>
  );
}

/** The signing screen. */
export function Signing({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const realm = encodeURIComponent(ctx.session.realm);
  const view = useLoad(() => adminGet<SigningView>(ctx.instance, `realms/${realm}/signing`));
  return (
    <div data-testid="signing" className="flex flex-col gap-6">
      <p>{t("signingIntro")}</p>
      <Show l={view}>
        {(v) => (
          <>
            <ProfilePanel ctx={ctx} v={v} />
            <KexPanel ctx={ctx} v={v} />
            <p
              data-testid="signing-fips-module"
              className="text-sm text-muted-foreground"
              data-module={v.fips_module ? "true" : "false"}
            >
              {t("signingFipsModule", {
                state: v.fips_module ? t("signingFipsModuleInUse") : t("signingFipsModuleNotInUse"),
              })}
            </p>
            <p data-testid="signing-pq-anchor" className="text-sm text-muted-foreground">
              {v.pq_reanchor === null
                ? t("signingNoAnchor")
                : t("signingAnchor", {
                    size: String(v.pq_reanchor.size),
                    time: at(v.pq_reanchor.time),
                  })}
            </p>
          </>
        )}
      </Show>
    </div>
  );
}
