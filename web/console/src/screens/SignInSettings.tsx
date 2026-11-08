// §8.17.4.1 identity plane note, E34, MD-14: realm configuration. Every change is drafted, shown
// on the signature screen and committed as one Exercise. The RP ID change is marked irreversible
// for passkeys (TN-17, X-L12); a new realm's first 90 minutes are shown (TN-111, CR-25); delayed
// signals (§8.13) and a missing GeoIP source (OP-151 m.3 (b)) are stated, never hidden.
import { useState, type ReactElement } from "react";

import { t } from "../i18n/index.js";
import { adminGet, change, type WriteResult } from "../lib/admin.js";
import { Problem } from "../lib/api.js";
import { type Ctx, at, Field, Panel, Show, useLoad, useRun } from "./parts.js";
import { UpstreamLink } from "./UpstreamLink.js";

interface Settings {
  readonly rp_id?: string | null;
  readonly signin_policy?: unknown;
  readonly session_policy?: unknown;
  readonly branding?: { readonly display_name?: string | null };
  /** Sections the repository manages (GitOps); shown read-only. */
  readonly managed?: readonly string[];
}

interface RealmMetadata {
  readonly key_state?: "pending" | "published" | "signing" | "unavailable";
  readonly signing_available_at?: string | null;
}

interface Signals {
  readonly transmitters?: readonly {
    readonly name: string;
    readonly delayed_since?: number | null;
  }[];
  readonly geoip?: "configured" | "not_configured" | "unreadable";
  readonly verifiers?: readonly { readonly name: string; readonly declared_until: number }[];
}

export interface AnalyticsDay {
  readonly day: string;
  readonly started: number;
  readonly completed: number;
  readonly failed: number;
  readonly passkey_accounts: number;
  readonly mfa_setup: number;
  readonly legacy_password_accounts?: number;
  readonly methods?: Readonly<Record<string, number>>;
}

interface Analytics {
  readonly days: readonly AnalyticsDay[];
  readonly surges?: readonly { readonly day: string; readonly failed: number }[];
}

const KEY_STATE = {
  pending: "keyPending",
  published: "keyPublished",
  signing: "keySigning",
  unavailable: "keyUnavailable",
} as const;

function realmPath(ctx: Ctx, rest = ""): string {
  return `realms/${encodeURIComponent(ctx.session.realm)}${rest}`;
}

/** §8.13, Ek B 2963, 3034: delayed signals, missing GeoIP and verifier reports. */
function Status({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const l = useLoad(() => adminGet<Signals>(ctx.instance, realmPath(ctx, "/signals")));
  if (l.status !== "done") return <></>;
  const s = l.value;
  return (
    <div data-testid="signal-status">
      {(s.transmitters ?? [])
        .filter((x) => x.delayed_since !== undefined && x.delayed_since !== null)
        .map((x) => (
          <p key={x.name} role="status" className="banner">
            {t("signalsDelayed", { provider: x.name, since: at(x.delayed_since) })}
          </p>
        ))}
      {/* OP-151 m.3 (o): a source that is missing or cannot be read is stated */}
      {s.geoip !== undefined && s.geoip !== "configured" && (
        <p role="status" className="banner">
          <strong>{t("geoipMissing")}</strong> — {t("geoipMissingText")}
        </p>
      )}
      {(s.verifiers ?? []).map((v) => (
        <p key={v.name} role="status" className="banner">
          {t("verifierMissing", { verifier: v.name, until: at(v.declared_until) })}
        </p>
      ))}
    </div>
  );
}

function Keys({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const l = useLoad(() =>
    adminGet<RealmMetadata>(
      ctx.instance,
      `platform/realms/${encodeURIComponent(ctx.session.realm)}`,
    ),
  );
  return (
    <Panel id="keys" title={t("settingsKeys")}>
      <Show l={l}>
        {(m) => (
          <>
            {m.key_state !== undefined && (
              <p data-testid="key-state">{t(KEY_STATE[m.key_state])}</p>
            )}
            {m.key_state !== "signing" &&
              m.signing_available_at !== undefined &&
              m.signing_available_at !== null && (
                <p data-testid="signing-at">{t("signingAt", { at: at(m.signing_available_at) })}</p>
              )}
          </>
        )}
      </Show>
    </Panel>
  );
}

function Branding({ ctx, s }: { readonly ctx: Ctx; readonly s: Settings }): ReactElement {
  const managed = (s.managed ?? []).includes("branding");
  const [name, setName] = useState(s.branding?.display_name ?? "");
  const [w, write] = useRun<WriteResult>();
  return (
    <Panel id="branding" title={t("settingsBranding")}>
      {managed ? (
        <>
          <p className="hint">{t("settingsGitops")}</p>
          <p data-testid="branding-name">{s.branding?.display_name ?? ""}</p>
        </>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            write(() =>
              change(ctx.instance, ctx.confirm, ctx.session.realm, {
                operation: "patchBranding",
                method: "PATCH",
                path: "settings/branding",
                body: { display_name: name },
              }),
            );
          }}
        >
          <Field id="brand-name" label={t("settingsBrandName")} value={name} onChange={setName} />
          <button type="submit">{t("settingsSave")}</button>
        </form>
      )}
      <Show l={w}>
        {(r) => <p role="status">{t("changeRecorded", { exercise: r.exercise_id })}</p>}
      </Show>
    </Panel>
  );
}

/** §8.10, TN-17, IDI-4: an RP ID change is irreversible for passkeys; the count confirms it. */
function RpId({ ctx, s }: { readonly ctx: Ctx; readonly s: Settings }): ReactElement {
  const managed = (s.managed ?? []).includes("rp_id");
  const [rp, setRp] = useState("");
  const [count, setCount] = useState("");
  const [w, write] = useRun<WriteResult>();
  const [mismatch, setMismatch] = useState(false);
  return (
    <Panel id="rp-id" title={t("settingsRpTitle")}>
      <dl className="facts">
        <dt>{t("settingsRpCurrent")}</dt>
        <dd className="mono">{s.rp_id ?? ""}</dd>
      </dl>
      <p role="note" className="banner" data-testid="rp-warning">
        {t("settingsRpWarning")}
      </p>
      {managed ? (
        <p className="hint">{t("settingsGitops")}</p>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setMismatch(false);
            write(() =>
              change(ctx.instance, ctx.confirm, ctx.session.realm, {
                operation: "putRpId",
                method: "PUT",
                path: "settings/rp-id",
                body: { rp_id: rp, acknowledge_passkey_loss: count },
              }).catch((err: unknown) => {
                if (err instanceof Problem && err.code === "passkey-loss-not-acknowledged") {
                  setMismatch(true);
                }
                throw err;
              }),
            );
          }}
        >
          <Field id="rp-new" label={t("settingsRpNew")} value={rp} onChange={setRp} />
          <Field
            id="rp-count"
            label={t("settingsRpCount")}
            value={count}
            onChange={setCount}
            hint={t("settingsRpCountHint")}
            type="number"
          />
          <button type="submit" disabled={rp === "" || count === ""}>
            {t("settingsSave")}
          </button>
        </form>
      )}
      {mismatch ? (
        <p role="alert">{t("settingsRpMismatch")}</p>
      ) : (
        <Show l={w}>{() => <p role="status">{t("settingsRpIrreversible")}</p>}</Show>
      )}
      <h4>{t("settingsRelated")}</h4>
      <p data-testid="related-origins">{t("settingsRelatedText")}</p>
    </Panel>
  );
}

interface Named {
  readonly items: readonly {
    readonly client_id?: string;
    readonly name?: string;
    readonly display_name?: string;
    readonly status?: string;
  }[];
}

function Listing({
  ctx,
  path,
  title,
  id,
}: {
  readonly ctx: Ctx;
  readonly path: string;
  readonly title: string;
  readonly id: string;
}): ReactElement {
  const l = useLoad(() => adminGet<Named>(ctx.instance, realmPath(ctx, path)));
  return (
    <Panel id={id} title={title}>
      <Show l={l}>
        {(v) => (
          <ul>
            {v.items.map((c) => {
              const key = c.client_id ?? c.name ?? "";
              return (
                <li key={key}>
                  <span className="mono">{key}</span>
                  {c.display_name !== undefined && ` — ${c.display_name}`}
                  {c.status === "retired" && ` (${t("statusRetired")})`}
                </li>
              );
            })}
          </ul>
        )}
      </Show>
    </Panel>
  );
}

interface SocialWarning {
  readonly code: string;
  readonly at?: string;
  readonly until?: string;
}

interface Socials {
  readonly items: readonly {
    readonly preset: string;
    readonly client_id?: string | null;
    readonly shared_development_client: boolean;
    readonly status: "active" | "disabled";
    readonly warnings: readonly SocialWarning[];
  }[];
}

/** One social warning as text; a warning never refuses anything (TN-87, IDP-31 (5)). */
function socialWarning(w: SocialWarning): string {
  if (w.until !== undefined) return t("socialAppleWindow", { until: w.until });
  if (w.at !== undefined) return t("socialClientChanged", { at: w.at });
  if (w.code === "apple-sign-in-recommended") return t("socialAppleRecommended");
  return w.code;
}

/** IDP-31, TN-87, Ek B 3572, 3655: the social presets and their warnings. */
function SocialProviders({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const l = useLoad(() => adminGet<Socials>(ctx.instance, realmPath(ctx, "/social-providers")));
  return (
    <Panel id="social" title={t("settingsSocial")}>
      <Show l={l}>
        {(v) => (
          <ul data-testid="social-providers">
            {v.items.map((s) => (
              <li key={s.preset}>
                <span className="mono">{s.preset}</span>
                {s.status === "disabled" && ` (${t("socialDisabled")})`}
                {s.shared_development_client && ` — ${t("socialSharedClient")}`}
                {s.warnings.map((w) => (
                  <p key={w.code} role="status" className="banner" data-testid="social-warning">
                    {socialWarning(w)}
                  </p>
                ))}
              </li>
            ))}
          </ul>
        )}
      </Show>
    </Panel>
  );
}

/** IDP-36, K14: counts only, never a decision input. */
export function AnalyticsPanel({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const l = useLoad(() => adminGet<Analytics>(ctx.instance, realmPath(ctx, "/analytics")));
  return (
    <Panel id="analytics" title={t("analyticsTitle")}>
      <p className="badge" data-testid="analytics-note">
        {t("analyticsNote")}
      </p>
      <Show l={l}>
        {(a) => (
          <>
            {a.days.length > 0 && (
              <p data-testid="analytics-legacy">
                {t("analyticsLegacy", {
                  count: String(a.days[a.days.length - 1]?.legacy_password_accounts ?? 0),
                })}
              </p>
            )}
            {(a.surges ?? []).map((s) => (
              <p key={s.day} role="status" className="banner">
                {t("analyticsSurge", { day: s.day, count: String(s.failed) })}
              </p>
            ))}
            <table>
              <thead>
                <tr>
                  <th scope="col">{t("analyticsDay")}</th>
                  <th scope="col">{t("analyticsStarted")}</th>
                  <th scope="col">{t("analyticsCompleted")}</th>
                  <th scope="col">{t("analyticsFailed")}</th>
                  <th scope="col">{t("analyticsPasskey")}</th>
                  <th scope="col">{t("analyticsMfa")}</th>
                  <th scope="col">{t("analyticsMethods")}</th>
                </tr>
              </thead>
              <tbody>
                {a.days.map((d) => (
                  <tr key={d.day}>
                    <td>{d.day}</td>
                    <td>{d.started}</td>
                    <td>{d.completed}</td>
                    <td>{d.failed}</td>
                    <td>{d.passkey_accounts}</td>
                    <td>{d.mfa_setup}</td>
                    <td className="mono">
                      {Object.entries(d.methods ?? {})
                        .map(([m, n]) => `${m}: ${String(n)}`)
                        .join(", ")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </Show>
    </Panel>
  );
}

export function SignInSettings({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const l = useLoad(() => adminGet<Settings>(ctx.instance, realmPath(ctx, "/settings")));
  return (
    <>
      <p>{t("settingsIntro")}</p>
      <Status ctx={ctx} />
      <Keys ctx={ctx} />
      <Show l={l}>
        {(s) => (
          <>
            <Branding ctx={ctx} s={s} />
            <RpId ctx={ctx} s={s} />
          </>
        )}
      </Show>
      <Listing ctx={ctx} path="/clients" title={t("settingsClients")} id="clients" />
      <Listing ctx={ctx} path="/upstream-idps" title={t("settingsUpstreams")} id="upstreams" />
      <SocialProviders ctx={ctx} />
      <UpstreamLink ctx={ctx} />
      <AnalyticsPanel ctx={ctx} />
    </>
  );
}
