// §8.17.4.1 identity plane note, E34, MD-14: realm configuration. Every change is drafted, shown
// on the signature screen and committed as one Exercise. The RP ID change is marked irreversible
// for passkeys (TN-17, X-L12); a new realm's first 90 minutes are shown (TN-111, CR-25); delayed
// signals (§8.13) and a missing GeoIP source (OP-151 m.3 (b)) are stated, never hidden. The page
// CSP mode, the DBSC switch and the Related Origins are set here too (OP-153 m.22 (c), (g), (k)).
import { useState, type ReactElement } from "react";

import { Badge } from "@suiss/access-ui/components/ui/badge";
import { Button } from "@suiss/access-ui/components/ui/button";
import { Field as FieldRoot, FieldLabel } from "@suiss/access-ui/components/ui/field";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@suiss/access-ui/components/ui/table";
import { Textarea } from "@suiss/access-ui/components/ui/textarea";

import { t } from "../i18n/index.js";
import { adminGet, adminGetTagged, change, type WriteResult } from "../lib/admin.js";
import { Problem } from "../lib/api.js";
import { BULLETS, CHOICE, CHOICE_LABEL, FACTS, FORM, Failure, HINT, MONO, Notice } from "../ui.js";
import { type Ctx, at, Field, Panel, Show, useLoad, useRun } from "./parts.js";
import { Domains } from "./Domains.js";
import { Signals as SignalSources } from "./Signals.js";
import { UpstreamLink } from "./UpstreamLink.js";

interface Settings {
  readonly rp_id?: string | null;
  readonly signin_policy?: { readonly dbsc?: boolean };
  readonly session_policy?: unknown;
  readonly branding?: { readonly display_name?: string | null };
  readonly csp_mode?: "enforce" | "report_only";
  readonly related_origins?: readonly string[];
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
    <div data-testid="signal-status" className="flex flex-col gap-3 empty:hidden">
      {(s.transmitters ?? [])
        .filter((x) => x.delayed_since !== undefined && x.delayed_since !== null)
        .map((x) => (
          <Notice key={x.name} role="status" tone="warning">
            {t("signalsDelayed", { provider: x.name, since: at(x.delayed_since) })}
          </Notice>
        ))}
      {/* OP-151 m.3 (o): a source that is missing or cannot be read is stated */}
      {s.geoip !== undefined && s.geoip !== "configured" && (
        <Notice role="status" tone="warning">
          <strong>{t("geoipMissing")}</strong> — {t("geoipMissingText")}
        </Notice>
      )}
      {(s.verifiers ?? []).map((v) => (
        <Notice key={v.name} role="status" tone="warning">
          {t("verifierMissing", { verifier: v.name, until: at(v.declared_until) })}
        </Notice>
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

/** The settings view and the `ETag` its `PUT`s and `PATCH`es send (OP-65). */
interface Tagged {
  readonly s: Settings;
  readonly etag?: string;
}

/** OP-153 m.22 (g): report-only loosens the page and is the higher tier; enforce tightens it. */
function CspMode({ ctx, s, etag }: { readonly ctx: Ctx } & Tagged): ReactElement {
  const current = s.csp_mode ?? "enforce";
  const [mode, setMode] = useState<"enforce" | "report_only">(current);
  const [w, write] = useRun<WriteResult>();
  const label = (m: "enforce" | "report_only") =>
    m === "enforce" ? t("settingsCspEnforce") : t("settingsCspReportOnly");
  return (
    <Panel id="csp-mode" title={t("settingsCspMode")}>
      <p>
        {t("settingsCspCurrent")}:{" "}
        <Badge variant="outline" data-testid="csp-current">
          {label(current)}
        </Badge>
      </p>
      <form
        className={FORM}
        onSubmit={(e) => {
          e.preventDefault();
          write(() =>
            change(ctx.instance, ctx.confirm, ctx.session.realm, {
              operation: "putCspMode",
              method: "PUT",
              path: "settings/csp-mode",
              body: { csp_mode: mode },
              ...(etag === undefined ? {} : { ifMatch: etag }),
            }),
          );
        }}
      >
        {(["enforce", "report_only"] as const).map((m) => (
          <label key={m} className={CHOICE_LABEL}>
            <input
              className={CHOICE}
              type="radio"
              name="csp-mode"
              value={m}
              checked={mode === m}
              onChange={() => {
                setMode(m);
              }}
            />
            {label(m)}
          </label>
        ))}
        {mode === "report_only" && current === "enforce" && (
          <Notice role="note" tone="warning" data-testid="csp-loosens">
            {t("settingsCspLoosens")}
          </Notice>
        )}
        <Button type="submit" className="self-start" isDisabled={mode === current}>
          {t("settingsSave")}
        </Button>
      </form>
      <Show l={w}>
        {(r) => <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>}
      </Show>
    </Panel>
  );
}

/** TN-33, OP-153 m.22 (c): whether a hosted sign-in is offered a device key. */
function SignInPolicy({ ctx, s, etag }: { readonly ctx: Ctx } & Tagged): ReactElement {
  const managed = (s.managed ?? []).includes("signin_policy");
  const current = s.signin_policy?.dbsc !== false;
  const [dbsc, setDbsc] = useState(current);
  const [w, write] = useRun<WriteResult>();
  return (
    <Panel id="signin-policy" title={t("settingsSignin")}>
      <p data-testid="dbsc-state">{current ? t("settingsDbscOn") : t("settingsDbscOff")}</p>
      {managed ? (
        <p className={HINT}>{t("settingsGitops")}</p>
      ) : (
        <form
          className={FORM}
          onSubmit={(e) => {
            e.preventDefault();
            write(() =>
              change(ctx.instance, ctx.confirm, ctx.session.realm, {
                operation: "patchSigninPolicy",
                method: "PATCH",
                path: "settings/signin-policy",
                body: { dbsc },
                ...(etag === undefined ? {} : { ifMatch: etag }),
              }),
            );
          }}
        >
          <label className={CHOICE_LABEL}>
            <input
              className={CHOICE}
              type="checkbox"
              checked={dbsc}
              onChange={(e) => {
                setDbsc(e.target.checked);
              }}
            />
            {t("settingsDbsc")}
          </label>
          <Button type="submit" className="self-start" isDisabled={dbsc === current}>
            {t("settingsSave")}
          </Button>
        </form>
      )}
      <Show l={w}>
        {(r) => <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>}
      </Show>
    </Panel>
  );
}

/** TN-18, OP-153 m.22 (j), (k): the Related Origins, under the organizations' verified domains. */
function RelatedOrigins({ ctx, s, etag }: { readonly ctx: Ctx } & Tagged): ReactElement {
  const [list, setList] = useState((s.related_origins ?? []).join("\n"));
  const [w, write] = useRun<WriteResult>();
  const origins = list
    .split("\n")
    .map((o) => o.trim())
    .filter((o) => o !== "");
  return (
    <Panel id="related" title={t("settingsRelated")}>
      <p data-testid="related-origins">{t("settingsRelatedText")}</p>
      {!(s.managed ?? []).includes("related_origins") && (
        <form
          className={FORM}
          onSubmit={(e) => {
            e.preventDefault();
            write(() =>
              change(ctx.instance, ctx.confirm, ctx.session.realm, {
                operation: "putRelatedOrigins",
                method: "PUT",
                path: "settings/related-origins",
                body: { origins },
                ...(etag === undefined ? {} : { ifMatch: etag }),
              }),
            );
          }}
        >
          <FieldRoot className="gap-2">
            <FieldLabel htmlFor="related-list" className="text-sm">
              {t("settingsRelatedList")}
            </FieldLabel>
            <Textarea
              id="related-list"
              className={`${MONO} text-sm`}
              value={list}
              onChange={(e) => {
                setList(e.target.value);
              }}
            />
          </FieldRoot>
          <Button type="submit" className="self-start">
            {t("settingsSave")}
          </Button>
        </form>
      )}
      <Show l={w}>
        {(r) => <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>}
      </Show>
    </Panel>
  );
}

function Branding({ ctx, s, etag }: { readonly ctx: Ctx } & Tagged): ReactElement {
  const managed = (s.managed ?? []).includes("branding");
  const [name, setName] = useState(s.branding?.display_name ?? "");
  const [w, write] = useRun<WriteResult>();
  return (
    <Panel id="branding" title={t("settingsBranding")}>
      {managed ? (
        <>
          <p className={HINT}>{t("settingsGitops")}</p>
          <p data-testid="branding-name">{s.branding?.display_name ?? ""}</p>
        </>
      ) : (
        <form
          className={FORM}
          onSubmit={(e) => {
            e.preventDefault();
            write(() =>
              change(ctx.instance, ctx.confirm, ctx.session.realm, {
                operation: "patchBranding",
                method: "PATCH",
                path: "settings/branding",
                body: { display_name: name },
                ...(etag === undefined ? {} : { ifMatch: etag }),
              }),
            );
          }}
        >
          <Field id="brand-name" label={t("settingsBrandName")} value={name} onChange={setName} />
          <Button type="submit" className="self-start">
            {t("settingsSave")}
          </Button>
        </form>
      )}
      <Show l={w}>
        {(r) => <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>}
      </Show>
    </Panel>
  );
}

/** §8.10, TN-17, IDI-4: an RP ID change is irreversible for passkeys; the count confirms it. */
function RpId({ ctx, s, etag }: { readonly ctx: Ctx } & Tagged): ReactElement {
  const managed = (s.managed ?? []).includes("rp_id");
  const [rp, setRp] = useState("");
  const [count, setCount] = useState("");
  const [w, write] = useRun<WriteResult>();
  const [mismatch, setMismatch] = useState(false);
  return (
    <Panel id="rp-id" title={t("settingsRpTitle")}>
      <dl className={FACTS}>
        <dt>{t("settingsRpCurrent")}</dt>
        <dd className={MONO}>{s.rp_id ?? ""}</dd>
      </dl>
      <Notice role="note" tone="warning" data-testid="rp-warning">
        {t("settingsRpWarning")}
      </Notice>
      {managed ? (
        <p className={HINT}>{t("settingsGitops")}</p>
      ) : (
        <form
          className={FORM}
          onSubmit={(e) => {
            e.preventDefault();
            setMismatch(false);
            write(() =>
              change(ctx.instance, ctx.confirm, ctx.session.realm, {
                operation: "putRpId",
                method: "PUT",
                path: "settings/rp-id",
                body: { rp_id: rp, acknowledge_passkey_loss: count },
                ...(etag === undefined ? {} : { ifMatch: etag }),
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
          <Button type="submit" className="self-start" isDisabled={rp === "" || count === ""}>
            {t("settingsSave")}
          </Button>
        </form>
      )}
      {mismatch ? (
        <Failure>{t("settingsRpMismatch")}</Failure>
      ) : (
        <Show l={w}>{() => <Notice role="status">{t("settingsRpIrreversible")}</Notice>}</Show>
      )}
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
          <ul className={BULLETS}>
            {v.items.map((c) => {
              const key = c.client_id ?? c.name ?? "";
              return (
                <li key={key}>
                  <span className={MONO}>{key}</span>
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
          <ul data-testid="social-providers" className="flex flex-col gap-3">
            {v.items.map((s) => (
              <li key={s.preset} className="flex flex-col gap-2">
                <span>
                  <span className={MONO}>{s.preset}</span>
                  {s.status === "disabled" && ` (${t("socialDisabled")})`}
                  {s.shared_development_client && ` — ${t("socialSharedClient")}`}
                </span>
                {s.warnings.map((w) => (
                  <Notice key={w.code} role="status" tone="warning" data-testid="social-warning">
                    {socialWarning(w)}
                  </Notice>
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
      <Badge variant="outline" className="self-start" data-testid="analytics-note">
        {t("analyticsNote")}
      </Badge>
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
              <Notice key={s.day} role="status" tone="warning">
                {t("analyticsSurge", { day: s.day, count: String(s.failed) })}
              </Notice>
            ))}
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead scope="col">{t("analyticsDay")}</TableHead>
                  <TableHead scope="col">{t("analyticsStarted")}</TableHead>
                  <TableHead scope="col">{t("analyticsCompleted")}</TableHead>
                  <TableHead scope="col">{t("analyticsFailed")}</TableHead>
                  <TableHead scope="col">{t("analyticsPasskey")}</TableHead>
                  <TableHead scope="col">{t("analyticsMfa")}</TableHead>
                  <TableHead scope="col">{t("analyticsMethods")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {a.days.map((d) => (
                  <TableRow key={d.day}>
                    <TableCell>{d.day}</TableCell>
                    <TableCell>{d.started}</TableCell>
                    <TableCell>{d.completed}</TableCell>
                    <TableCell>{d.failed}</TableCell>
                    <TableCell>{d.passkey_accounts}</TableCell>
                    <TableCell>{d.mfa_setup}</TableCell>
                    <TableCell className={MONO}>
                      {Object.entries(d.methods ?? {})
                        .map(([m, n]) => `${m}: ${String(n)}`)
                        .join(", ")}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </>
        )}
      </Show>
    </Panel>
  );
}

export function SignInSettings({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const l = useLoad(async () => {
    const r = await adminGetTagged(ctx.instance, realmPath(ctx, "/settings"));
    return { s: r.value as Settings, ...(r.etag === undefined ? {} : { etag: r.etag }) };
  });
  return (
    <>
      <p>{t("settingsIntro")}</p>
      <Status ctx={ctx} />
      <Keys ctx={ctx} />
      <Show l={l}>
        {({ s, etag }) => {
          const tag = etag === undefined ? {} : { etag };
          return (
            <>
              <SignInPolicy ctx={ctx} s={s} {...tag} />
              <Branding ctx={ctx} s={s} {...tag} />
              {!(s.managed ?? []).includes("branding") && <CspMode ctx={ctx} s={s} {...tag} />}
              <RpId ctx={ctx} s={s} {...tag} />
              <RelatedOrigins ctx={ctx} s={s} {...tag} />
            </>
          );
        }}
      </Show>
      <Domains ctx={ctx} />
      <SignalSources ctx={ctx} />
      <Listing ctx={ctx} path="/clients" title={t("settingsClients")} id="clients" />
      <Listing ctx={ctx} path="/upstream-idps" title={t("settingsUpstreams")} id="upstreams" />
      <SocialProviders ctx={ctx} />
      <UpstreamLink ctx={ctx} />
      <AnalyticsPanel ctx={ctx} />
    </>
  );
}
