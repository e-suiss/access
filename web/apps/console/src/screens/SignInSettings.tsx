// §8.17.4.1 identity plane note, E34, MD-14: environment configuration. Every change is drafted, shown
// on the signature screen and committed as one Exercise. The RP ID change is marked irreversible
// for passkeys (TN-17, X-L12); a new environment's first 90 minutes are shown (TN-111, CR-25); delayed
// signals (§8.13) and a missing GeoIP source (OP-151 m.3 (b)) are stated, never hidden. The page
// CSP mode, the DBSC switch and the Related Origins are set here too (OP-153 m.22 (c), (g), (k)).

import { Badge } from "@access/ui/components/badge";
import { Button } from "@access/ui/components/button";
import { FieldLabel, Field as FieldRoot } from "@access/ui/components/field";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@access/ui/components/table";
import { Textarea } from "@access/ui/components/textarea";
import { type ReactElement, useState } from "react";
import * as v from "valibot";

import { t } from "../i18n/index.js";
import { adminGet, adminGetTagged, change, items, type WriteResult } from "../lib/admin.js";
import { Problem } from "../lib/api.js";
import { BULLETS, CHOICE, CHOICE_LABEL, FACTS, Failure, FORM, HINT, MONO, Notice } from "../ui.js";
import { Domains } from "./Domains.js";
import { at, type Ctx, Field, Panel, readKey, Show, useLoad, useRun } from "./parts.js";
import { Signals as SignalSources } from "./Signals.js";
import { UpstreamLink } from "./UpstreamLink.js";

// OP-159 m.46 (f)
const Settings = v.looseObject({
  rp_id: v.exactOptional(v.nullable(v.string())),
  signin_policy: v.exactOptional(v.looseObject({ dbsc: v.exactOptional(v.boolean()) })),
  session_policy: v.exactOptional(v.unknown()),
  branding: v.exactOptional(
    v.looseObject({ display_name: v.exactOptional(v.nullable(v.string())) }),
  ),
  csp_mode: v.exactOptional(v.picklist(["enforce", "report_only"])),
  related_origins: v.exactOptional(v.array(v.string())),
  managed: v.exactOptional(v.array(v.string())),
});

type Settings = v.InferOutput<typeof Settings>;

const EnvironmentMetadata = v.looseObject({
  key_state: v.exactOptional(v.picklist(["pending", "published", "signing", "unavailable"])),
  signing_available_at: v.exactOptional(v.nullable(v.string())),
});

const Signals = v.looseObject({
  transmitters: v.exactOptional(
    v.array(
      v.looseObject({ name: v.string(), delayed_since: v.exactOptional(v.nullable(v.number())) }),
    ),
  ),
  geoip: v.exactOptional(v.picklist(["configured", "not_configured", "unreadable"])),
  verifiers: v.exactOptional(
    v.array(v.looseObject({ name: v.string(), declared_until: v.number() })),
  ),
});

const AnalyticsDay = v.looseObject({
  day: v.string(),
  started: v.number(),
  completed: v.number(),
  failed: v.number(),
  passkey_accounts: v.number(),
  mfa_setup: v.number(),
  legacy_password_accounts: v.exactOptional(v.number()),
  methods: v.exactOptional(v.record(v.string(), v.number())),
});

export type AnalyticsDay = v.InferOutput<typeof AnalyticsDay>;

const Analytics = v.looseObject({
  days: v.array(AnalyticsDay),
  surges: v.exactOptional(v.array(v.looseObject({ day: v.string(), failed: v.number() }))),
});

const KEY_STATE = {
  pending: "keyPending",
  published: "keyPublished",
  signing: "keySigning",
  unavailable: "keyUnavailable",
} as const;

function environmentPath(ctx: Ctx, rest = ""): string {
  return `envs/${encodeURIComponent(ctx.session.environment)}${rest}`;
}

/** §8.13, Ek B 2963, 3034: delayed signals, missing GeoIP and verifier reports. */
function Status({ ctx }: { readonly ctx: Ctx }): ReactElement | null {
  const l = useLoad(readKey(ctx, "/signals"), () =>
    adminGet(ctx.instance, environmentPath(ctx, "/signals"), Signals),
  );
  if (l.status !== "done") return null;
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
  const l = useLoad(
    readKey(ctx, `platform/envs/${encodeURIComponent(ctx.session.environment)}`),
    () =>
      adminGet(
        ctx.instance,
        `platform/envs/${encodeURIComponent(ctx.session.environment)}`,
        EnvironmentMetadata,
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
            change(ctx.instance, ctx.confirm, ctx.session.environment, {
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
        <Button type="submit" className="self-start" disabled={mode === current}>
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
              change(ctx.instance, ctx.confirm, ctx.session.environment, {
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
          <Button type="submit" className="self-start" disabled={dbsc === current}>
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
              change(ctx.instance, ctx.confirm, ctx.session.environment, {
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
              change(ctx.instance, ctx.confirm, ctx.session.environment, {
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
              change(ctx.instance, ctx.confirm, ctx.session.environment, {
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
          <Button type="submit" className="self-start" disabled={rp === "" || count === ""}>
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

const Named = items(
  v.looseObject({
    client_id: v.exactOptional(v.string()),
    name: v.exactOptional(v.string()),
    display_name: v.exactOptional(v.nullable(v.string())),
    status: v.exactOptional(v.string()),
  }),
);

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
  const l = useLoad(readKey(ctx, path), () =>
    adminGet(ctx.instance, environmentPath(ctx, path), Named),
  );
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
                  {typeof c.display_name === "string" && ` — ${c.display_name}`}
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

const SocialWarning = v.looseObject({
  code: v.string(),
  at: v.exactOptional(v.string()),
  until: v.exactOptional(v.string()),
});

type SocialWarning = v.InferOutput<typeof SocialWarning>;

const Socials = items(
  v.looseObject({
    preset: v.string(),
    client_id: v.exactOptional(v.nullable(v.string())),
    shared_development_client: v.boolean(),
    status: v.picklist(["active", "disabled"]),
    warnings: v.array(SocialWarning),
  }),
);

/** One social warning as text; a warning never refuses anything (TN-87, IDP-31 (5)). */
function socialWarning(w: SocialWarning): string {
  if (w.until !== undefined) return t("socialAppleWindow", { until: w.until });
  if (w.at !== undefined) return t("socialClientChanged", { at: w.at });
  if (w.code === "apple-sign-in-recommended") return t("socialAppleRecommended");
  return w.code;
}

/** IDP-31, TN-87, Ek B 3572, 3655: the social presets and their warnings. */
function SocialProviders({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const l = useLoad(readKey(ctx, "/social-providers"), () =>
    adminGet(ctx.instance, environmentPath(ctx, "/social-providers"), Socials),
  );
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
  const l = useLoad(readKey(ctx, "/analytics"), () =>
    adminGet(ctx.instance, environmentPath(ctx, "/analytics"), Analytics),
  );
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
  const l = useLoad(readKey(ctx, "/settings"), async () => {
    const r = await adminGetTagged(ctx.instance, environmentPath(ctx, "/settings"), Settings);
    return { s: r.value, ...(r.etag === undefined ? {} : { etag: r.etag }) };
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
