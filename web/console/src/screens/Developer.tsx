// §8.17.10, S8, X21, §8.11: the Developer section. A publisher can never accept its own schema
// for a domain here (no accept control exists), OAuth words appear only qualified as protocol
// terms, the lab's answers are advisory and never recorded, and a sandbox is an ordinary domain
// in the domain list, never a switch.
import { useState, type ReactElement } from "react";

import { t, type Key } from "../i18n/index.js";
import { adminGet } from "../lib/admin.js";
import { check, explain, type Explained, search, type SearchAnswer } from "../lib/adp.js";
import type { Wanted } from "../lib/intents.js";
import {
  type PackageDraft,
  publicationStatus,
  type PublicationStatus,
  publish,
  type Published,
} from "../lib/meta.js";
import { Explanation } from "./Explanation.js";
import { Advisory, type Ctx, Field, Panel, Show, useLoad, useRun } from "./parts.js";
import { type Publication, PublicationView } from "./Reports.js";

function lines(text: string): string[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "");
}

interface DraftParam {
  readonly name: string;
  readonly affects: string;
  readonly type: string;
}

/** E12: an authority-relevant parameter without a closed type is refused at publication. */
export function unmapped(params: readonly DraftParam[]): readonly DraftParam[] {
  return params.filter((p) => p.name !== "" && p.affects !== "" && p.type.trim() === "");
}

function PrePublish(): ReactElement {
  const [name, setName] = useState("note");
  const [affects, setAffects] = useState("");
  const [type, setType] = useState("");
  const warnings = unmapped([{ name, affects, type }]);
  return (
    <Panel id="pre-publish" title={t("schemasPublishTitle")}>
      <Field id="param-name" label={t("paramName")} value={name} onChange={setName} />
      <Field id="param-affects" label={t("paramAffects")} value={affects} onChange={setAffects} />
      <Field id="param-type" label={t("paramType")} value={type} onChange={setType} />
      {warnings.map((w) => (
        <p key={w.name} role="alert" data-testid="e12-warning">
          {t("schemasUnmapped", { param: w.name, affects: w.affects })}
        </p>
      ))}
    </Panel>
  );
}

const PARAM_TYPES = ["amount", "int", "text", "bool", "bytes", "id", "opaque"] as const;
const EFFECTS = ["none", "reversible", "irreversible"] as const;

/** The package a publish form describes, or why it does not describe one. */
export function packageOf(
  namespace: string,
  version: string,
  actionLines: readonly string[],
  paramLines: readonly string[],
): PackageDraft | undefined {
  const catalog = Number(version);
  if (namespace === "" || !Number.isInteger(catalog) || catalog < 0) return undefined;
  const actions = new Map<
    string,
    { name: string; effect: string; params: Record<string, string> }
  >();
  for (const l of actionLines) {
    const [name, effect] = l.split(/\s+/);
    if (name === undefined || !EFFECTS.includes(effect as (typeof EFFECTS)[number])) {
      return undefined;
    }
    actions.set(name, { name, effect: effect ?? "", params: {} });
  }
  const classes: { action: string; parameter: string; class: string }[] = [];
  for (const l of paramLines) {
    const [path, type, cls] = l.split(/\s+/);
    const [action, parameter] = (path ?? "").split(".");
    const a = action === undefined ? undefined : actions.get(action);
    if (
      a === undefined ||
      parameter === undefined ||
      !PARAM_TYPES.includes(type as (typeof PARAM_TYPES)[number]) ||
      cls === undefined
    ) {
      return undefined;
    }
    a.params[parameter] = type ?? "";
    classes.push({ action: a.name, parameter, class: cls });
  }
  return {
    namespace,
    catalog_version: catalog,
    actions: [...actions.values()].map((a) => ({
      name: a.name,
      major: 1,
      effect_class: a.effect,
      ...(Object.keys(a.params).length > 0 ? { params: a.params } : {}),
    })),
    classes,
  };
}

/**
 * §8.17.10.2, X21, E10–E12, Ek B 3104–3107: publish a version to the domains named; then where
 * it stands: "Pending acceptance in: …". There is no accept control: each domain accepts on its
 * own, by its own protected change.
 */
function Publish({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [namespace, setNamespace] = useState("");
  const [version, setVersion] = useState("1");
  const [actionsText, setActions] = useState("");
  const [paramsText, setParams] = useState("");
  const [domainsText, setDomains] = useState(ctx.session.domain);
  const [l, run] = useRun<{ published: Published; status?: PublicationStatus }>();
  const pkg = packageOf(namespace, version, lines(actionsText), lines(paramsText));
  const domains = lines(domainsText);
  const name = (d: string) => (d === ctx.session.domain ? ctx.session.realm : d);
  return (
    <Panel id="publish" title={t("publishTitle")}>
      <p className="hint">{t("publishIntro")}</p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (pkg === undefined) return;
          run(async () => {
            const published = await publish(ctx.instance, pkg, domains);
            if (!published.kept) return { published };
            const status = await publicationStatus(
              ctx.instance,
              pkg.namespace,
              published.fingerprint,
              domains,
            );
            return { published, status };
          });
        }}
      >
        <Field
          id="publish-ns"
          label={t("pendingNamespace")}
          value={namespace}
          onChange={setNamespace}
        />
        <Field
          id="publish-version"
          label={t("publishVersion")}
          value={version}
          onChange={setVersion}
          type="number"
        />
        <p className="field">
          <label htmlFor="publish-actions">{t("publishActions")}</label>
          <textarea
            id="publish-actions"
            value={actionsText}
            onChange={(e) => {
              setActions(e.target.value);
            }}
          />
        </p>
        <p className="field">
          <label htmlFor="publish-params">{t("publishParams")}</label>
          <textarea
            id="publish-params"
            value={paramsText}
            onChange={(e) => {
              setParams(e.target.value);
            }}
          />
        </p>
        <p className="field">
          <label htmlFor="publish-domains">{t("publishDomains")}</label>
          <textarea
            id="publish-domains"
            value={domainsText}
            onChange={(e) => {
              setDomains(e.target.value);
            }}
          />
        </p>
        <button type="submit" disabled={pkg === undefined || domains.length === 0}>
          {t("publishButton")}
        </button>
      </form>
      <Show l={l}>
        {({ published, status }) =>
          published.kept ? (
            <>
              <p>
                {t("publishKept")}{" "}
                <span className="mono" data-testid="published-fingerprint">
                  {published.fingerprint}
                </span>
              </p>
              <p data-testid="published-unchanged">{t("pubExisting")}</p>
              {published.new_actions.length > 0 && (
                <p>
                  {t("pubNewActions", {
                    namespace: pkg?.namespace ?? namespace,
                    actions: published.new_actions.join(", "),
                  })}
                </p>
              )}
              <p data-testid="published-pending">
                {(status?.pending_acceptance.length ?? 0) === 0
                  ? t("schemasNoPending")
                  : t("schemasPendingIn", {
                      domains: (status?.pending_acceptance ?? []).map(name).join(", "),
                    })}
              </p>
              {(status?.accepted_in.length ?? 0) > 0 && (
                <p>
                  {t("publishAcceptedIn", {
                    domains: (status?.accepted_in ?? []).map(name).join(", "),
                  })}
                </p>
              )}
            </>
          ) : (
            <ul data-testid="publish-warnings">
              {published.warnings.map((w) => (
                <li key={w.parameter} role="alert">
                  {t("schemasUnmapped", {
                    param: w.parameter,
                    affects: w.reason.replace("affects_", ""),
                  })}
                </li>
              ))}
            </ul>
          )
        }
      </Show>
    </Panel>
  );
}

/** §8.17.10.2, X21: where each published version stands; "Pending acceptance in: …", no accept. */
export function Schemas({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [namespace, setNamespace] = useState("");
  const [l, run] = useRun<SearchAnswer<Publication>>();
  return (
    <>
      <p>{t("schemasIntro")}</p>
      <PrePublish />
      <Publish ctx={ctx} />
      <Panel id="publications" title={t("pendingNamespace")}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            run(() => search<Publication>(ctx.instance, "schema-publications", { namespace }));
          }}
        >
          <Field
            id="pub-ns"
            label={t("pendingNamespace")}
            value={namespace}
            onChange={setNamespace}
          />
          <button type="submit">{t("run")}</button>
        </form>
        <Show l={l}>
          {(a) => {
            const pending = a.results.filter((p) => p.standing === "pending_acceptance");
            return (
              <>
                <p data-testid="pending-in">
                  {pending.length === 0
                    ? t("schemasNoPending")
                    : t("schemasPendingIn", { domains: ctx.session.realm })}
                </p>
                {a.results.map((p) => (
                  <PublicationView key={p.fingerprint} p={p} />
                ))}
              </>
            );
          }}
        </Show>
      </Panel>
    </>
  );
}

interface Items<T> {
  readonly items: readonly T[];
}

interface Client {
  readonly client_id: string;
  readonly display_name?: string;
  readonly token_endpoint_auth_method?: string;
  readonly redirect_uris?: readonly string[];
  readonly grant_types?: readonly string[];
  readonly status?: string;
}

interface Hook {
  readonly hook_id: string;
  readonly point: string;
  readonly url: string;
  readonly on_no_answer: string;
  readonly status?: string;
}

interface Webhook {
  readonly webhook_id: string;
  readonly url: string;
  readonly events: readonly string[];
  readonly status?: string;
}

interface Delivery {
  readonly event_id: string;
  readonly event: string;
  readonly state: string;
  readonly attempts: number;
  readonly last_status?: number | null;
  readonly occurred_at: string;
}

/** TN-136, OP-151 m.20 (e), Ek B 3108: a webhook's delivery log, newest first, never a body. */
function Deliveries({
  ctx,
  base,
  webhook,
}: {
  readonly ctx: Ctx;
  readonly base: string;
  readonly webhook: string;
}): ReactElement {
  const l = useLoad(() =>
    adminGet<Items<Delivery>>(
      ctx.instance,
      `${base}/webhooks/${encodeURIComponent(webhook)}/deliveries`,
    ),
  );
  return (
    <Show l={l}>
      {(v) =>
        v.items.length === 0 ? (
          <p>{t("webhookDeliveriesNone")}</p>
        ) : (
          <ul data-testid="deliveries">
            {v.items.map((d) => (
              <li key={d.event_id}>
                <span className="mono">{d.event}</span> · {d.state} ·{" "}
                {t("deliveryAttempts", { n: String(d.attempts) })}
                {d.last_status !== undefined && d.last_status !== null
                  ? ` · HTTP ${String(d.last_status)}`
                  : ""}{" "}
                · {d.occurred_at}
              </li>
            ))}
          </ul>
        )
      }
    </Show>
  );
}

/** §8.11, Ek B 3109: OAuth terms only as "OAuth grant type"; hooks and webhooks of the realm. */
export function Integrations({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const base = `realms/${encodeURIComponent(ctx.session.realm)}`;
  const clients = useLoad(() => adminGet<Items<Client>>(ctx.instance, `${base}/clients`));
  const hooks = useLoad(() => adminGet<Items<Hook>>(ctx.instance, `${base}/hooks`));
  const webhooks = useLoad(() => adminGet<Items<Webhook>>(ctx.instance, `${base}/webhooks`));
  return (
    <>
      <p>{t("integrationsIntro")}</p>
      <Panel id="clients" title={t("settingsClients")}>
        <Show l={clients}>
          {(v) => (
            <table>
              <thead>
                <tr>
                  <th scope="col">{t("settingsClients")}</th>
                  <th scope="col">{t("clientAuth")}</th>
                  <th scope="col">{t("oauthGrantType")}</th>
                  <th scope="col">{t("clientRedirects")}</th>
                  <th scope="col">{t("clientStatus")}</th>
                </tr>
              </thead>
              <tbody>
                {v.items.map((c) => (
                  <tr key={c.client_id}>
                    <td>
                      <span className="mono">{c.client_id}</span>
                      {c.display_name !== undefined && ` — ${c.display_name}`}
                    </td>
                    <td className="mono">{c.token_endpoint_auth_method ?? ""}</td>
                    <td className="mono">{(c.grant_types ?? []).join(", ")}</td>
                    <td className="mono">{(c.redirect_uris ?? []).join(" ")}</td>
                    <td>{c.status === "retired" ? t("statusRetired") : t("statusActive")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Show>
      </Panel>
      <Panel id="hooks" title={t("hooksTitle")}>
        <Show l={hooks}>
          {(v) => (
            <ul>
              {v.items.map((h) => (
                <li key={h.hook_id}>
                  <span className="mono">{h.point}</span> · <span className="mono">{h.url}</span> ·{" "}
                  {t("hookOnNoAnswer")}:{" "}
                  {h.on_no_answer === "continue_without_claims"
                    ? t("hookContinue")
                    : t("hookRefuse")}
                </li>
              ))}
            </ul>
          )}
        </Show>
      </Panel>
      <Connectors />
      <Panel id="webhooks" title={t("webhooksTitle")}>
        <Show l={webhooks}>
          {(v) => (
            <ul>
              {v.items.map((h) => (
                <li key={h.webhook_id}>
                  <span className="mono">{h.url}</span> · {t("webhookEvents")}:{" "}
                  <span className="mono">{h.events.join(", ")}</span>
                  <h4>{t("webhookDeliveries")}</h4>
                  <Deliveries ctx={ctx} base={base} webhook={h.webhook_id} />
                </li>
              ))}
            </ul>
          )}
        </Show>
      </Panel>
    </>
  );
}

/** One kind of product Access works beside, and what it gets from Access (§18.3, E22, IDP-39). */
interface Connector {
  readonly kind: Key;
  readonly ready: readonly string[];
  readonly gives: Key;
  readonly where: readonly Key[] | Key;
}

/** §18.3, E22, IDP-39, OP-156 m.3 (x), Ek B 5238: one catalogue of the enterprise connectors. */
const CONNECTORS: readonly Connector[] = [
  {
    kind: "connPam",
    ready: ["Teleport", "CyberArk"],
    gives: "connPamGives",
    where: ["navAdmin", "screenSsh"],
  },
  {
    kind: "connSecrets",
    ready: ["OpenBao", "HashiCorp Vault"],
    gives: "connSecretsGives",
    where: "connSecretsWhere",
  },
  { kind: "connIga", ready: [], gives: "connIgaGives", where: "connIgaWhere" },
  {
    kind: "connSiem",
    ready: ["Splunk", "Microsoft Sentinel", "Datadog", "Elastic"],
    gives: "connSiemGives",
    where: ["navAdmin", "screenSiem"],
  },
  {
    kind: "connHr",
    ready: ["Personio", "BambooHR", "HiBob", "Workday", "SAP SuccessFactors", "Kolay İK", "Logo"],
    gives: "connHrGives",
    where: ["navAdmin", "screenHr"],
  },
  {
    kind: "connDevices",
    ready: ["Microsoft Intune", "Jamf Pro"],
    gives: "connDevicesGives",
    where: ["navAdmin", "screenSignIn"],
  },
  {
    kind: "connProofing",
    ready: ["Onfido", "Persona"],
    gives: "connProofingGives",
    where: ["navAdmin", "screenSignIn"],
  },
  { kind: "connRisk", ready: [], gives: "connRiskGives", where: ["navAdmin", "screenSignIn"] },
  { kind: "connDlp", ready: [], gives: "connDlpGives", where: ["navAdmin", "screenSignIn"] },
];

function where(w: Connector["where"]): string {
  return typeof w === "string" ? t(w) : w.map((k) => t(k)).join(" ▸ ");
}

/** §18.3, Ek B 5238: the catalogue; it lists products and calls nothing. */
function Connectors(): ReactElement {
  return (
    <Panel id="connectors" title={t("connectorsTitle")}>
      <p>{t("connectorsIntro")}</p>
      <table data-testid="connectors">
        <thead>
          <tr>
            <th scope="col">{t("connectorsKind")}</th>
            <th scope="col">{t("connectorsReady")}</th>
            <th scope="col">{t("connectorsGives")}</th>
            <th scope="col">{t("connectorsWhere")}</th>
          </tr>
        </thead>
        <tbody>
          {CONNECTORS.map((c) => (
            <tr key={c.kind}>
              <th scope="row">{t(c.kind)}</th>
              <td>{c.ready.length > 0 ? c.ready.join(", ") : t("connectorsAny")}</td>
              <td>{t(c.gives)}</td>
              <td>{where(c.where)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  );
}

interface Sandbox {
  readonly items: readonly { readonly slug: string; readonly domain: string }[];
}

interface RealmMetadata {
  readonly tenant_id?: string;
}

/** D7, L25, X21: the domains the lab can ask: this one and its tenant's sandbox domains. */
function useDomains(ctx: Ctx) {
  return useLoad(async () => {
    const own = [{ slug: ctx.session.realm, domain: ctx.session.domain }];
    try {
      const m = await adminGet<RealmMetadata>(
        ctx.instance,
        `platform/realms/${encodeURIComponent(ctx.session.realm)}`,
      );
      if (m.tenant_id === undefined) return own;
      const s = await adminGet<Sandbox>(
        ctx.instance,
        `platform/tenants/${encodeURIComponent(m.tenant_id)}/sandbox-domains`,
      );
      return [...own, ...s.items.filter((x) => x.slug !== ctx.session.realm)];
    } catch {
      return own;
    }
  });
}

/** §8.17.10.4: Check and Explain. Check is advisory: not recorded, not a promise (E-2). */
export function Lab({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const domains = useDomains(ctx);
  const [domain, setDomain] = useState(ctx.session.realm);
  const [subject, setSubject] = useState(ctx.session.account);
  const [ns, setNs] = useState("");
  const [name, setName] = useState("");
  const [major, setMajor] = useState("1");
  const [rns, setRns] = useState("");
  const [rpath, setRpath] = useState("");
  const [checked, runCheck] = useRun<boolean>();
  const [explained, runExplain] = useRun<Explained>();
  const wanted = (): Wanted => ({
    action: { namespace: ns, name, major: Number(major) },
    resources: [{ namespace: rns, path: rpath.split("/").filter((p) => p !== "") }],
  });
  const here = domain === ctx.session.realm;
  return (
    <>
      <p>{t("labIntro")}</p>
      <Panel id="lab-ask" title={t("labCheck")}>
        <p className="field">
          <label htmlFor="lab-domain">{t("labDomain")}</label>
          <select
            id="lab-domain"
            value={domain}
            onChange={(e) => {
              setDomain(e.target.value);
            }}
          >
            {(domains.status === "done"
              ? domains.value
              : [{ slug: ctx.session.realm, domain: ctx.session.domain }]
            ).map((d) => (
              <option key={d.slug} value={d.slug}>
                {d.slug}
              </option>
            ))}
          </select>
        </p>
        {!here && <p className="hint">{t("labOtherDomain", { realm: domain })}</p>}
        <Field id="lab-subject" label={t("labSubject")} value={subject} onChange={setSubject} />
        <Field id="lab-ns" label={t("labNamespace")} value={ns} onChange={setNs} />
        <Field id="lab-name" label={t("labAction")} value={name} onChange={setName} />
        <Field
          id="lab-major"
          label={t("labMajor")}
          value={major}
          onChange={setMajor}
          type="number"
        />
        <Field id="lab-rns" label={t("labResourceNs")} value={rns} onChange={setRns} />
        <Field id="lab-rpath" label={t("labResourcePath")} value={rpath} onChange={setRpath} />
        <p className="actions">
          <button
            type="button"
            disabled={!here}
            onClick={() => {
              runCheck(() => check(ctx.instance, subject, wanted()));
            }}
          >
            {t("labCheck")}
          </button>
          <button
            type="button"
            disabled={!here}
            onClick={() => {
              runExplain(() => explain(ctx.instance, subject, wanted()));
            }}
          >
            {t("labExplain")}
          </button>
        </p>
        <Show l={checked}>
          {(ok) => (
            <div data-testid="lab-check">
              <Advisory />
              <p>{ok ? t("labWouldAllow") : t("labWouldNot")}</p>
            </div>
          )}
        </Show>
        <Show l={explained}>{(a) => <Explanation answer={a} />}</Show>
      </Panel>
    </>
  );
}

/** INV-27, §8.17.10.4: a recorded decision evaluated again; match or mismatch is reported. */
export function Replay({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [position, setPosition] = useState("");
  const [ns, setNs] = useState("");
  const [name, setName] = useState("");
  const [rns, setRns] = useState("");
  const [rpath, setRpath] = useState("");
  const [l, run] = useRun<Explained>();
  return (
    <>
      <p>{t("replayIntro")}</p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          run(() =>
            explain(
              ctx.instance,
              ctx.session.account,
              {
                action: { namespace: ns, name, major: 1 },
                resources: [{ namespace: rns, path: rpath.split("/").filter((p) => p !== "") }],
              },
              { position: Number(position), scope: "audit" },
            ),
          );
        }}
      >
        <Field
          id="replay-pos"
          label={t("labRecord")}
          value={position}
          onChange={setPosition}
          type="number"
        />
        <Field id="replay-ns" label={t("labNamespace")} value={ns} onChange={setNs} />
        <Field id="replay-name" label={t("labAction")} value={name} onChange={setName} />
        <Field id="replay-rns" label={t("labResourceNs")} value={rns} onChange={setRns} />
        <Field id="replay-rpath" label={t("labResourcePath")} value={rpath} onChange={setRpath} />
        <button type="submit">{t("labReplay")}</button>
      </form>
      <Show l={l}>
        {(a) => {
          const replay = a.context?.["replay"] as { match?: unknown } | undefined;
          return (
            <>
              {replay !== undefined && typeof replay.match === "boolean" && (
                <p role="status" data-testid="replay-result">
                  {replay.match ? t("replayMatch") : t("replayMismatch")}
                </p>
              )}
              <Explanation answer={a} record={Number(position)} />
            </>
          );
        }}
      </Show>
    </>
  );
}

/** §8.17.10.3, §9.9.2: a recorded event, with the causal-binding warning where it applies. */
export function Logs({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [position, setPosition] = useState("");
  const [ns, setNs] = useState("");
  const [name, setName] = useState("");
  const [rns, setRns] = useState("");
  const [rpath, setRpath] = useState("");
  const [l, run] = useRun<Explained>();
  return (
    <>
      <p>{t("logsIntro")}</p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          run(() =>
            explain(
              ctx.instance,
              ctx.session.account,
              {
                action: { namespace: ns, name, major: 1 },
                resources: [{ namespace: rns, path: rpath.split("/").filter((p) => p !== "") }],
              },
              { position: Number(position), scope: "viewer" },
            ),
          );
        }}
      >
        <Field
          id="log-pos"
          label={t("labRecord")}
          value={position}
          onChange={setPosition}
          type="number"
        />
        <Field id="log-ns" label={t("labNamespace")} value={ns} onChange={setNs} />
        <Field id="log-name" label={t("labAction")} value={name} onChange={setName} />
        <Field id="log-rns" label={t("labResourceNs")} value={rns} onChange={setRns} />
        <Field id="log-rpath" label={t("labResourcePath")} value={rpath} onChange={setRpath} />
        <button type="submit">{t("run")}</button>
      </form>
      <Show l={l}>
        {(a) => (
          <>
            {a.context?.["causal_binding"] === "audit-only" && (
              <p role="note" className="banner" data-testid="causal-warning">
                {t("causalAuditOnly")}
              </p>
            )}
            <Explanation answer={a} record={Number(position)} />
          </>
        )}
      </Show>
    </>
  );
}
