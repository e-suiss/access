// §8.17.10, S8, X21, §8.11: the Developer section. A publisher can never accept its own schema
// for a domain here (no accept control exists), OAuth words appear only qualified as protocol
// terms, the lab's answers are advisory and never recorded, and a sandbox is an ordinary domain
// in the domain list, never a switch.
import { useState, type ReactElement } from "react";

import { Button } from "@suiss/access-ui/components/ui/button";
import { Field as FieldRoot, FieldLabel } from "@suiss/access-ui/components/ui/field";
import { NativeSelect, NativeSelectOption } from "@suiss/access-ui/components/ui/native-select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@suiss/access-ui/components/ui/table";
import { Textarea } from "@suiss/access-ui/components/ui/textarea";

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
import { ACTIONS, BULLETS, FORM, H4, HINT, MONO, Notice } from "../ui.js";

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
        <Notice key={w.name} tone="danger" role="alert" data-testid="e12-warning">
          {t("schemasUnmapped", { param: w.name, affects: w.affects })}
        </Notice>
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
      <p className={HINT}>{t("publishIntro")}</p>
      <form
        className={FORM}
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
        <FieldRoot className="max-w-xl gap-2">
          <FieldLabel htmlFor="publish-actions" className="text-sm">
            {t("publishActions")}
          </FieldLabel>
          <Textarea
            id="publish-actions"
            className={MONO}
            value={actionsText}
            onChange={(e) => {
              setActions(e.target.value);
            }}
          />
        </FieldRoot>
        <FieldRoot className="max-w-xl gap-2">
          <FieldLabel htmlFor="publish-params" className="text-sm">
            {t("publishParams")}
          </FieldLabel>
          <Textarea
            id="publish-params"
            className={MONO}
            value={paramsText}
            onChange={(e) => {
              setParams(e.target.value);
            }}
          />
        </FieldRoot>
        <FieldRoot className="max-w-xl gap-2">
          <FieldLabel htmlFor="publish-domains" className="text-sm">
            {t("publishDomains")}
          </FieldLabel>
          <Textarea
            id="publish-domains"
            className={MONO}
            value={domainsText}
            onChange={(e) => {
              setDomains(e.target.value);
            }}
          />
        </FieldRoot>
        <p className={ACTIONS}>
          <Button type="submit" isDisabled={pkg === undefined || domains.length === 0}>
            {t("publishButton")}
          </Button>
        </p>
      </form>
      <Show l={l}>
        {({ published, status }) =>
          published.kept ? (
            <>
              <p>
                {t("publishKept")}{" "}
                <span className={MONO} data-testid="published-fingerprint">
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
            <ul data-testid="publish-warnings" className="flex flex-col gap-2">
              {published.warnings.map((w) => (
                <li
                  key={w.parameter}
                  role="alert"
                  className="rounded-xl bg-red-50 p-3 text-sm text-red-900 ring-1 ring-red-700/25 dark:bg-red-950/40 dark:text-red-50"
                >
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
          className={FORM}
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
          <p className={ACTIONS}>
            <Button type="submit" variant="outline">
              {t("run")}
            </Button>
          </p>
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
          <p className={HINT}>{t("webhookDeliveriesNone")}</p>
        ) : (
          <ul data-testid="deliveries" className={BULLETS}>
            {v.items.map((d) => (
              <li key={d.event_id}>
                <span className={MONO}>{d.event}</span> · {d.state} ·{" "}
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
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead scope="col">{t("settingsClients")}</TableHead>
                  <TableHead scope="col">{t("clientAuth")}</TableHead>
                  <TableHead scope="col">{t("oauthGrantType")}</TableHead>
                  <TableHead scope="col">{t("clientRedirects")}</TableHead>
                  <TableHead scope="col">{t("clientStatus")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {v.items.map((c) => (
                  <TableRow key={c.client_id}>
                    <TableCell className="whitespace-normal">
                      <span className={MONO}>{c.client_id}</span>
                      {c.display_name !== undefined && ` — ${c.display_name}`}
                    </TableCell>
                    <TableCell className={MONO}>{c.token_endpoint_auth_method ?? ""}</TableCell>
                    <TableCell className={`${MONO} whitespace-normal`}>
                      {(c.grant_types ?? []).join(", ")}
                    </TableCell>
                    <TableCell className={`${MONO} whitespace-normal`}>
                      {(c.redirect_uris ?? []).join(" ")}
                    </TableCell>
                    <TableCell>
                      {c.status === "retired" ? t("statusRetired") : t("statusActive")}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Show>
      </Panel>
      <Panel id="hooks" title={t("hooksTitle")}>
        <Show l={hooks}>
          {(v) => (
            <ul className={BULLETS}>
              {v.items.map((h) => (
                <li key={h.hook_id}>
                  <span className={MONO}>{h.point}</span> · <span className={MONO}>{h.url}</span> ·{" "}
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
            <ul className="flex flex-col gap-4">
              {v.items.map((h) => (
                <li key={h.webhook_id} className="flex flex-col gap-2">
                  <p>
                    <span className={MONO}>{h.url}</span> · {t("webhookEvents")}:{" "}
                    <span className={MONO}>{h.events.join(", ")}</span>
                  </p>
                  <h4 className={H4}>{t("webhookDeliveries")}</h4>
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
      <Table data-testid="connectors">
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead scope="col">{t("connectorsKind")}</TableHead>
            <TableHead scope="col">{t("connectorsReady")}</TableHead>
            <TableHead scope="col">{t("connectorsGives")}</TableHead>
            <TableHead scope="col">{t("connectorsWhere")}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {CONNECTORS.map((c) => (
            <TableRow key={c.kind}>
              <TableHead scope="row" className="text-sm font-medium text-foreground">
                {t(c.kind)}
              </TableHead>
              <TableCell className="whitespace-normal">
                {c.ready.length > 0 ? c.ready.join(", ") : t("connectorsAny")}
              </TableCell>
              <TableCell className="whitespace-normal">{t(c.gives)}</TableCell>
              <TableCell>{where(c.where)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
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
        <FieldRoot className="max-w-xl gap-2">
          <FieldLabel htmlFor="lab-domain" className="text-sm">
            {t("labDomain")}
          </FieldLabel>
          <NativeSelect
            id="lab-domain"
            size="sm"
            value={domain}
            onChange={(e) => {
              setDomain(e.target.value);
            }}
          >
            {(domains.status === "done"
              ? domains.value
              : [{ slug: ctx.session.realm, domain: ctx.session.domain }]
            ).map((d) => (
              <NativeSelectOption key={d.slug} value={d.slug}>
                {d.slug}
              </NativeSelectOption>
            ))}
          </NativeSelect>
        </FieldRoot>
        {!here && <p className={HINT}>{t("labOtherDomain", { realm: domain })}</p>}
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
        <p className={ACTIONS}>
          <Button
            isDisabled={!here}
            onPress={() => {
              runCheck(() => check(ctx.instance, subject, wanted()));
            }}
          >
            {t("labCheck")}
          </Button>
          <Button
            variant="outline"
            isDisabled={!here}
            onPress={() => {
              runExplain(() => explain(ctx.instance, subject, wanted()));
            }}
          >
            {t("labExplain")}
          </Button>
        </p>
        <Show l={checked}>
          {(ok) => (
            <div data-testid="lab-check" className="flex flex-col gap-2">
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
        className={FORM}
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
        <p className={ACTIONS}>
          <Button type="submit">{t("labReplay")}</Button>
        </p>
      </form>
      <Show l={l}>
        {(a) => {
          const replay = a.context?.["replay"] as { match?: unknown } | undefined;
          return (
            <>
              {replay !== undefined && typeof replay.match === "boolean" && (
                <Notice
                  role="status"
                  tone={replay.match ? "info" : "warning"}
                  data-testid="replay-result"
                >
                  {replay.match ? t("replayMatch") : t("replayMismatch")}
                </Notice>
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
        className={FORM}
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
        <p className={ACTIONS}>
          <Button type="submit">{t("run")}</Button>
        </p>
      </form>
      <Show l={l}>
        {(a) => (
          <>
            {a.context?.["causal_binding"] === "audit-only" && (
              <Notice role="note" tone="warning" data-testid="causal-warning">
                {t("causalAuditOnly")}
              </Notice>
            )}
            <Explanation answer={a} record={Number(position)} />
          </>
        )}
      </Show>
    </>
  );
}
