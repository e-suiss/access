// §8.17.9.6, E6, EI-8, OP-157 m.3 (v): the Admin section's offboarding screen.
import { useState, type ReactElement } from "react";

import { loadKernel } from "@esuiss/access";

import { t } from "../i18n/index.js";
import { adminGet, draftChange, type WriteResult } from "../lib/admin.js";
import { API, b64url, call, fromB64url, json, Problem } from "../lib/api.js";
import {
  decodedIntent,
  decodedStatement,
  nonce,
  NotSigned,
  readProof,
  sign,
} from "../lib/instance.js";
import { basisCbor, basisFor, type Basis, type MetaPayload } from "../lib/meta.js";
import { at, type Ctx, Field, Panel, Show, useRun } from "./parts.js";

interface Selects {
  readonly class: string;
  readonly value?: string | null;
}

interface Preview {
  readonly party: string;
  readonly status: string;
  readonly survive: number;
  readonly channels: {
    readonly grants: readonly { readonly grant: string; readonly choices: readonly string[] }[];
    readonly instances: readonly {
      readonly instance: string;
      readonly choices: readonly string[];
    }[];
    readonly holdings: readonly {
      readonly grant: string;
      readonly selects: readonly Selects[];
      readonly choices: readonly string[];
    }[];
    readonly self_anchor: {
      readonly anchor?: string | null;
      readonly given: readonly string[];
      readonly choices: readonly string[];
    };
    readonly reentry: { readonly choices: readonly string[] };
  };
  readonly ended: readonly {
    readonly grant: string;
    readonly selects: readonly Selects[];
    readonly at?: string | null;
    readonly source?: string | null;
  }[];
}

type Choices = Readonly<Record<string, string>>;

interface MetaDraft {
  readonly intent: {
    readonly resources: readonly { readonly namespace: string; readonly path: readonly string[] }[];
  };
  readonly envelope: string;
  readonly payload: string;
  readonly basis?: { readonly anchor: string };
}

const LABELS: Readonly<Record<string, Parameters<typeof t>[0]>> = {
  keep: "offboardingKeep",
  revoke: "offboardingRevoke",
  terminate: "offboardingTerminate",
  retain: "offboardingRetain",
  exclude: "offboardingExclude",
  restrict: "offboardingRestrict",
  retire: "offboardingRetire",
  transfer: "offboardingHandOver",
  allowed: "offboardingReentryAllowed",
  blocked: "offboardingReentryBlocked",
};

function Pick({
  name,
  legend,
  choices,
  value,
  onPick,
}: {
  readonly name: string;
  readonly legend: string;
  readonly choices: readonly string[];
  readonly value: string | undefined;
  readonly onPick: (c: string) => void;
}): ReactElement {
  return (
    <fieldset>
      <legend className="mono">{legend}</legend>
      {choices.map((c) => (
        <label key={c}>
          <input
            type="radio"
            name={name}
            checked={value === c}
            onChange={() => {
              onPick(c);
            }}
          />{" "}
          {t(LABELS[c] ?? "offboardingMissingChoice")}
        </label>
      ))}
    </fieldset>
  );
}

function selected(s: readonly Selects[]): string {
  return s.map((c) => c.value ?? c.class).join(", ");
}

/** One operation of the commit: the meta write drafted by the BFF and signed by this Instance. */
async function operation(
  ctx: Ctx,
  op: string,
  key: string,
  payload: MetaPayload,
): Promise<{ readonly body: unknown; readonly shown: ReturnType<typeof decodedIntent> }> {
  const k = await loadKernel();
  const [name = ""] = Object.keys(payload);
  const draft = await json<MetaDraft>("/intents", {
    method: "POST",
    body: { action: { namespace: "access", name, major: 1 }, payload, mode: "commit" },
    headers: { "x-access-ais": await readProof(ctx.instance, "POST", `${API}/intents`) },
  });
  const envelope = fromB64url(draft.envelope);
  const shown = decodedIntent(k, envelope);
  // TN-110: the drafted intent is the meta-action asked for
  if (shown.action.namespace !== "access" || shown.action.name !== name) {
    throw new NotSigned("mismatch");
  }
  const resource = draft.intent.resources[0];
  const anchor = draft.basis?.anchor;
  if (resource === undefined || anchor === undefined) throw new NotSigned("mismatch");
  const basis: Basis = await basisFor(ctx.instance, name, resource, anchor);
  const n = nonce();
  const statement = k.aisStatement(
    ctx.instance.domain,
    n,
    k.intentDigest(envelope),
    "commit",
    ctx.instance.pep,
    new Uint8Array(),
    basisCbor(k, basis),
    BigInt(Date.now()),
    new Uint8Array(),
  );
  if (decodedStatement(k, statement).intent !== shown.digest) throw new NotSigned("mismatch");
  return {
    shown,
    body: {
      operation: op,
      key,
      body: {
        ais: await sign(ctx.instance.key, k, ctx.instance.kid, statement),
        intent: draft.intent,
        payload: draft.payload,
        nonce: b64url(n),
        basis,
        capacity: "own",
      },
    },
  };
}

/**
 * OP-157 m.3 (v), E6: the commit. Every channel's choice and the administrator's own signed
 * Exercises go together; the envelope signs both, and "Offboarded" comes from the answer, never
 * from the screen.
 */
async function commit(
  ctx: Ctx,
  p: Preview,
  choices: {
    readonly grants: Choices;
    readonly instances: Choices;
    readonly holdings: Choices;
    readonly anchor: string;
    readonly reentry: string;
  },
): Promise<WriteResult> {
  const slug = ctx.session.realm;
  const ops: { readonly op: string; readonly key: string; readonly payload: MetaPayload }[] = [];
  for (const [grant, c] of Object.entries(choices.grants)) {
    if (c === "revoke")
      ops.push({ op: "revokeGrant", key: grant, payload: { grant_revoke: { grant } } });
  }
  for (const instance of Object.keys(choices.instances)) {
    ops.push({
      op: "terminateInstance",
      key: instance,
      payload: { instance_terminate: { instance } },
    });
  }
  ops.push({
    op: "departParty",
    key: p.party,
    payload: {
      party_depart: {
        party: p.party,
        disposition: p.channels.self_anchor.given.map((grant) => ({
          grant,
          disposition: "revoke",
        })),
      },
    },
  });
  const signed = [];
  for (const o of ops) signed.push(await operation(ctx, o.op, o.key, o.payload));
  const body = {
    choices: {
      grants: choices.grants,
      instances: choices.instances,
      holdings: choices.holdings,
      self_anchor: choices.anchor,
      reentry: choices.reentry,
    },
    operations: signed.map((s) => s.body),
  };
  const path = `realms/${encodeURIComponent(slug)}/offboarding/${encodeURIComponent(p.party)}/commit`;
  const d = await draftChange(ctx.instance, slug, {
    operation: "commitOffboarding",
    key: p.party,
    method: "POST",
    path,
    body,
  });
  const k = await loadKernel();
  const n = nonce();
  const statement = k.aisStatement(
    ctx.instance.domain,
    n,
    fromB64url(d.intent_digest),
    "commit",
    ctx.instance.pep,
    new Uint8Array(),
    ctx.instance.basis,
    BigInt(Date.now()),
    new Uint8Array(),
  );
  const shown = decodedStatement(k, statement);
  if (!(await ctx.confirm({ statement: shown, intents: signed.map((s) => s.shown) }))) {
    throw new NotSigned("cancelled");
  }
  const r = await call(`/proxy/admin/${path}`, {
    method: "POST",
    body,
    headers: {
      "x-access-ais": await sign(ctx.instance.key, k, ctx.instance.kid, statement),
      "idempotency-key": b64url(n),
    },
  });
  if (!r.ok) {
    const problem = (await r.json().catch(() => ({}))) as { code?: unknown };
    throw new Problem(
      r.status,
      typeof problem.code === "string" ? problem.code : "unknown",
      undefined,
    );
  }
  return (await r.json()) as WriteResult;
}

function Departure({ p, ctx }: { readonly p: Preview; readonly ctx: Ctx }): ReactElement {
  const [grants, setGrants] = useState<Choices>({});
  const [instances, setInstances] = useState<Choices>({});
  const [holdings, setHoldings] = useState<Choices>({});
  const [anchor, setAnchor] = useState<string | undefined>(undefined);
  const [reentry, setReentry] = useState<string | undefined>(undefined);
  const [w, write] = useRun<WriteResult>();
  const ch = p.channels;
  const all = (
    list: readonly { readonly choices: readonly string[] }[],
    key: (i: number) => string,
    m: Choices,
  ) => list.every((_, i) => m[key(i)] !== undefined);
  const decided =
    all(ch.grants, (i) => ch.grants[i]?.grant ?? "", grants) &&
    all(ch.instances, (i) => ch.instances[i]?.instance ?? "", instances) &&
    all(ch.holdings, (i) => ch.holdings[i]?.grant ?? "", holdings) &&
    anchor !== undefined &&
    reentry !== undefined;
  // §8.17.9.6
  const elsewhere =
    (anchor !== undefined && anchor !== "retire") ||
    Object.values(holdings).some((c) => c === "exclude" || c === "restrict");
  const offboarded =
    p.status === "offboarded" ||
    (w.status === "done" &&
      (w.value.resource as { readonly status?: unknown } | undefined)?.status === "offboarded");
  return (
    <>
      {p.ended.map((e) => (
        <p key={e.grant} role="note" data-testid="role-ended">
          {t("offboardingRoleEnded", {
            role: selected(e.selects),
            source: e.source ?? "",
            at: at(e.at),
          })}
        </p>
      ))}
      {p.survive > 0 && (
        <p role="note" data-testid="survive">
          {t("offboardingSurviveCount", { n: String(p.survive) })}
        </p>
      )}
      <h4>{t("offboardingChannelGrants")}</h4>
      {ch.grants.map((g) => (
        <Pick
          key={g.grant}
          name={`off-g-${g.grant}`}
          legend={g.grant}
          choices={g.choices}
          value={grants[g.grant]}
          onPick={(c) => {
            setGrants({ ...grants, [g.grant]: c });
          }}
        />
      ))}
      <h4>{t("offboardingChannelInstances")}</h4>
      {ch.instances.map((i) => (
        <Pick
          key={i.instance}
          name={`off-i-${i.instance}`}
          legend={i.instance}
          choices={i.choices}
          value={instances[i.instance]}
          onPick={(c) => {
            setInstances({ ...instances, [i.instance]: c });
          }}
        />
      ))}
      <h4>{t("offboardingChannelRules")}</h4>
      {ch.holdings.map((h) => (
        <Pick
          key={h.grant}
          name={`off-h-${h.grant}`}
          legend={`${h.grant} (${selected(h.selects)})`}
          choices={h.choices}
          value={holdings[h.grant]}
          onPick={(c) => {
            setHoldings({ ...holdings, [h.grant]: c });
          }}
        />
      ))}
      <h4>{t("offboardingChannelAnchor")}</h4>
      <Pick
        name="off-anchor"
        legend={ch.self_anchor.anchor ?? ""}
        choices={ch.self_anchor.choices}
        value={anchor}
        onPick={setAnchor}
      />
      <h4>{t("offboardingChannelReentry")}</h4>
      <Pick
        name="off-reentry"
        legend={t("offboardingChannelReentry")}
        choices={ch.reentry.choices}
        value={reentry}
        onPick={setReentry}
      />
      <button
        type="button"
        data-testid="depart"
        disabled={!decided || elsewhere || offboarded}
        onClick={() => {
          if (anchor === undefined || reentry === undefined) return;
          write(() => commit(ctx, p, { grants, instances, holdings, anchor, reentry }));
        }}
      >
        {t("offboardingDepart")}
      </button>
      {!decided && <p className="hint">{t("offboardingMissingChoice")}</p>}
      {elsewhere && <p className="hint">{t("offboardingElsewhere")}</p>}
      <Show l={w}>{() => null}</Show>
      {offboarded && <p data-testid="offboarded">{t("offboardingDone")}</p>}
    </>
  );
}

/**
 * §8.17.9.6, E6, EI-8: the preview lists every channel of the departing Party and asks for an
 * explicit choice for each; nothing has a default. "Offboarded" is shown only once the server
 * says the departure Exercise committed.
 */
export function Offboarding({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [party, setParty] = useState("");
  const [l, load] = useRun<Preview>();
  const preview = () => {
    load(() =>
      adminGet<Preview>(
        ctx.instance,
        `realms/${encodeURIComponent(ctx.session.realm)}/offboarding/${encodeURIComponent(party)}/preview`,
      ),
    );
  };
  return (
    <>
      <p>{t("offboardingIntro")}</p>
      <p>{t("offboardingChannels")}</p>
      <Panel id="offboard" title={t("offboardingTitle")}>
        <Field id="off-party" label={t("offboardingParty")} value={party} onChange={setParty} />
        <button type="button" data-testid="preview" disabled={party === ""} onClick={preview}>
          {t("offboardingPreview")}
        </button>
        <Show l={l}>{(p) => <Departure key={p.party} p={p} ctx={ctx} />}</Show>
      </Panel>
      <p>{t("offboardingLabel")}</p>
    </>
  );
}
