// IDP-39 (3), LFP-18, OP-157 m.3 (w), m.6 (a): the Admin section's access review screen. A
// campaign is a view, never a queue: the reviewer sees the Grants of their own team, Keep records
// that one was checked and changes nothing, Remove is the reviewer's own revoke of that one Grant.
import { useState, type ReactElement } from "react";

import { loadKernel } from "@esuiss/access";

import { Button } from "@suiss/access-ui/components/ui/button";

import { t } from "../i18n/index.js";
import { adminGet, change, draftChange, type WriteResult } from "../lib/admin.js";
import { b64url, call, fromB64url, Problem } from "../lib/api.js";
import { decodedStatement, nonce, NotSigned, sign } from "../lib/instance.js";
import { type Basis, metaWrite, type MetaResult } from "../lib/meta.js";
import { ACTIONS, Failure, FORM, HINT, MONO, Notice, ROW, ROWLIST } from "../ui.js";
import { at, type Ctx, Field, Panel, Show, useLoad, useRun } from "./parts.js";

interface Review {
  readonly name: string;
  readonly period_days: number;
  readonly scope: string;
  readonly status: "live" | "closed";
  readonly next_run?: string | null;
}

interface Item {
  readonly grant: string;
  readonly holder: { readonly party?: string; readonly group?: readonly string[] };
  readonly actions: readonly { readonly namespace: string; readonly name: string }[];
  readonly valid_until?: string | null;
  readonly derived: number;
  readonly remove: { readonly operation: string; readonly basis: Basis };
}

interface Page<T> {
  readonly items: readonly T[];
}

function holderText(h: Item["holder"]): string {
  return h.party ?? (h.group ?? []).join(", ");
}

/** OP-157 m.6 (a): the keep, signed with this Instance over the drafted keep digest. */
async function keep(ctx: Ctx, review: string, grant: string): Promise<boolean> {
  const slug = ctx.session.realm;
  const path = `realms/${encodeURIComponent(slug)}/reviews/${encodeURIComponent(review)}/items/${encodeURIComponent(grant)}/keep`;
  const d = await draftChange(ctx.instance, slug, {
    operation: "keepReviewItem",
    key: `${review}:${grant}`,
    method: "POST",
    path,
    body: {},
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
  if (!(await ctx.confirm({ statement: shown, intents: [] }))) throw new NotSigned("cancelled");
  const r = await call(`/proxy/admin/${path}`, {
    method: "POST",
    body: {},
    headers: {
      "x-access-ais": await sign(ctx.instance.key, k, ctx.instance.kid, statement),
      "idempotency-key": b64url(n),
    },
  });
  if (!r.ok) throw new Problem(r.status, "unknown", undefined);
  const v = (await r.json()) as { kept?: unknown };
  return v.kept === true;
}

function Items({ ctx, review }: { readonly ctx: Ctx; readonly review: string }): ReactElement {
  const realm = encodeURIComponent(ctx.session.realm);
  const items = useLoad(() =>
    adminGet<Page<Item>>(
      ctx.instance,
      `realms/${realm}/reviews/${encodeURIComponent(review)}/items`,
    ),
  );
  const [kept, setKept] = useState<ReadonlySet<string>>(new Set());
  const [k, runKeep] = useRun<boolean>();
  const [removed, runRemove] = useRun<MetaResult>();
  const subject = ctx.instance.party ?? "";
  return (
    <>
      <p className={HINT}>{t("reviewsEachOnItsOwn")}</p>
      <Show l={items}>
        {(p) =>
          p.items.length === 0 ? (
            <p className={HINT}>{t("none")}</p>
          ) : (
            <ul data-testid="review-items" className={ROWLIST}>
              {p.items.map((i) => (
                <li key={i.grant} className={ROW}>
                  <span className={MONO}>{holderText(i.holder)}</span> ·{" "}
                  {i.actions.map((a) => `${a.namespace}:${a.name}`).join(", ")}
                  {i.valid_until !== null && i.valid_until !== undefined && (
                    <> · {at(i.valid_until)}</>
                  )}{" "}
                  {kept.has(i.grant) ? (
                    <span role="status" className="ms-auto font-medium text-primary">
                      {t("reviewsKept")}
                    </span>
                  ) : (
                    <span className="ms-auto flex gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onPress={() => {
                          runKeep(async () => {
                            const done = await keep(ctx, review, i.grant);
                            if (done) setKept(new Set([...kept, i.grant]));
                            return done;
                          });
                        }}
                      >
                        {t("reviewsKeep")}
                      </Button>{" "}
                      <Button
                        variant="destructive"
                        size="sm"
                        onPress={() => {
                          runRemove(() =>
                            metaWrite(
                              ctx.instance,
                              ctx.confirm,
                              subject,
                              { grant_revoke: { grant: i.grant } },
                              i.remove.basis,
                            ),
                          );
                        }}
                      >
                        {t("reviewsRemove")}
                      </Button>
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )
        }
      </Show>
      <Show l={k}>{() => null}</Show>
      <Show l={removed}>
        {(r) =>
          r.decision && r.exercise !== undefined ? (
            <Notice role="status">{t("changeRecorded", { exercise: r.exercise })}</Notice>
          ) : (
            <Failure>{t("notChanged")}</Failure>
          )
        }
      </Show>
    </>
  );
}

/** The access review screen. */
export function Reviews({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const realm = encodeURIComponent(ctx.session.realm);
  const reviews = useLoad(() => adminGet<Page<Review>>(ctx.instance, `realms/${realm}/reviews`));
  const [name, setName] = useState("");
  const [period, setPeriod] = useState("90");
  const [open, setOpen] = useState<string | undefined>(undefined);
  const [w, write] = useRun<WriteResult>();
  const send = (operation: string, path: string, body: Record<string, unknown>, key?: string) => {
    write(() =>
      change(ctx.instance, ctx.confirm, ctx.session.realm, {
        operation,
        method: "POST",
        path,
        body,
        ...(key === undefined ? {} : { key }),
      }),
    );
  };
  return (
    <>
      <p className="text-muted-foreground">{t("reviewsIntro")}</p>
      <Panel id="reviews-list" title={t("screenReviews")}>
        <Show l={reviews}>
          {(p) =>
            p.items.length === 0 ? (
              <p className={HINT}>{t("none")}</p>
            ) : (
              <ul data-testid="reviews" className={ROWLIST}>
                {p.items.map((r) => (
                  <li key={r.name} className={ROW}>
                    <span className={MONO}>{r.name}</span> ·{" "}
                    {r.status === "live" && r.next_run !== null && r.next_run !== undefined
                      ? t("reviewsNext", { date: at(r.next_run) })
                      : r.status}{" "}
                    {r.status === "live" && (
                      <span className="ms-auto flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onPress={() => {
                            setOpen(r.name);
                          }}
                        >
                          {t("reviewsItems")}
                        </Button>{" "}
                        <Button
                          variant="outline"
                          size="sm"
                          onPress={() => {
                            send(
                              "closeReview",
                              `reviews/${encodeURIComponent(r.name)}/close`,
                              {},
                              r.name,
                            );
                          }}
                        >
                          {t("reviewsClose")}
                        </Button>
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            )
          }
        </Show>
      </Panel>
      {open !== undefined && (
        <Panel id="review-items" title={`${t("reviewsItems")}: ${open}`}>
          <Items ctx={ctx} review={open} key={open} />
        </Panel>
      )}
      <Panel id="reviews-schedule" title={t("reviewsSchedule")}>
        <form
          className={FORM}
          onSubmit={(e) => {
            e.preventDefault();
            send("scheduleReview", "reviews", {
              name,
              period_days: Number(period),
              scope: "manager_team",
            });
          }}
        >
          <Field id="review-name" label={t("reviewsName")} value={name} onChange={setName} />
          <Field
            id="review-period"
            label={t("reviewsPeriod")}
            value={period}
            onChange={setPeriod}
            type="number"
          />
          <p className="flex flex-col gap-1 text-sm">
            <span className="font-semibold">{t("reviewsScope")}</span> {t("reviewsScopeTeam")}
          </p>
          <div className={ACTIONS}>
            <Button type="submit" isDisabled={name === "" || !(Number(period) >= 7)}>
              {t("reviewsSchedule")}
            </Button>
          </div>
        </form>
      </Panel>
      <Show l={w}>
        {(r) => <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>}
      </Show>
    </>
  );
}
