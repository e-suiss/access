// OP-157 m.3 (f), §8.16, TN-137, XI-7, SI-21: the person's own support access page. An operator's
// request only invites; the person opens this page, reads what is asked and gives it with their
// own device, or doesn't. What they gave is listed with who holds it and until when, and is
// ended with one Revoke; Block support access stops further requests.
import { support as components } from "@suiss/access-react";
import { Badge } from "@suiss/access-ui/components/ui/badge";
import { Button } from "@suiss/access-ui/components/ui/button";
import { Card, CardContent } from "@suiss/access-ui/components/ui/card";
import { Field, FieldLabel } from "@suiss/access-ui/components/ui/field";
import { ItemActions, ItemContent } from "@suiss/access-ui/components/ui/item";
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { useAnnouncer, when } from "../account/common.js";
import { frontend, json } from "../lib/api.js";
import { catalogue, t } from "../lib/i18n.js";
import type { Confirm, Instance } from "../lib/instance.js";
import { Check, Loading, Meta, Nothing, PageTitle, Panel, RowItem, Rows } from "../lib/ui.js";
import { type Access, type Requests, type SupportRow } from "./model.js";
import { type Drafted, signDraft } from "./sign.js";

function ended(a: SupportRow): string {
  return t(a.state === "revoked" ? "support.revoked" : "support.ended", {
    time: when(a.ended_at ?? a.until),
  });
}

export function SupportPage({
  instance,
  confirm,
}: {
  readonly instance: Instance;
  readonly confirm: Confirm;
}): ReactElement {
  const [requests, setRequests] = useState<Requests | null>(null);
  const [access, setAccess] = useState<Access | null>(null);
  const [busy, setBusy] = useState(false);
  const { say, fail, region } = useAnnouncer();
  const reload = useCallback(() => {
    json<Requests>(frontend("/v1/support/requests"))
      .then(setRequests)
      .catch((e: unknown) => {
        fail(e);
      });
    json<Access>(frontend("/v1/me/support-access"))
      .then(setAccess)
      .catch((e: unknown) => {
        fail(e);
      });
  }, [fail]);
  useEffect(reload, [reload]);
  const signed = (path: string, draft: Drafted, done: string) => {
    setBusy(true);
    signDraft(instance, confirm, draft)
      .then((body) => json(frontend(path, { method: "POST", body })))
      .then(() => {
        say(done);
        reload();
      })
      .catch((e: unknown) => {
        fail(e);
      })
      .finally(() => {
        setBusy(false);
      });
  };
  if (requests === null || access === null) {
    return (
      <div data-testid="support">
        {region}
        <Loading status />
      </div>
    );
  }
  const open = requests.requests.filter((r) => r.state === "waiting" && r.give !== undefined);
  const active = access.access.filter((a) => a.state === "active");
  const past = access.access.filter((a) => a.state !== "active");
  return (
    <div data-testid="support" className="flex flex-col gap-6">
      <div className="flex flex-col gap-1">
        <PageTitle>{t("support.title")}</PageTitle>
        <Meta>{t("support.intro")}</Meta>
      </div>
      {region}
      <Panel
        aria-label={t("support.requests_title")}
        data-testid="support-requests"
        title={t("support.requests_title")}
      >
        {open.map((r) => {
          const give = r.give;
          if (give === undefined) return null;
          const path = `/v1/support/requests/${encodeURIComponent(r.id)}`;
          return (
            <div key={r.id} data-testid="support-request" className="flex flex-col gap-3">
              <components.SupportRequest
                request={{
                  organization: r.organization,
                  case: r.case,
                  what: r.what,
                  minutes: r.minutes,
                  readOnly: r.read_only,
                }}
                openedBy="user"
                busy={busy}
                catalogue={catalogue}
                onGive={() => {
                  signed(
                    `${path}/give`,
                    give,
                    t("support.active", {
                      operator: r.operator,
                      organization: r.organization,
                      case: r.case,
                      time: when(give.until),
                    }),
                  );
                }}
                onDecline={() => {
                  void json(frontend(`${path}/decline`, { method: "POST" }))
                    .then(() => {
                      say(t("support.declined"));
                      reload();
                    })
                    .catch((e: unknown) => {
                      fail(e);
                    });
                }}
              />
              {give.standing !== undefined && (
                <Button
                  variant="outline"
                  className="self-start"
                  isDisabled={busy}
                  onPress={() => {
                    const standing = give.standing;
                    if (standing === undefined) return;
                    signed(`${path}/give`, standing, t("support.read_only"));
                  }}
                >
                  {t("support.standing")}
                </Button>
              )}
            </div>
          );
        })}
      </Panel>
      <section aria-label={t("support.title")} data-testid="support-access">
        <Card>
          <CardContent className="flex flex-col gap-4">
            {active.length === 0 && <Nothing>{t("support.none")}</Nothing>}
            <Rows>
              {active.map((a) => (
                <RowItem key={a.id} data-testid="support-active">
                  <ItemContent>
                    <p>
                      {t("support.active", {
                        operator: a.operator,
                        organization: a.organization,
                        case: a.case,
                        time: when(a.until),
                      })}
                    </p>
                    {a.read_only && <Badge variant="outline">{t("support.read_only")}</Badge>}
                  </ItemContent>
                  {a.revoke !== undefined && a.basis !== undefined && (
                    <ItemActions>
                      <Button
                        variant="outline"
                        size="sm"
                        isDisabled={busy}
                        onPress={() => {
                          const { revoke, basis } = a;
                          if (revoke === undefined || basis === undefined) return;
                          signed(
                            `/v1/me/support-access/${encodeURIComponent(basis.holding.grant)}/revoke`,
                            revoke,
                            t("support.revoked", { time: when(Date.now()) }),
                          );
                        }}
                      >
                        {t("support.revoke")}
                      </Button>
                    </ItemActions>
                  )}
                </RowItem>
              ))}
              {past.map((a) => (
                <RowItem key={a.id} data-testid="support-past" variant="muted">
                  <ItemContent className="text-sm text-muted-foreground">
                    {ended(a)} · {a.organization} · {a.case}
                  </ItemContent>
                </RowItem>
              ))}
            </Rows>
          </CardContent>
        </Card>
      </section>
      <Card>
        <CardContent className="flex flex-col gap-2">
          <Field orientation="horizontal">
            <Check
              id="support-block"
              data-testid="support-block"
              checked={requests.blocked}
              onChange={(e) => {
                void json(
                  frontend("/v1/me/support-block", {
                    method: "PUT",
                    body: { blocked: e.target.checked },
                  }),
                )
                  .then(reload)
                  .catch((x: unknown) => {
                    fail(x);
                  });
              }}
            />
            <FieldLabel htmlFor="support-block" className="font-normal">
              {t("support.block")}
            </FieldLabel>
          </Field>
          {requests.blocked && <Meta>{t("support.block_on")}</Meta>}
        </CardContent>
      </Card>
    </div>
  );
}
