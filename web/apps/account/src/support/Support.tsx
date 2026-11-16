// OP-157 m.3 (f), §8.16, TN-137, XI-7, SI-21: the person's own support access page. An operator's
// request only invites; the person opens this page, reads what is asked and gives it with their
// own device, or doesn't. What they gave is listed with who holds it and until when, and is
// ended with one Revoke; Block support access stops further requests.
import { support as components } from "@access/ui";
import { Badge } from "@access/ui/components/badge";
import { Button } from "@access/ui/components/button";
import { Card, CardContent } from "@access/ui/components/card";
import { Field, FieldLabel } from "@access/ui/components/field";
import { ItemActions, ItemContent } from "@access/ui/components/item";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ReactElement } from "react";

import { useAnnouncer, when } from "../account/common.js";
import { frontend, json } from "../lib/api.js";
import { catalogue, t } from "../lib/i18n.js";
import type { Confirm, Instance } from "../lib/instance.js";
import { Check, Loading, Meta, Nothing, PageTitle, Panel, RowItem, Rows } from "../lib/ui.js";
import { Requests, readAccess, type SupportRow } from "./model.js";
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
  const queries = useQueryClient();
  const asked = useQuery({
    queryKey: ["support", "requests"],
    queryFn: () => json(frontend("/v1/support/requests"), Requests),
  });
  const given = useQuery({ queryKey: ["support", "access"], queryFn: readAccess });
  const { say, fail, region } = useAnnouncer(asked.error ?? given.error);
  const reload = () => {
    void queries.invalidateQueries({ queryKey: ["support"] });
  };
  const write = {
    onSuccess: (done: string) => {
      say(done);
      reload();
    },
    onError: (e: unknown) => {
      fail(e);
    },
  };
  const signing = useMutation({
    mutationFn: async (w: { path: string; draft: Drafted; done: string }) => {
      const body = await signDraft(instance, confirm, w.draft);
      await json(frontend(w.path, { method: "POST", body }));
      return w.done;
    },
    ...write,
  });
  const declining = useMutation({
    mutationFn: async (path: string) => {
      await json(frontend(`${path}/decline`, { method: "POST" }));
      return t("support.declined");
    },
    ...write,
  });
  const blocking = useMutation({
    mutationFn: (blocked: boolean) =>
      json(frontend("/v1/me/support-block", { method: "PUT", body: { blocked } })),
    onSuccess: reload,
    onError: (e) => {
      fail(e);
    },
  });
  const busy = signing.isPending;
  const signed = (path: string, draft: Drafted, done: string) => {
    signing.mutate({ path, draft, done });
  };
  const requests = asked.data;
  const access = given.data;
  if (requests === undefined || access === undefined) {
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
                  declining.mutate(path);
                }}
              />
              {give.standing !== undefined && (
                <Button
                  variant="outline"
                  className="self-start"
                  disabled={busy}
                  onClick={() => {
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
                        disabled={busy}
                        onClick={() => {
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
                blocking.mutate(e.target.checked);
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
