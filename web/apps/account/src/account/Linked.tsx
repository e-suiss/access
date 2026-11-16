// S11 (§8.5; TN-65, TN-68, OP-153 m.3 (m), (z)): the other sign-ins linked to this account and
// the apps it shares identity details with. A linked sign-in is never called "merged"; linking
// proves control of the other sign-in at its provider. Sharing details with an app is not
// authority: stopping it keeps the record and the app receives no details until asked again.
import { Button } from "@access/ui/components/button";
import { ItemActions, ItemContent } from "@access/ui/components/item";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ReactElement } from "react";
import * as v from "valibot";

import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { Loading, Meta, Nothing, Panel, RowItem, Rows } from "../lib/ui.js";
import { useAnnouncer, when } from "./common.js";

const LinkedList = v.object({
  linked: v.array(
    v.object({
      link: v.string(),
      provider: v.string(),
      linked_at_ms: v.number(),
      verified_at_ms: v.nullable(v.number()),
    }),
  ),
});

const Apps = v.object({
  apps: v.array(
    v.object({
      client_id: v.string(),
      app: v.string(),
      claims: v.array(v.string()),
      since_ms: v.number(),
    }),
  ),
});

const LINKED = ["account", "linked"] as const;
const APPS = ["account", "connected-apps"] as const;

const LINK_CODES = {
  "last-sign-in-method": "methods.last_method",
  "no-such-provider": "linked.unavailable",
} as const;

/** "Linked sign-ins". */
export function LinkedSignIns(): ReactElement {
  const queries = useQueryClient();
  const { data: list, error } = useQuery({
    queryKey: LINKED,
    queryFn: () => json(frontend("/v1/account/linked"), LinkedList),
  });
  const { say, fail, region } = useAnnouncer(error);
  const unlink = useMutation({
    mutationFn: (link: string) =>
      json(frontend(`/v1/account/linked/${encodeURIComponent(link)}`, { method: "DELETE" })),
    onSuccess: () => {
      say(t("methods.removed"));
      void queries.invalidateQueries({ queryKey: LINKED });
    },
    onError: (e) => {
      fail(e, LINK_CODES);
    },
  });
  return (
    <Panel
      aria-labelledby="linked-heading"
      data-testid="linked-sign-ins"
      title={t("settings.linked_sign_ins")}
      titleId="linked-heading"
    >
      {region}
      {list === undefined ? (
        <Loading />
      ) : list.linked.length === 0 ? (
        <Nothing>{t("linked.none")}</Nothing>
      ) : (
        <Rows>
          {list.linked.map((l) => (
            <RowItem key={l.link} data-testid="linked-row">
              <ItemContent>
                <strong>{l.provider}</strong>
                <Meta>{t("linked.since", { date: when(l.linked_at_ms) })}</Meta>
              </ItemContent>
              <ItemActions>
                <Button
                  variant="outline"
                  size="sm"
                  aria-label={`${t("action.remove")}: ${l.provider}`}
                  onClick={() => {
                    unlink.mutate(l.link);
                  }}
                >
                  {t("action.remove")}
                </Button>
              </ItemActions>
            </RowItem>
          ))}
        </Rows>
      )}
    </Panel>
  );
}

/** "Connected apps" (OP-153 m.3 (z)). */
export function ConnectedApps(): ReactElement {
  const queries = useQueryClient();
  const { data: apps, error } = useQuery({
    queryKey: APPS,
    queryFn: () => json(frontend("/v1/account/connected-apps"), Apps),
  });
  const { say, fail, region } = useAnnouncer(error);
  const stop = useMutation({
    mutationFn: (client: string) =>
      json(
        frontend(`/v1/account/connected-apps/${encodeURIComponent(client)}`, { method: "DELETE" }),
      ),
    onSuccess: () => {
      say(t("apps.stopped"));
      void queries.invalidateQueries({ queryKey: APPS });
    },
    onError: (e) => {
      fail(e);
    },
  });
  return (
    <Panel
      aria-labelledby="apps-heading"
      data-testid="connected-apps"
      title={t("settings.connected_apps")}
      titleId="apps-heading"
    >
      {region}
      {apps === undefined ? (
        <Loading />
      ) : apps.apps.length === 0 ? (
        <Nothing>{t("apps.none")}</Nothing>
      ) : (
        <Rows>
          {apps.apps.map((a) => (
            <RowItem key={a.client_id} data-testid="app-row">
              <ItemContent>
                <strong>{a.app}</strong>
                <Meta>{t("apps.claims", { claims: a.claims.join(", ") })}</Meta>
                <Meta>{t("apps.since", { date: when(a.since_ms) })}</Meta>
              </ItemContent>
              <ItemActions>
                <Button
                  variant="outline"
                  size="sm"
                  aria-label={`${t("action.stop_sharing")}: ${a.app}`}
                  onClick={() => {
                    stop.mutate(a.client_id);
                  }}
                >
                  {t("action.stop_sharing")}
                </Button>
              </ItemActions>
            </RowItem>
          ))}
        </Rows>
      )}
    </Panel>
  );
}
