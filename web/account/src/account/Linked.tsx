// S11 (§8.5; TN-65, TN-68, OP-153 m.3 (m), (z)): the other sign-ins linked to this account and
// the apps it shares identity details with. A linked sign-in is never called "merged"; linking
// proves control of the other sign-in at its provider. Sharing details with an app is not
// authority: stopping it keeps the record and the app receives no details until asked again.
import { Button } from "@suiss/access-ui/components/ui/button";
import { ItemActions, ItemContent } from "@suiss/access-ui/components/ui/item";
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { Loading, Meta, Nothing, Panel, RowItem, Rows } from "../lib/ui.js";
import { useAnnouncer, when } from "./common.js";

interface LinkedList {
  readonly linked: readonly {
    readonly link: string;
    readonly provider: string;
    readonly linked_at_ms: number;
    readonly verified_at_ms: number | null;
  }[];
}

interface Apps {
  readonly apps: readonly {
    readonly client_id: string;
    readonly app: string;
    readonly claims: readonly string[];
    readonly since_ms: number;
  }[];
}

const LINK_CODES = {
  "last-sign-in-method": "methods.last_method",
  "no-such-provider": "linked.unavailable",
} as const;

/** "Linked sign-ins". */
export function LinkedSignIns(): ReactElement {
  const [list, setList] = useState<LinkedList | null>(null);
  const { say, fail, region } = useAnnouncer();
  const reload = useCallback(() => {
    json<LinkedList>(frontend("/v1/account/linked"))
      .then(setList)
      .catch((e: unknown) => {
        fail(e);
      });
  }, [fail]);
  useEffect(reload, [reload]);
  return (
    <Panel
      aria-labelledby="linked-heading"
      data-testid="linked-sign-ins"
      title={t("settings.linked_sign_ins")}
      titleId="linked-heading"
    >
      {region}
      {list === null ? (
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
                  onPress={() => {
                    void json(
                      frontend(`/v1/account/linked/${encodeURIComponent(l.link)}`, {
                        method: "DELETE",
                      }),
                    )
                      .then(() => {
                        say(t("methods.removed"));
                        reload();
                      })
                      .catch((e: unknown) => {
                        fail(e, LINK_CODES);
                      });
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
  const [apps, setApps] = useState<Apps | null>(null);
  const { say, fail, region } = useAnnouncer();
  const reload = useCallback(() => {
    json<Apps>(frontend("/v1/account/connected-apps"))
      .then(setApps)
      .catch((e: unknown) => {
        fail(e);
      });
  }, [fail]);
  useEffect(reload, [reload]);
  return (
    <Panel
      aria-labelledby="apps-heading"
      data-testid="connected-apps"
      title={t("settings.connected_apps")}
      titleId="apps-heading"
    >
      {region}
      {apps === null ? (
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
                  onPress={() => {
                    void json(
                      frontend(`/v1/account/connected-apps/${encodeURIComponent(a.client_id)}`, {
                        method: "DELETE",
                      }),
                    )
                      .then(() => {
                        say(t("apps.stopped"));
                        reload();
                      })
                      .catch((e: unknown) => {
                        fail(e);
                      });
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
