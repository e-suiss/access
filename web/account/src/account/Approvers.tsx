// S11, OP-156 m.3 (d): the person's approvers, apps on their phone that approve sign-ins by push
// after the number on the sign-in page is typed in. An approver registers itself from its app with
// its own key; here they are listed and removed. Removing needs a recent sign-in and deletes
// nothing on the server.
import { Button } from "@suiss/access-ui/components/ui/button";
import { ItemActions, ItemContent } from "@suiss/access-ui/components/ui/item";
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { Loading, Meta, Nothing, Panel, RowItem, Rows } from "../lib/ui.js";
import { useAnnouncer, when } from "./common.js";

/** What `GET /v1/approvers` answers. */
export interface ApproverList {
  readonly approvers: readonly {
    readonly id: string;
    readonly name: string;
    readonly device_key: string;
    readonly registered_at: string;
    readonly last_used_at: string | null;
  }[];
}

const CODES = { "no-such-approver": "methods.removed" } as const;

/** "Approvers". */
export function Approvers(): ReactElement {
  const [list, setList] = useState<ApproverList | null>(null);
  const { say, fail, region } = useAnnouncer();
  const reload = useCallback(() => {
    json<ApproverList>(frontend("/v1/approvers"))
      .then(setList)
      .catch((e: unknown) => {
        fail(e);
      });
  }, [fail]);
  useEffect(reload, [reload]);
  return (
    <Panel
      aria-labelledby="approvers-heading"
      data-testid="approvers"
      title={t("approvers.title")}
      titleId="approvers-heading"
      description={t("approvers.intro")}
    >
      {region}
      {list === null ? (
        <Loading />
      ) : list.approvers.length === 0 ? (
        <Nothing>{t("approvers.none")}</Nothing>
      ) : (
        <Rows>
          {list.approvers.map((a) => (
            <RowItem key={a.id} data-testid="approver-row">
              <ItemContent>
                <strong>{a.name}</strong>
                <Meta>{t("methods.added_on", { date: when(a.registered_at) })}</Meta>
              </ItemContent>
              <ItemActions>
                <Button
                  variant="outline"
                  size="sm"
                  aria-label={`${t("approvers.remove")}: ${a.name}`}
                  onPress={() => {
                    void json(
                      frontend(`/v1/approvers/${encodeURIComponent(a.id)}/retire`, {
                        method: "POST",
                      }),
                    )
                      .then(() => {
                        say(t("methods.removed"));
                        reload();
                      })
                      .catch((e: unknown) => {
                        fail(e, CODES);
                      });
                  }}
                >
                  {t("approvers.remove")}
                </Button>
              </ItemActions>
            </RowItem>
          ))}
        </Rows>
      )}
    </Panel>
  );
}
