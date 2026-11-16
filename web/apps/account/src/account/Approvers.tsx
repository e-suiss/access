// S11, OP-156 m.3 (d): the person's approvers, apps on their phone that approve sign-ins by push
// after the number on the sign-in page is typed in. An approver registers itself from its app with
// its own key; here they are listed and removed. Removing needs a recent sign-in and deletes
// nothing on the server.
import { Button } from "@access/ui/components/button";
import { ItemActions, ItemContent } from "@access/ui/components/item";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ReactElement } from "react";
import * as v from "valibot";

import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { Loading, Meta, Nothing, Panel, RowItem, Rows } from "../lib/ui.js";
import { useAnnouncer, when } from "./common.js";

/** What `GET /v1/approvers` answers. */
export const ApproverList = v.object({
  approvers: v.array(
    v.object({
      id: v.string(),
      name: v.string(),
      device_key: v.string(),
      registered_at: v.string(),
      last_used_at: v.nullable(v.string()),
    }),
  ),
});
export type ApproverList = v.InferOutput<typeof ApproverList>;

const KEY = ["approvers"] as const;

const CODES = { "no-such-approver": "methods.removed" } as const;

/** "Approvers". */
export function Approvers(): ReactElement {
  const queries = useQueryClient();
  const { data: list, error } = useQuery({
    queryKey: KEY,
    queryFn: () => json(frontend("/v1/approvers"), ApproverList),
  });
  const { say, fail, region } = useAnnouncer(error);
  const retire = useMutation({
    mutationFn: (id: string) =>
      json(frontend(`/v1/approvers/${encodeURIComponent(id)}/retire`, { method: "POST" })),
    onSuccess: () => {
      say(t("methods.removed"));
      void queries.invalidateQueries({ queryKey: KEY });
    },
    onError: (e) => {
      fail(e, CODES);
    },
  });
  return (
    <Panel
      aria-labelledby="approvers-heading"
      data-testid="approvers"
      title={t("approvers.title")}
      titleId="approvers-heading"
      description={t("approvers.intro")}
    >
      {region}
      {list === undefined ? (
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
                  onClick={() => {
                    retire.mutate(a.id);
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
