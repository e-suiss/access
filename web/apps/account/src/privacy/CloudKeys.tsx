// OP-156 m.3 (w), E59: One's cloud key permissions, each letting a checked cloud environment
// open named data of the person for one purpose, for at most a day. The person sees every live
// one and stops it with one tap; stopping tells the environment to destroy its copies.
import { Button } from "@access/ui/components/button";
import { ItemActions, ItemContent } from "@access/ui/components/item";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ReactElement } from "react";
import * as v from "valibot";

import { useAnnouncer, when } from "../account/common.js";
import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { Loading, Meta, Panel, RowItem, Rows } from "../lib/ui.js";

/** What `GET /v1/me/cloud-key-permissions` answers. */
export const CloudKeyList = v.object({
  permissions: v.array(
    v.object({
      id: v.string(),
      purpose: v.string(),
      classes: v.array(v.string()),
      valid_until: v.string(),
      state: v.string(),
      destroy: v.boolean(),
    }),
  ),
});
export type CloudKeyList = v.InferOutput<typeof CloudKeyList>;

const KEY = ["cloud-key-permissions"] as const;

/** "Cloud use of your data by One". */
export function CloudKeys(): ReactElement | null {
  const queries = useQueryClient();
  const { data: list, error } = useQuery({
    queryKey: KEY,
    queryFn: () => json(frontend("/v1/me/cloud-key-permissions"), CloudKeyList),
  });
  const { say, fail, region } = useAnnouncer(error);
  const revoke = useMutation({
    mutationFn: (id: string) =>
      json(
        frontend(`/v1/me/cloud-key-permissions/${encodeURIComponent(id)}/revoke`, {
          method: "POST",
        }),
      ),
    onSuccess: () => {
      say(t("cloud_key.revoke"));
      void queries.invalidateQueries({ queryKey: KEY });
    },
    onError: (e) => {
      fail(e);
    },
  });
  const live = list?.permissions.filter((p) => p.state === "live") ?? [];
  if (list !== undefined && live.length === 0) return null;
  return (
    <Panel
      aria-labelledby="cloud-key-heading"
      data-testid="cloud-keys"
      title={t("cloud_key.title")}
      titleId="cloud-key-heading"
    >
      {region}
      {list === undefined ? (
        <Loading rows={1} />
      ) : (
        <Rows>
          {live.map((p) => (
            <RowItem key={p.id} data-testid="cloud-key-row">
              <ItemContent>
                <p>
                  {t("cloud_key.intro", {
                    classes: p.classes.join(", "),
                    purpose: p.purpose,
                  })}
                </p>
                <Meta>{t("cloud_key.until", { time: when(p.valid_until) })}</Meta>
              </ItemContent>
              <ItemActions>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    revoke.mutate(p.id);
                  }}
                >
                  {t("cloud_key.revoke")}
                </Button>
              </ItemActions>
            </RowItem>
          ))}
        </Rows>
      )}
    </Panel>
  );
}
