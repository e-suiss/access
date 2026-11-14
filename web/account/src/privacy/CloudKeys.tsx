// OP-156 m.3 (w), E59: One's cloud key permissions, each letting a checked cloud environment
// open named data of the person for one purpose, for at most a day. The person sees every live
// one and stops it with one tap; stopping tells the environment to destroy its copies.
import { Button } from "@suiss/access-ui/components/ui/button";
import { ItemActions, ItemContent } from "@suiss/access-ui/components/ui/item";
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { useAnnouncer, when } from "../account/common.js";
import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { Loading, Meta, Panel, RowItem, Rows } from "../lib/ui.js";

/** What `GET /v1/me/cloud-key-permissions` answers. */
export interface CloudKeyList {
  readonly permissions: readonly {
    readonly id: string;
    readonly purpose: string;
    readonly classes: readonly string[];
    readonly valid_until: string;
    readonly state: string;
    readonly destroy: boolean;
  }[];
}

/** "Cloud use of your data by One". */
export function CloudKeys(): ReactElement | null {
  const [list, setList] = useState<CloudKeyList | null>(null);
  const { say, fail, region } = useAnnouncer();
  const reload = useCallback(() => {
    json<CloudKeyList>(frontend("/v1/me/cloud-key-permissions"))
      .then(setList)
      .catch((e: unknown) => {
        fail(e);
      });
  }, [fail]);
  useEffect(reload, [reload]);
  const live = list?.permissions.filter((p) => p.state === "live") ?? [];
  if (list !== null && live.length === 0) return null;
  return (
    <Panel
      aria-labelledby="cloud-key-heading"
      data-testid="cloud-keys"
      title={t("cloud_key.title")}
      titleId="cloud-key-heading"
    >
      {region}
      {list === null ? (
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
                  onPress={() => {
                    void json(
                      frontend(`/v1/me/cloud-key-permissions/${encodeURIComponent(p.id)}/revoke`, {
                        method: "POST",
                      }),
                    )
                      .then(() => {
                        say(t("cloud_key.revoke"));
                        reload();
                      })
                      .catch((e: unknown) => {
                        fail(e);
                      });
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
