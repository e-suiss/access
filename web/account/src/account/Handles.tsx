// E56, OP-156 m.4 (Q20): the person's names beside their permanent ID, a Suiss subdomain or a
// domain they own. A name shows only once the site points back to the person; until then it
// waits and can be checked again. A removed name is never handed to anyone else.
import { Button } from "@suiss/access-ui/components/ui/button";
import { Field, FieldLabel } from "@suiss/access-ui/components/ui/field";
import { Input } from "@suiss/access-ui/components/ui/input";
import { ItemActions, ItemContent } from "@suiss/access-ui/components/ui/item";
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { Loading, Meta, Panel, RowItem, Rows } from "../lib/ui.js";
import { useAnnouncer } from "./common.js";

/** What `GET /v1/me/handles` answers. */
export interface HandleList {
  readonly handles: readonly {
    readonly id: string;
    readonly handle: string;
    readonly kind: string;
    readonly state: string;
    readonly shown: boolean;
  }[];
}

/** "Your names". */
export function Handles(): ReactElement {
  const [list, setList] = useState<HandleList | null>(null);
  const [draft, setDraft] = useState("");
  const { say, fail, region } = useAnnouncer();
  const reload = useCallback(() => {
    json<HandleList>(frontend("/v1/me/handles"))
      .then(setList)
      .catch((e: unknown) => {
        fail(e);
      });
  }, [fail]);
  useEffect(reload, [reload]);
  const post = (path: string, body?: unknown): void => {
    void json(frontend(path, body === undefined ? { method: "POST" } : { method: "POST", body }))
      .then(() => {
        say(t("handle.title"));
        reload();
      })
      .catch((e: unknown) => {
        fail(e);
      });
  };
  return (
    <Panel
      aria-labelledby="handles-heading"
      data-testid="handles"
      title={t("handle.title")}
      titleId="handles-heading"
      description={t("handle.intro")}
    >
      {region}
      {list === null ? (
        <Loading />
      ) : (
        list.handles.length > 0 && (
          <Rows>
            {list.handles.map((h) => (
              <RowItem key={h.id} data-testid="handle-row">
                <ItemContent>
                  <strong className="wrap-anywhere">{h.handle}</strong>
                  {h.shown ? null : <Meta>{t("handle.pending", { site: h.handle })}</Meta>}
                </ItemContent>
                <ItemActions>
                  {h.shown ? null : (
                    <Button
                      variant="outline"
                      size="sm"
                      onPress={() => {
                        post(`/v1/me/handles/${encodeURIComponent(h.id)}/verify`);
                      }}
                    >
                      {t("handle.check")}
                    </Button>
                  )}
                  <Button
                    variant="outline"
                    size="sm"
                    aria-label={`${t("handle.remove")}: ${h.handle}`}
                    onPress={() => {
                      post(`/v1/me/handles/${encodeURIComponent(h.id)}/retire`);
                    }}
                  >
                    {t("handle.remove")}
                  </Button>
                </ItemActions>
              </RowItem>
            ))}
          </Rows>
        )
      )}
      <form
        className="flex flex-col gap-2 sm:flex-row sm:items-end"
        onSubmit={(e) => {
          e.preventDefault();
          post("/v1/me/handles", { handle: draft });
          setDraft("");
        }}
      >
        <Field className="flex-1">
          <FieldLabel htmlFor="handle-new">{t("handle.add")}</FieldLabel>
          <Input
            id="handle-new"
            size="md"
            value={draft}
            onChange={(e) => {
              setDraft(e.target.value);
            }}
          />
        </Field>
        <Button type="submit">{t("handle.add")}</Button>
      </form>
    </Panel>
  );
}
