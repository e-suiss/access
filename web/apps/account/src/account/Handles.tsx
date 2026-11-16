// E56, OP-156 m.4 (Q20): the person's names beside their permanent ID, a Suiss subdomain or a
// domain they own. A name shows only once the site points back to the person; until then it
// waits and can be checked again. A removed name is never handed to anyone else.
import { Button } from "@access/ui/components/button";
import { Field, FieldLabel } from "@access/ui/components/field";
import { Input } from "@access/ui/components/input";
import { ItemActions, ItemContent } from "@access/ui/components/item";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type ReactElement } from "react";
import * as v from "valibot";

import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { Loading, Meta, Panel, RowItem, Rows } from "../lib/ui.js";
import { useAnnouncer } from "./common.js";

/** What `GET /v1/me/handles` answers. */
export const HandleList = v.object({
  handles: v.array(
    v.object({
      id: v.string(),
      handle: v.string(),
      kind: v.string(),
      state: v.string(),
      shown: v.boolean(),
    }),
  ),
});
export type HandleList = v.InferOutput<typeof HandleList>;

const KEY = ["handles"] as const;

/** "Your names". */
export function Handles(): ReactElement {
  const queries = useQueryClient();
  const [draft, setDraft] = useState("");
  const { data: list, error } = useQuery({
    queryKey: KEY,
    queryFn: () => json(frontend("/v1/me/handles"), HandleList),
  });
  const { say, fail, region } = useAnnouncer(error);
  const write = useMutation({
    mutationFn: ({ path, body }: { readonly path: string; readonly body?: unknown }) =>
      json(frontend(path, body === undefined ? { method: "POST" } : { method: "POST", body })),
    onSuccess: () => {
      say(t("handle.title"));
      void queries.invalidateQueries({ queryKey: KEY });
    },
    onError: (e) => {
      fail(e);
    },
  });
  const post = (path: string, body?: unknown): void => {
    write.mutate(body === undefined ? { path } : { path, body });
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
      {list === undefined ? (
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
                      onClick={() => {
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
                    onClick={() => {
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
