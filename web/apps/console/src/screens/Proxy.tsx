// IDP-30, B22, OP-156 m.3 (l), (m), m.15 (h): the environment's forward-auth proxies. Registering,
// retiring and turning plain identity headers on or off are each one signed change; turning them
// on runs the setup check, and its refusal is shown as the change's answer.

import { Button } from "@access/ui/components/button";
import { FieldLabel, Field as FieldRoot } from "@access/ui/components/field";
import { NativeSelect, NativeSelectOption } from "@access/ui/components/native-select";
import { type ReactElement, useState } from "react";
import * as v from "valibot";

import { t } from "../i18n/index.js";
import { adminGet, change, items, type WriteResult } from "../lib/admin.js";
import { ACTIONS, FORM, HINT, MONO, Notice } from "../ui.js";
import { type Ctx, Field, Panel, readKey, Show, useLoad, useRun } from "./parts.js";

// OP-159 m.46 (f)
const ProxyRows = items(
  v.looseObject({
    name: v.string(),
    engine: v.string(),
    host: v.string(),
    upstream: v.nullable(v.string()),
    status: v.string(),
    plain_headers: v.boolean(),
    decision_cache_s: v.number(),
    routes: v.array(v.string()),
  }),
);

const ENGINES = ["envoy", "caddy", "traefik", "nginx"] as const;

/** The forward-auth proxies screen. */
export function Proxies({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const environment = encodeURIComponent(ctx.session.environment);
  const proxies = useLoad(readKey(ctx, `envs/${environment}/proxies`), () =>
    adminGet(ctx.instance, `envs/${environment}/proxies`, ProxyRows),
  );
  const [name, setName] = useState("");
  const [engine, setEngine] = useState<string>("envoy");
  const [host, setHost] = useState("");
  const [upstream, setUpstream] = useState("");
  const [clientId, setClientId] = useState("");
  const [pep, setPep] = useState("");
  const [actionNamespace, setActionNamespace] = useState("");
  const [actionName, setActionName] = useState("");
  const [actionMajor, setActionMajor] = useState("1");
  const [actionSchema, setActionSchema] = useState("");
  const [namespace, setNamespace] = useState("");
  const [routes, setRoutes] = useState("/");
  const [w, write] = useRun<WriteResult>();
  const send = (
    operation: string,
    method: "POST" | "PUT",
    path: string,
    body: Record<string, unknown>,
    key?: string,
  ) => {
    write(() =>
      change(ctx.instance, ctx.confirm, ctx.session.environment, {
        operation,
        method,
        path,
        body,
        ...(key === undefined ? {} : { key }),
      }),
    );
  };
  const ready =
    name !== "" &&
    host !== "" &&
    clientId !== "" &&
    pep !== "" &&
    actionNamespace !== "" &&
    actionName !== "" &&
    actionSchema !== "" &&
    namespace !== "";
  return (
    <>
      <Panel id="proxy-list" title={t("proxyListTitle")}>
        <p>{t("proxyIntro")}</p>
        <Show l={proxies}>
          {(p) =>
            p.items.length === 0 ? (
              <p className={HINT}>{t("none")}</p>
            ) : (
              <ul data-testid="proxies" className="flex flex-col divide-y">
                {p.items.map((r) => (
                  <li key={r.name} className="flex flex-col gap-2 py-3 first:pt-0 last:pb-0">
                    <span>
                      <span className={MONO}>{r.name}</span> ·{" "}
                      <span className={MONO}>{r.host}</span> · {r.engine} ·{" "}
                      {r.status === "live" ? t("proxyLive") : t("proxyRetired")} ·{" "}
                      {r.plain_headers ? t("proxyPlainOn") : t("proxyPlainOff")} ·{" "}
                      {t("proxyCache", { s: String(r.decision_cache_s) })}
                    </span>
                    {r.status === "live" && (
                      <span className={ACTIONS}>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            send(
                              "putProxyPlainHeaders",
                              "PUT",
                              `proxies/${encodeURIComponent(r.name)}/plain-headers`,
                              { enabled: !r.plain_headers },
                              r.name,
                            );
                          }}
                        >
                          {r.plain_headers
                            ? t("proxyPlainClose", { name: r.name })
                            : t("proxyPlainOpen", { name: r.name })}
                        </Button>
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() => {
                            send(
                              "retireProxy",
                              "POST",
                              `proxies/${encodeURIComponent(r.name)}/retire`,
                              {},
                              r.name,
                            );
                          }}
                        >
                          {t("proxyRetire", { name: r.name })}
                        </Button>
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            )
          }
        </Show>
        <Notice role="note" data-testid="proxy-plain-note">
          {t("proxyPlainNote")}
        </Notice>
      </Panel>
      <Panel id="proxy-register" title={t("proxyRegisterTitle")}>
        <form
          className={FORM}
          onSubmit={(e) => {
            e.preventDefault();
            send("registerProxy", "POST", "proxies", {
              name,
              engine,
              host,
              ...(upstream === "" ? {} : { upstream }),
              client_id: clientId,
              pep,
              action: {
                namespace: actionNamespace,
                name: actionName,
                major: Number(actionMajor),
                schema: actionSchema,
              },
              namespace,
              routes: routes
                .split(",")
                .map((s) => s.trim())
                .filter((s) => s !== ""),
            });
          }}
        >
          <Field
            id="proxy-name"
            label={t("proxyName")}
            value={name}
            onChange={setName}
            hint={t("proxyNameHint")}
          />
          <FieldRoot className="gap-2">
            <FieldLabel htmlFor="proxy-engine" className="text-sm">
              {t("proxyEngine")}
            </FieldLabel>
            <NativeSelect
              id="proxy-engine"
              size="sm"
              value={engine}
              onChange={(e) => {
                setEngine(e.target.value);
              }}
            >
              {ENGINES.map((x) => (
                <NativeSelectOption key={x} value={x}>
                  {x}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </FieldRoot>
          <Field id="proxy-host" label={t("proxyHost")} value={host} onChange={setHost} />
          <Field
            id="proxy-upstream"
            label={t("proxyUpstream")}
            value={upstream}
            onChange={setUpstream}
            hint={t("proxyUpstreamHint")}
          />
          <Field
            id="proxy-client"
            label={t("proxyClient")}
            value={clientId}
            onChange={setClientId}
            hint={t("proxyClientHint")}
          />
          <Field
            id="proxy-pep"
            label={t("proxyPep")}
            value={pep}
            onChange={setPep}
            hint={t("proxyPepHint")}
          />
          <Field
            id="proxy-action-namespace"
            label={t("proxyActionNamespace")}
            value={actionNamespace}
            onChange={setActionNamespace}
          />
          <Field
            id="proxy-action-name"
            label={t("proxyActionName")}
            value={actionName}
            onChange={setActionName}
          />
          <Field
            id="proxy-action-major"
            label={t("proxyActionMajor")}
            type="number"
            value={actionMajor}
            onChange={setActionMajor}
          />
          <Field
            id="proxy-action-schema"
            label={t("proxyActionSchema")}
            value={actionSchema}
            onChange={setActionSchema}
          />
          <Field
            id="proxy-namespace"
            label={t("proxyNamespace")}
            value={namespace}
            onChange={setNamespace}
          />
          <Field
            id="proxy-routes"
            label={t("proxyRoutes")}
            value={routes}
            onChange={setRoutes}
            hint={t("proxyRoutesHint")}
          />
          <div className={ACTIONS}>
            <Button type="submit" disabled={!ready}>
              {t("proxyRegisterSend")}
            </Button>
          </div>
        </form>
      </Panel>
      <Show l={w}>
        {(r) => <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>}
      </Show>
    </>
  );
}
