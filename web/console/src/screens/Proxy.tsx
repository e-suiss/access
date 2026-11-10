// IDP-30, B22, OP-156 m.3 (l), (m), m.15 (h): the realm's forward-auth proxies. Registering,
// retiring and turning plain identity headers on or off are each one signed change; turning them
// on runs the setup check, and its refusal is shown as the change's answer.
import { useState, type ReactElement } from "react";

import { t } from "../i18n/index.js";
import { adminGet, change, type WriteResult } from "../lib/admin.js";
import { type Ctx, Field, Panel, Show, useLoad, useRun } from "./parts.js";

interface ProxyRow {
  readonly name: string;
  readonly engine: string;
  readonly host: string;
  readonly upstream: string | null;
  readonly status: string;
  readonly plain_headers: boolean;
  readonly decision_cache_s: number;
  readonly routes: readonly string[];
}

interface Page<T> {
  readonly items: readonly T[];
}

const ENGINES = ["envoy", "caddy", "traefik", "nginx"] as const;

/** The forward-auth proxies screen. */
export function Proxy({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const realm = encodeURIComponent(ctx.session.realm);
  const proxies = useLoad(() => adminGet<Page<ProxyRow>>(ctx.instance, `realms/${realm}/proxies`));
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
      change(ctx.instance, ctx.confirm, ctx.session.realm, {
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
              <p>{t("none")}</p>
            ) : (
              <ul data-testid="proxies">
                {p.items.map((r) => (
                  <li key={r.name}>
                    <span className="mono">{r.name}</span> · <span className="mono">{r.host}</span>{" "}
                    · {r.engine} · {r.status === "live" ? t("proxyLive") : t("proxyRetired")} ·{" "}
                    {r.plain_headers ? t("proxyPlainOn") : t("proxyPlainOff")} ·{" "}
                    {t("proxyCache", { s: String(r.decision_cache_s) })}
                    {r.status === "live" && (
                      <>
                        {" "}
                        <button
                          type="button"
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
                        </button>{" "}
                        <button
                          type="button"
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
                        </button>
                      </>
                    )}
                  </li>
                ))}
              </ul>
            )
          }
        </Show>
        <p role="note" data-testid="proxy-plain-note">
          {t("proxyPlainNote")}
        </p>
      </Panel>
      <Panel id="proxy-register" title={t("proxyRegisterTitle")}>
        <form
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
          <p className="field">
            <label htmlFor="proxy-engine">{t("proxyEngine")}</label>
            <select
              id="proxy-engine"
              value={engine}
              onChange={(e) => {
                setEngine(e.target.value);
              }}
            >
              {ENGINES.map((x) => (
                <option key={x} value={x}>
                  {x}
                </option>
              ))}
            </select>
          </p>
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
          <button type="submit" disabled={!ready}>
            {t("proxyRegisterSend")}
          </button>
        </form>
      </Panel>
      <Show l={w}>
        {(r) => <p role="status">{t("changeRecorded", { exercise: r.exercise_id })}</p>}
      </Show>
    </>
  );
}
