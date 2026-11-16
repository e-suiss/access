// OP-156 m.3 (i), §10.2.4, TN-16, TN-17: an environment's custom domains. Registering one shows the two
// records to publish, the TXT challenge and the CNAME to the environment's own host; Access checks them
// and checks them again every 90 days, and a domain is served with its own certificate only while
// they hold. Binding the issuer or the passkey domain to a confirmed domain is one signed CT3
// change that can't be reversed. Each change is one signed Exercise.

import { Button } from "@access/ui/components/button";
import { Input } from "@access/ui/components/input";
import { type ReactElement, useState } from "react";
import * as v from "valibot";

import { t } from "../i18n/index.js";
import { adminGet, change, items, type WriteResult } from "../lib/admin.js";
import { ACTIONS, H4, HINT, MONO, Notice } from "../ui.js";
import { at, type Ctx, Panel, readKey, Show, useLoad, useRun } from "./parts.js";

// OP-159 m.46 (f)
const Domain = v.looseObject({
  host: v.string(),
  status: v.string(),
  served: v.boolean(),
  txt_name: v.string(),
  txt_value: v.string(),
  cname_target: v.string(),
  finding: v.exactOptional(v.nullable(v.string())),
  reverify_by: v.exactOptional(v.nullable(v.string())),
  bound_as: v.exactOptional(v.nullable(v.picklist(["issuer", "rp_id"]))),
  certificate_expires_at: v.exactOptional(v.nullable(v.string())),
  renews_at: v.exactOptional(v.nullable(v.string())),
});

type Domain = v.InferOutput<typeof Domain>;

const Domains_ = items(Domain);

function Steps({ d }: { readonly d: Domain }): ReactElement {
  return (
    <ol className="flex flex-col gap-2">
      <li>
        {t("domainStepTxt", { host: d.host })}{" "}
        <span className={MONO} data-testid="domain-txt">
          {d.txt_value}
        </span>
      </li>
      <li data-testid="domain-cname">
        {t("domainStepCname", { host: d.host, target: d.cname_target })}
      </li>
      <li>{t("domainStepCheck")}</li>
    </ol>
  );
}

function State({ d }: { readonly d: Domain }): ReactElement {
  if (d.served && typeof d.certificate_expires_at === "string")
    return (
      <p data-testid="domain-state">
        {t("domainCertificateReady", { date: at(d.certificate_expires_at) })}
      </p>
    );
  if (d.served) return <p data-testid="domain-state">{t("domainConfirmed")}</p>;
  return <p data-testid="domain-state">{t("domainCheckFailed")}</p>;
}

/** The custom domains panel of the environment's sign-in settings. */
export function Domains({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const environment = encodeURIComponent(ctx.session.environment);
  const list = useLoad(readKey(ctx, `envs/${environment}/domains`), () =>
    adminGet(ctx.instance, `envs/${environment}/domains`, Domains_),
  );
  const [host, setHost] = useState("");
  const [w, write] = useRun<WriteResult>();
  const send = (operation: string, path: string, body: Record<string, unknown>, key?: string) => {
    write(() =>
      change(ctx.instance, ctx.confirm, ctx.session.environment, {
        operation,
        ...(key === undefined ? {} : { key }),
        method: "POST",
        path,
        body,
      }),
    );
  };
  return (
    <Panel id="custom-domains" title={t("domainsTitle")}>
      <p>{t("domainsIntro")}</p>
      <p className={HINT}>{t("domainRpIdNote")}</p>
      <Show l={list}>
        {(p) => (
          <ul data-testid="domain-list" className="flex flex-col divide-y">
            {p.items
              .filter((d) => d.status !== "retired" && d.status !== "expired")
              .map((d) => (
                <li key={d.host} className="flex flex-col gap-3 py-4 first:pt-0 last:pb-0">
                  <h4 className={`${H4} ${MONO}`}>{d.host}</h4>
                  {!d.served && <Steps d={d} />}
                  <State d={d} />
                  {d.served && (d.bound_as ?? null) === null && (
                    <p className={ACTIONS}>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          send(
                            "bindDomainIssuer",
                            `domains/${encodeURIComponent(d.host)}/issuer-bind`,
                            { bind: "rp_id" },
                            d.host,
                          );
                        }}
                      >
                        {t("domainBindRpId")}
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          send(
                            "bindDomainIssuer",
                            `domains/${encodeURIComponent(d.host)}/issuer-bind`,
                            { bind: "issuer" },
                            d.host,
                          );
                        }}
                      >
                        {t("domainBindIssuer")}
                      </Button>
                    </p>
                  )}
                  {(d.bound_as ?? null) === null && (
                    <Button
                      variant="destructive"
                      size="sm"
                      className="self-start"
                      onClick={() => {
                        send(
                          "retireDomain",
                          `domains/${encodeURIComponent(d.host)}/retire`,
                          {},
                          d.host,
                        );
                      }}
                    >
                      {t("domainRetire")}
                    </Button>
                  )}
                </li>
              ))}
          </ul>
        )}
      </Show>
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (host !== "") send("registerDomain", "domains", { host });
        }}
      >
        <label className="flex min-w-64 flex-1 flex-col gap-2 text-sm font-semibold">
          {t("domainHost")}
          <Input
            size="md"
            className="font-normal"
            type="text"
            inputMode="url"
            autoComplete="off"
            spellCheck={false}
            value={host}
            onChange={(e) => {
              setHost(e.target.value.trim().toLowerCase());
            }}
          />
        </label>
        <Button type="submit" disabled={host === ""}>
          {t("domainRegister")}
        </Button>
      </form>
      <Show l={w}>
        {(r) => <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>}
      </Show>
    </Panel>
  );
}
