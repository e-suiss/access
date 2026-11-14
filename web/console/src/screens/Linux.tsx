// IDP-32, OP-156 m.3 (p): the realm's Linux client hosts. Registering a host, retiring it, its
// offline limits and its break-glass switch are each one signed change. A host resolves and
// signs in exactly the people whose ssh.login access names its server group; sudo asks for a
// security key every time and never works offline.
import { useState, type ReactElement } from "react";

import { Badge } from "@suiss/access-ui/components/ui/badge";
import { Button } from "@suiss/access-ui/components/ui/button";

import { t } from "../i18n/index.js";
import { adminGet, change, type WriteResult } from "../lib/admin.js";
import { ACTIONS, FACTS, FORM, H4, HINT, MONO, Notice } from "../ui.js";
import { type Ctx, Field, Panel, Show, useLoad, useRun } from "./parts.js";

interface Host {
  readonly name: string;
  readonly host_group: string;
  readonly certificate: string;
  readonly sudo_ct: number;
  readonly nss_ttl_s: number;
  readonly console_ttl_s: number;
  readonly break_glass: boolean;
  readonly status: string;
}

interface Page<T> {
  readonly items: readonly T[];
}

const hours = (s: number): string => String(Math.round((s / 3600) * 10) / 10);

/** The Linux client screen. */
export function Linux({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const realm = encodeURIComponent(ctx.session.realm);
  const hosts = useLoad(() => adminGet<Page<Host>>(ctx.instance, `realms/${realm}/linux-hosts`));
  const [name, setName] = useState("");
  const [group, setGroup] = useState("");
  const [certificate, setCertificate] = useState("");
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
  const at = (h: Host, rest: string) => `linux-hosts/${encodeURIComponent(h.name)}/${rest}`;
  return (
    <>
      <Panel id="linux-hosts" title={t("linuxHostsTitle")}>
        <p>{t("linuxHostsIntro")}</p>
        <Show l={hosts}>
          {(p) =>
            p.items.length === 0 ? (
              <p className={HINT}>{t("none")}</p>
            ) : (
              <ul data-testid="linux-hosts" className="flex flex-col divide-y">
                {p.items.map((h) => (
                  <li
                    key={h.name}
                    className="flex flex-col gap-3 py-4 text-sm first:pt-0 last:pb-0"
                  >
                    <p className="flex flex-wrap items-center gap-x-2 gap-y-1">
                      <span className={`${MONO} font-medium`}>{h.name}</span> · {h.host_group} ·{" "}
                      <Badge variant={h.status === "live" ? "outline" : "secondary"}>
                        {h.status === "live" ? t("linuxHostLive") : t("linuxHostRetired")}
                      </Badge>
                    </p>
                    <dl className={FACTS}>
                      <dt>{t("linuxOffline")}</dt>
                      <dd>
                        {t("linuxOfflineLimits", {
                          nss: hours(h.nss_ttl_s),
                          console: hours(h.console_ttl_s),
                        })}
                      </dd>
                      <dt>{t("linuxSudo")}</dt>
                      <dd>{t("linuxSudoTier", { ct: String(h.sudo_ct) })}</dd>
                      <dt>{t("linuxBreakGlass")}</dt>
                      <dd>{h.break_glass ? t("linuxBreakGlassOn") : t("linuxBreakGlassOff")}</dd>
                    </dl>
                    {h.status === "live" && (
                      <p className={ACTIONS}>
                        <Button
                          variant="outline"
                          size="sm"
                          onPress={() => {
                            send(
                              "putLinuxOfflinePolicy",
                              "PUT",
                              at(h, "offline-policy"),
                              { nss_ttl_s: 0, console_ttl_s: 0 },
                              h.name,
                            );
                          }}
                        >
                          {t("linuxOfflineOff", { name: h.name })}
                        </Button>
                        <Button
                          variant={h.break_glass ? "outline" : "destructive"}
                          size="sm"
                          onPress={() => {
                            send(
                              "putLinuxBreakGlassPolicy",
                              "PUT",
                              at(h, "break-glass-policy"),
                              { enabled: !h.break_glass },
                              h.name,
                            );
                          }}
                        >
                          {h.break_glass
                            ? t("linuxBreakGlassDisable", { name: h.name })
                            : t("linuxBreakGlassEnable", { name: h.name })}
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onPress={() => {
                            send("retireLinuxHost", "POST", at(h, "retire"), {}, h.name);
                          }}
                        >
                          {t("linuxHostRetire", { name: h.name })}
                        </Button>
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            )
          }
        </Show>
        <Notice role="note" data-testid="linux-break-glass-note">
          {t("linuxBreakGlassNote")}
        </Notice>
        <form
          className={FORM}
          onSubmit={(e) => {
            e.preventDefault();
            send("registerLinuxHost", "POST", "linux-hosts", {
              name,
              host_group: group,
              certificate,
            });
          }}
        >
          <h4 className={H4}>{t("linuxHostRegister")}</h4>
          <Field
            id="linux-host-name"
            label={t("linuxHostName")}
            value={name}
            onChange={setName}
            hint={t("sshGroupNameHint")}
          />
          <Field
            id="linux-host-group"
            label={t("linuxHostGroup")}
            value={group}
            onChange={setGroup}
          />
          <Field
            id="linux-host-certificate"
            label={t("linuxHostCertificate")}
            value={certificate}
            onChange={setCertificate}
            hint={t("linuxHostCertificateHint")}
          />
          <Button
            type="submit"
            className="self-start"
            isDisabled={name === "" || group === "" || certificate === ""}
          >
            {t("linuxHostRegisterSend")}
          </Button>
        </form>
      </Panel>
      <Panel id="linux-setup" title={t("linuxSetupTitle")}>
        <pre
          className={`${MONO} overflow-x-auto rounded-lg bg-muted p-3 text-sm whitespace-pre`}
          data-testid="linux-nsswitch"
        >
          {"passwd: files access\ngroup:  files access"}
        </pre>
        <pre
          className={`${MONO} overflow-x-auto rounded-lg bg-muted p-3 text-sm whitespace-pre`}
          data-testid="linux-pam"
        >
          {"auth required /usr/lib/access/pam_access.so"}
        </pre>
      </Panel>
      <Show l={w}>
        {(r) => <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>}
      </Show>
    </>
  );
}
