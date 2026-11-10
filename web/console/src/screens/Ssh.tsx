// IDP-32, OP-156 m.3 (o): the realm's SSH certificate authority. Turning it on or off, rotating
// and replacing its key, and registering and retiring server groups are each one signed change;
// servers trust the CA key the realm publishes and refuse what its KRL lists. Certificates are
// projections of ssh.login Grants and show in the audit log.
import { useState, type ReactElement } from "react";

import { t } from "../i18n/index.js";
import { adminGet, change, type WriteResult } from "../lib/admin.js";
import { type Ctx, Field, Panel, Show, useLoad, useRun } from "./parts.js";

interface HostGroup {
  readonly name: string;
  readonly description: string;
  readonly status: string;
  readonly version: number;
}

interface Page<T> {
  readonly items: readonly T[];
}

/** The SSH certificate authority screen. */
export function Ssh({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const realm = encodeURIComponent(ctx.session.realm);
  const groups = useLoad(() =>
    adminGet<Page<HostGroup>>(ctx.instance, `realms/${realm}/ssh-host-groups`),
  );
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
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
  const base = `/realms/${ctx.session.realm}`;
  return (
    <>
      <Panel id="ssh-ca" title={t("sshCaTitle")}>
        <p>{t("sshCaIntro")}</p>
        <p>
          <button
            type="button"
            onClick={() => {
              send("putSshCa", "PUT", "settings/ssh-ca", { enabled: true });
            }}
          >
            {t("sshCaOn")}
          </button>{" "}
          <button
            type="button"
            onClick={() => {
              send("putSshCa", "PUT", "settings/ssh-ca", { enabled: false });
            }}
          >
            {t("sshCaOff")}
          </button>{" "}
          <button
            type="button"
            onClick={() => {
              send("rotateSshCa", "POST", "settings/ssh-ca/rotate", {});
            }}
          >
            {t("sshCaRotate")}
          </button>
        </p>
        <p role="note" data-testid="ssh-replace-warning">
          {t("sshCaReplaceWarning")}
        </p>
        <p>
          <button
            type="button"
            className="danger"
            onClick={() => {
              send("replaceSshCa", "POST", "settings/ssh-ca/replace", {});
            }}
          >
            {t("sshCaReplace")}
          </button>
        </p>
        <h4>{t("sshServerSetup")}</h4>
        <dl className="facts">
          <dt>{t("sshCaKeyAt")}</dt>
          <dd className="mono" data-testid="ssh-ca-url">{`${base}/ssh/ca.pub`}</dd>
          <dt>{t("sshKrlAt")}</dt>
          <dd className="mono" data-testid="ssh-krl-url">{`${base}/ssh/krl`}</dd>
        </dl>
        <pre className="mono" data-testid="ssh-sshd-config">
          {"TrustedUserCAKeys /etc/ssh/access-ca.pub\nRevokedKeys /etc/ssh/access.krl"}
        </pre>
      </Panel>
      <Panel id="ssh-groups" title={t("sshGroupsTitle")}>
        <p>{t("sshGroupsIntro")}</p>
        <Show l={groups}>
          {(g) =>
            g.items.length === 0 ? (
              <p>{t("none")}</p>
            ) : (
              <ul data-testid="ssh-groups">
                {g.items.map((h) => (
                  <li key={h.name}>
                    <span className="mono">{h.name}</span>
                    {h.description === "" ? "" : ` · ${h.description}`} ·{" "}
                    {h.status === "live" ? t("sshGroupLive") : t("sshGroupRetired")}
                    {h.status === "live" && (
                      <>
                        {" "}
                        <button
                          type="button"
                          onClick={() => {
                            send(
                              "retireSshHostGroup",
                              "POST",
                              `ssh-host-groups/${encodeURIComponent(h.name)}/retire`,
                              {},
                              h.name,
                            );
                          }}
                        >
                          {t("sshGroupRetire", { name: h.name })}
                        </button>
                      </>
                    )}
                  </li>
                ))}
              </ul>
            )
          }
        </Show>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            send("registerSshHostGroup", "POST", "ssh-host-groups", { name, description });
          }}
        >
          <h4>{t("sshGroupRegister")}</h4>
          <Field
            id="ssh-group-name"
            label={t("sshGroupName")}
            value={name}
            onChange={setName}
            hint={t("sshGroupNameHint")}
          />
          <Field
            id="ssh-group-description"
            label={t("sshGroupDescription")}
            value={description}
            onChange={setDescription}
          />
          <button type="submit" disabled={name === ""}>
            {t("sshGroupRegisterSend")}
          </button>
        </form>
      </Panel>
      <Panel id="ssh-certificates" title={t("sshCertificatesTitle")}>
        <p data-testid="ssh-certificates-note">
          {t("sshCertificatesNote")} <a href="/console/audit/records">{t("sshAuditLink")}</a>
        </p>
      </Panel>
      <Show l={w}>
        {(r) => <p role="status">{t("changeRecorded", { exercise: r.exercise_id })}</p>}
      </Show>
    </>
  );
}
