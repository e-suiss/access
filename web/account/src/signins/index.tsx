// S10 "Sign-ins & instances" (§8.5, §8.8, §12.2.1; X36, X33, MD-13, OP-153 m.3 (y)): one row per
// sign-in on a device. The identity part (signed in until …, stays signed in) and the authority
// part (this device's key) are shown apart. "End this sign-in" is for another device and never
// one button with "Sign out"; signing out everywhere says honestly what stays. Device binding is
// "tied to this device", never a claim of trust.
import { Badge } from "@suiss/access-ui/components/ui/badge";
import { Button } from "@suiss/access-ui/components/ui/button";
import { Card, CardContent } from "@suiss/access-ui/components/ui/card";
import { Field, FieldLabel } from "@suiss/access-ui/components/ui/field";
import { ItemActions, ItemContent } from "@suiss/access-ui/components/ui/item";
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { useSignature } from "../hub/Sign.js";
import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { NotSigned } from "../lib/instance.js";
import { Actions, Check, Loading, MONO, PageTitle, RowItem, Rows } from "../lib/ui.js";
import { useAnnouncer, when } from "../account/common.js";
import { ownInstance, terminate } from "./authority.js";

/** One sign-in as `GET /v1/sessions` lists it. */
export interface SignIn {
  readonly id: string;
  readonly authenticated_at: string | null;
  readonly expires_at: string | null;
  readonly keep_signed_in: boolean;
  readonly current?: boolean;
  readonly device?: string | null;
  readonly instance?: string | null;
  readonly bound?: boolean;
}

/** The closed list of "Signed out because …" reasons (OP-153 m.3 (y)). */
export const SIGNED_OUT_REASONS = [
  "password_changed",
  "device_mismatch",
  "admin_ended",
  "recovery",
  "expired",
] as const;

/** Why this browser's sign-in ended, from `GET /v1/sessions/current`; `null` when unknown. */
export async function signedOutReason(): Promise<string | null> {
  try {
    const r = await frontend("/v1/sessions/current");
    if (r.status !== 401) return null;
    const p = (await r.json()) as { reason?: unknown };
    const reason = SIGNED_OUT_REASONS.find((x) => x === p.reason);
    return reason === undefined ? null : t(`signed_out.${reason}`);
  } catch {
    return null;
  }
}

/** "Signed out because …", for the signed-out screen. */
export function SignedOutReason(): ReactElement | null {
  const [text, setText] = useState<string | null>(null);
  useEffect(() => {
    void signedOutReason().then(setText);
  }, []);
  return text === null ? null : (
    <p role="status" data-testid="signed-out-reason">
      {text}
    </p>
  );
}

function Row(props: {
  readonly s: SignIn;
  readonly expert: boolean;
  readonly busy: boolean;
  readonly end: (s: SignIn) => void;
  readonly signOut: () => void;
}): ReactElement {
  const { s } = props;
  const current = s.current === true;
  const device = current ? t("signins.this_device") : (s.device ?? t("signins.another_device"));
  return (
    <RowItem data-testid="sign-in-row" data-current={current}>
      <ItemContent className="min-w-0">
        <strong>{t("signins.on_device", { device })}</strong>
        <dl className="grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[auto_1fr]">
          <dt className="text-muted-foreground">{t("signins.identity")}</dt>
          <dd className="flex flex-wrap items-center gap-x-1">
            {s.expires_at === null ? "" : t("signins.until", { date: when(s.expires_at) })}
            {s.keep_signed_in && (
              <span className="text-muted-foreground"> · {t("signins.kept")}</span>
            )}
            {s.bound === true && (
              <span className="text-muted-foreground" data-testid="bound">
                {" · "}
                {current ? t("settings.tied_to_device") : t("signins.tied")}
              </span>
            )}
            {props.expert && (
              <Badge variant="outline" className="ms-1" data-testid="binding">
                {s.bound === true ? t("signins.device_bound") : t("signins.not_bound")}
              </Badge>
            )}
          </dd>
          <dt className="text-muted-foreground">{t("signins.authority")}</dt>
          <dd data-testid="authority">
            {s.instance === null || s.instance === undefined
              ? t("signins.no_device_key")
              : t("signins.device_key")}
            {props.expert && s.instance !== null && s.instance !== undefined && (
              <span className={MONO}> {s.instance}</span>
            )}
          </dd>
        </dl>
      </ItemContent>
      <ItemActions>
        {current ? (
          <Button variant="outline" size="sm" isDisabled={props.busy} onPress={props.signOut}>
            {t("action.sign_out")}
          </Button>
        ) : (
          <Button
            variant="outline"
            size="sm"
            isDisabled={props.busy}
            aria-label={`${t("action.end_sign_in")}: ${device}`}
            onPress={() => {
              props.end(s);
            }}
          >
            {t("action.end_sign_in")}
          </Button>
        )}
      </ItemActions>
    </RowItem>
  );
}

/** S10: where this person is signed in. */
export function SignIns(): ReactElement {
  const [list, setList] = useState<readonly SignIn[] | null>(null);
  const [expert, setExpert] = useState(false);
  const [busy, setBusy] = useState(false);
  const [everywhere, setEverywhere] = useState(false);
  const { say, fail, region } = useAnnouncer();
  const { confirm, dialog } = useSignature();
  const reload = useCallback(() => {
    json<{ sessions: SignIn[] }>(frontend("/v1/sessions"))
      .then((r) => {
        setList(r.sessions);
      })
      .catch((e: unknown) => {
        fail(e);
      });
  }, [fail]);
  useEffect(reload, [reload]);

  const end = (s: SignIn) => {
    setBusy(true);
    void json<{ instance?: string | null }>(
      frontend(`/v1/sessions/${encodeURIComponent(s.id)}/end`, { method: "POST" }),
    )
      .then(async (r) => {
        reload();
        const target = r.instance ?? null;
        if (target === null) {
          say(t("signins.ended"));
          return;
        }
        const own = await ownInstance();
        if (own === undefined) {
          say(t("signins.ended_key_stays"));
          return;
        }
        try {
          await terminate(own, confirm, target);
          say(t("signins.ended_with_key"));
        } catch (e) {
          if (e instanceof NotSigned) say(t("signins.ended_key_stays"));
          else fail(e);
        }
      })
      .catch((e: unknown) => {
        fail(e);
      })
      .finally(() => {
        setBusy(false);
      });
  };

  const signOut = () => {
    setBusy(true);
    void json(frontend("/v1/sessions/current/sign-out", { method: "POST" }))
      .then(() => {
        location.reload();
      })
      .catch((e: unknown) => {
        fail(e);
      })
      .finally(() => {
        setBusy(false);
      });
  };

  const signOutEverywhere = () => {
    setBusy(true);
    void json(frontend("/v1/sessions/sign-out-everywhere", { method: "POST" }))
      .then(() => {
        setEverywhere(true);
        setList([]);
      })
      .catch((e: unknown) => {
        fail(e);
      })
      .finally(() => {
        setBusy(false);
      });
  };

  return (
    <section
      aria-labelledby="sign-ins-heading"
      data-testid="sign-ins"
      className="flex flex-col gap-6"
    >
      <PageTitle id="sign-ins-heading">{t("settings.sign_ins")}</PageTitle>
      <Card>
        <CardContent className="flex flex-col gap-4">
          {region}
          {everywhere ? (
            <div
              role="status"
              data-testid="signed-out-everywhere"
              className="flex flex-col gap-1 rounded-xl bg-muted p-4"
            >
              <p className="font-semibold">{t("signins.signed_out_everywhere")}</p>
              <p className="text-sm">{t("signed_out.delegations_remain")}</p>
            </div>
          ) : list === null ? (
            <Loading />
          ) : (
            <>
              <Field orientation="horizontal">
                <Check
                  id="sign-ins-expert"
                  checked={expert}
                  onChange={(e) => {
                    setExpert(e.target.checked);
                  }}
                />
                <FieldLabel htmlFor="sign-ins-expert" className="font-normal">
                  {t("signins.details")}
                </FieldLabel>
              </Field>
              <Rows>
                {list.map((s) => (
                  <Row key={s.id} s={s} expert={expert} busy={busy} end={end} signOut={signOut} />
                ))}
              </Rows>
              <Actions>
                <Button variant="outline" isDisabled={busy} onPress={signOutEverywhere}>
                  {t("action.sign_out_everywhere")}
                </Button>
              </Actions>
            </>
          )}
        </CardContent>
      </Card>
      {dialog}
    </section>
  );
}
