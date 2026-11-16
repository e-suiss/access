// S10 "Sign-ins & instances" (§8.5, §8.8, §12.2.1; X36, X33, MD-13, OP-153 m.3 (y)): one row per
// sign-in on a device. The identity part (signed in until …, stays signed in) and the authority
// part (this device's key) are shown apart. "End this sign-in" is for another device and never
// one button with "Sign out"; signing out everywhere says honestly what stays. Device binding is
// "tied to this device", never a claim of trust.
import { Badge } from "@access/ui/components/badge";
import { Button } from "@access/ui/components/button";
import { Card, CardContent } from "@access/ui/components/card";
import { Field, FieldLabel } from "@access/ui/components/field";
import { ItemActions, ItemContent } from "@access/ui/components/item";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ReactElement, useState } from "react";
import * as v from "valibot";
import { useAnnouncer, when } from "../account/common.js";
import { useSignature } from "../hub/Sign.js";
import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { NotSigned } from "../lib/instance.js";
import { Actions, Check, Loading, MONO, PageTitle, RowItem, Rows } from "../lib/ui.js";
import { ownInstance, terminate } from "./authority.js";

/** One sign-in as `GET /v1/sessions` lists it. */
export const SignIn = v.object({
  id: v.string(),
  authenticated_at: v.nullable(v.string()),
  expires_at: v.nullable(v.string()),
  keep_signed_in: v.boolean(),
  current: v.optional(v.boolean()),
  device: v.optional(v.nullable(v.string())),
  instance: v.optional(v.nullable(v.string())),
  bound: v.optional(v.boolean()),
});
export type SignIn = v.InferOutput<typeof SignIn>;

const Sessions = v.object({ sessions: v.array(SignIn) });
const Ended = v.object({ instance: v.optional(v.nullable(v.string())) });
const SignedOut = v.object({ reason: v.optional(v.unknown()) });

const KEY = ["sessions"] as const;

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
    const p = v.parse(SignedOut, await r.json());
    const reason = SIGNED_OUT_REASONS.find((x) => x === p.reason);
    return reason === undefined ? null : t(`signed_out.${reason}`);
  } catch {
    return null;
  }
}

/** "Signed out because …", for the signed-out screen. */
export function SignedOutReason(): ReactElement | null {
  const { data: text } = useQuery({ queryKey: ["signed-out-reason"], queryFn: signedOutReason });
  return text === null || text === undefined ? null : (
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
          <Button variant="outline" size="sm" disabled={props.busy} onClick={props.signOut}>
            {t("action.sign_out")}
          </Button>
        ) : (
          <Button
            variant="outline"
            size="sm"
            disabled={props.busy}
            aria-label={`${t("action.end_sign_in")}: ${device}`}
            onClick={() => {
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
  const queries = useQueryClient();
  const [expert, setExpert] = useState(false);
  const { data: list, error } = useQuery({
    queryKey: KEY,
    queryFn: async () => (await json(frontend("/v1/sessions"), Sessions)).sessions,
  });
  const { say, fail, region } = useAnnouncer(error);
  const { confirm, dialog } = useSignature();

  const ending = useMutation({
    mutationFn: async (s: SignIn): Promise<string> => {
      const r = await json(
        frontend(`/v1/sessions/${encodeURIComponent(s.id)}/end`, { method: "POST" }),
        Ended,
      );
      void queries.invalidateQueries({ queryKey: KEY });
      const target = r.instance ?? null;
      if (target === null) return t("signins.ended");
      const own = await ownInstance();
      if (own === undefined) return t("signins.ended_key_stays");
      try {
        await terminate(own, confirm, target);
        return t("signins.ended_with_key");
      } catch (e) {
        if (e instanceof NotSigned) return t("signins.ended_key_stays");
        throw e;
      }
    },
    onSuccess: (text) => {
      say(text);
    },
    onError: (e) => {
      fail(e);
    },
  });

  const leaving = useMutation({
    mutationFn: () => json(frontend("/v1/sessions/current/sign-out", { method: "POST" })),
    onSuccess: () => {
      location.reload();
    },
    onError: (e) => {
      fail(e);
    },
  });

  const leavingEverywhere = useMutation({
    mutationFn: () => json(frontend("/v1/sessions/sign-out-everywhere", { method: "POST" })),
    onError: (e) => {
      fail(e);
    },
  });

  const busy = ending.isPending || leaving.isPending || leavingEverywhere.isPending;
  const everywhere = leavingEverywhere.isSuccess;
  const end = (s: SignIn) => {
    ending.mutate(s);
  };
  const signOut = () => {
    leaving.mutate();
  };
  const signOutEverywhere = () => {
    leavingEverywhere.mutate();
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
          ) : list === undefined ? (
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
                <Button variant="outline" disabled={busy} onClick={signOutEverywhere}>
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
