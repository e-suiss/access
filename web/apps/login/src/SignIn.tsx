import { useCallback, useEffect, useRef, useState } from "react";

import { createFlow, getFlow, stepUp, submit, type Answer } from "./api.js";
import type { FlowKind, LoginUi, Message, Submission } from "./contract.js";
import { t } from "./i18n.js";
import { note, Panel, problem } from "./Layout.js";
import { pushGiveUpMs, pushOf, PUSH_POLL_MS, waitsForPush } from "./PushWait.js";
import { StepView } from "./StepView.js";

type State =
  | { readonly phase: "loading" }
  | { readonly phase: "ready"; readonly ui: LoginUi }
  | { readonly phase: "failed" }
  | { readonly phase: "degraded" };

const expired: Message = { id: "flow.expired", text: "", severity: "error" };
const unavailable: Message = { id: "login.unavailable", text: "", severity: "error" };
// OP-45, §8.13
const degraded: Message = { id: "login.degraded", text: "", severity: "error" };
const stopped: Message = { id: "page.email_wait_stopped", text: "", severity: "error" };

/** TN-102: the link wait polls with a growing pause and gives up after the link's lifetime. */
export const POLL_FIRST_MS = 2000;
export const POLL_MAX_MS = 10_000;
export const POLL_GIVE_UP_MS = 15 * 60 * 1000;

function withMessage(ui: LoginUi, message: Message): LoginUi {
  return { ...ui, messages: [message] };
}

function remember(ui: LoginUi) {
  const url = new URL(window.location.href);
  if (url.searchParams.get("flow") !== ui.flow) {
    url.searchParams.set("flow", ui.flow);
    window.history.replaceState(null, "", url);
  }
}

/** A step that waits for the e-mailed link to be opened elsewhere (TN-102). */
export function waitsForLink(ui: LoginUi): boolean {
  return (
    ui.step === "authenticate" &&
    ui.messages.some((m) => m.id === "email.sent") &&
    !ui.nodes.some((n) => n.type === "input" && n.name === "email_code")
  );
}

export function SignIn({ kind }: { readonly kind: FlowKind }) {
  const [state, setState] = useState<State>({ phase: "loading" });
  const [busy, setBusy] = useState(false);

  const current = useRef<LoginUi | null>(null);

  const show = useCallback((ui: LoginUi) => {
    current.current = ui;
    remember(ui);
    setState({ phase: "ready", ui });
  }, []);

  const restart = useCallback(
    async (message: Message | null) => {
      const answer = await createFlow(kind);
      if (answer.kind === "ui")
        show(message === null ? answer.ui : withMessage(answer.ui, message));
      else setState({ phase: answer.kind === "degraded" ? "degraded" : "failed" });
    },
    [show, kind],
  );

  const settle = useCallback(
    async (answer: Answer) => {
      switch (answer.kind) {
        case "ui":
          show(answer.ui);
          break;
        case "expired":
          await restart(expired);
          break;
        case "failed": {
          const ui = current.current;
          if (ui === null) setState({ phase: "failed" });
          else show(withMessage(ui, unavailable));
          break;
        }
        case "degraded": {
          const ui = current.current;
          if (ui === null) setState({ phase: "degraded" });
          else show(withMessage(ui, degraded));
          break;
        }
      }
    },
    [show, restart],
  );

  useEffect(() => {
    const params = new URL(window.location.href).searchParams;
    const flow = params.get("flow");
    const reason = params.get("reason");
    // TN-44, X-L3: only the authorization request's own reason asks for a step-up
    const start =
      flow !== null
        ? getFlow(flow)
        : reason === "step_up" || reason === "reauthenticate"
          ? stepUp(params.get("acr")).then((a) => (a.kind === "ui" ? a : createFlow()))
          : createFlow(kind);
    void start.then(settle);
  }, [settle, kind]);

  // TN-102
  const ui = state.phase === "ready" ? state.ui : null;
  useEffect(() => {
    if (ui === null || !waitsForLink(ui)) return;
    let pause = POLL_FIRST_MS;
    let timer: number | undefined;
    let live = true;
    const began = Date.now();
    const tick = async () => {
      const answer = await getFlow(ui.flow);
      if (!live) return;
      if (answer.kind === "ui" && waitsForLink(answer.ui)) {
        if (Date.now() - began >= POLL_GIVE_UP_MS) {
          show(withMessage(answer.ui, stopped));
          return;
        }
        pause = Math.min(Math.round(pause * 1.5), POLL_MAX_MS);
        timer = window.setTimeout(() => void tick(), pause);
        return;
      }
      await settle(answer);
    };
    timer = window.setTimeout(() => void tick(), pause);
    return () => {
      live = false;
      window.clearTimeout(timer);
    };
  }, [ui, settle, show]);

  // OP-156 m.3 (d), TN-102
  useEffect(() => {
    if (ui === null || !waitsForPush(ui)) return;
    const node = pushOf(ui);
    if (node === undefined) return;
    let timer: number | undefined;
    let live = true;
    const until = Date.now() + pushGiveUpMs(node, Date.now());
    const tick = async () => {
      const answer = await getFlow(ui.flow);
      if (!live) return;
      if (answer.kind === "ui" && waitsForPush(answer.ui) && Date.now() < until) {
        timer = window.setTimeout(() => void tick(), PUSH_POLL_MS);
        return;
      }
      await settle(answer);
    };
    timer = window.setTimeout(() => void tick(), PUSH_POLL_MS);
    return () => {
      live = false;
      window.clearTimeout(timer);
    };
  }, [ui, settle]);

  const onSubmit = useCallback(
    (submission: Submission) => {
      const ui = current.current;
      if (ui === null) return;
      setBusy(true);
      void submit(ui, submission)
        .then(settle)
        .finally(() => {
          setBusy(false);
        });
    },
    [settle],
  );

  return (
    <Panel aria-busy={state.phase === "loading" || busy}>
      {state.phase === "ready" && <StepView ui={state.ui} busy={busy} onSubmit={onSubmit} />}
      {ui !== null && waitsForLink(ui) && (
        <p role="status" className={note} data-testid="link-wait">
          {t("page.email_waiting")}
        </p>
      )}
      {state.phase === "loading" && (
        <p role="status" className={note}>
          {t("page.loading")}
        </p>
      )}
      {state.phase === "failed" && (
        <p role="alert" className={problem} data-message-id={unavailable.id}>
          {t(unavailable.id)}
        </p>
      )}
      {state.phase === "degraded" && (
        <p role="alert" className={problem} data-message-id={degraded.id}>
          {t(degraded.id)}
        </p>
      )}
    </Panel>
  );
}
