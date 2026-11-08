import { useCallback, useEffect, useRef, useState } from "react";

import { createFlow, getFlow, stepUp, submit, type Answer } from "./api.js";
import type { LoginUi, Message, Submission } from "./contract.js";
import { StepView } from "./StepView.js";

type State =
  | { readonly phase: "loading" }
  | { readonly phase: "ready"; readonly ui: LoginUi }
  | { readonly phase: "failed" };

const expired: Message = {
  id: "flow.expired",
  text: "This sign-in page has expired. Start again.",
  severity: "error",
};

const unavailable: Message = {
  id: "login.unavailable",
  text: "Sign-in is briefly unavailable. Try again shortly.",
  severity: "error",
};

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

export function App() {
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
      const answer = await createFlow();
      if (answer.kind === "ui")
        show(message === null ? answer.ui : withMessage(answer.ui, message));
      else setState({ phase: "failed" });
    },
    [show],
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
          : createFlow();
    void start.then(settle);
  }, [settle]);

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
    <main>
      <div className="card" aria-busy={state.phase === "loading" || busy}>
        {state.phase === "ready" && <StepView ui={state.ui} busy={busy} onSubmit={onSubmit} />}
        {state.phase === "loading" && <p>Loading…</p>}
        {state.phase === "failed" && (
          <p role="alert" data-message-id={unavailable.id}>
            {unavailable.text}
          </p>
        )}
      </div>
    </main>
  );
}
